use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, Write};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Parser;
use regex::Regex;
use serde::Deserialize;
use tracing::{debug, info};

const VERSION: &str = env!("CARGO_PKG_VERSION");

// ── Colors ───────────────────────────────────────────────────────────
// Raw ANSI SGR codes, always embedded in the strings this module builds.
// `anstream` strips them at the point of writing (see `main`/`run`) when
// stdout isn't a terminal or `NO_COLOR`/`CLICOLOR` say not to color.

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const RED_BOLD: &str = "\x1b[1;31m";
const GREEN: &str = "\x1b[32m";
const GREEN_BOLD: &str = "\x1b[1;32m";

/// Wrap `text` in `code`, resetting styling afterward.
fn style(code: &str, text: &str) -> String {
    format!("{code}{text}{RESET}")
}

// ── CLI ──────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "whiplash", version = VERSION, about = "Compare two log files using configurable regex patterns")]
struct Cli {
    /// Path to the TOML configuration file
    #[arg(long)]
    config: PathBuf,

    /// Override index_threshold from config
    #[arg(long)]
    threshold: Option<usize>,

    /// Override max_failed_items from config
    #[arg(long = "max-failed")]
    max_failed: Option<usize>,

    /// Validate config against a single log file
    #[arg(long)]
    validate: bool,

    /// Open an interactive side-by-side view with a live minimap instead of
    /// the default divergence output
    #[arg(long, conflicts_with = "validate")]
    side_by_side: bool,

    /// Clean (reference) log file
    clean_log: PathBuf,

    /// Dirty (test) log file
    dirty_log: Option<PathBuf>,
}

// ── Config types (raw TOML deserialization) ──────────────────────────

#[derive(Deserialize)]
struct RawConfig {
    general: Option<RawGeneral>,
    atoms: HashMap<String, String>,
    items: Vec<RawItem>,
}

/// One regex, or a list of regexes any of which may match.
#[derive(Deserialize)]
#[serde(untagged)]
enum PatternList {
    Single(String),
    List(Vec<String>),
}

impl PatternList {
    fn as_slice(&self) -> &[String] {
        match self {
            PatternList::Single(s) => std::slice::from_ref(s),
            PatternList::List(v) => v.as_slice(),
        }
    }
}

#[derive(Deserialize, Default)]
struct RawGeneral {
    index_threshold: Option<usize>,
    max_failed_items: Option<usize>,
    blacklist_atoms: Option<Vec<String>>,
    delimiters: Option<PatternList>,
    record_start: Option<PatternList>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawItem {
    name: String,
    parts: Option<Vec<RawPart>>,
    flags: Option<FlagValue>,
    ignore_atoms: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum FlagValue {
    Single(String),
    List(Vec<String>),
}

#[derive(Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
struct RawPart {
    atom: Option<String>,
    regex: Option<String>,
    #[serde(default)]
    optional: bool,
}

// ── Resolved config ──────────────────────────────────────────────────

struct Config {
    index_threshold: usize,
    max_failed_items: usize,
    delimiters: Vec<Regex>,
    /// A line matching any of these patterns starts a new block, without
    /// needing a delimiter line. Lets consecutive multi-line records be
    /// split by recognizing where the next one begins (e.g. a timestamp at
    /// the start of a line) instead of requiring a separator between them.
    record_start: Vec<Regex>,
    items: Vec<CompiledItem>,
}

struct DiagnosticPart {
    label: String,    // atom name or "(joining-regex)" for inline regex
    fragment: String, // the raw regex fragment for this part
}

struct CompiledItem {
    name: String,
    pattern: Regex,
    /// Atom names that participate in this item's captures (in order).
    capture_atoms: Vec<(String, String)>, // (atom_name, capture_group_name)
    /// Atoms to ignore in signature.
    ignore_set: Vec<String>,
    /// Ordered parts for diagnostic output on validation failure.
    diagnostic_parts: Vec<DiagnosticPart>,
    /// Flags prefix e.g. "(?ims)" or "", needed to reconstruct partial patterns.
    flags_prefix: String,
}

// ── Config loading & validation ──────────────────────────────────────

fn load_config(path: &PathBuf, cli: &Cli) -> Result<Config> {
    let text = fs::read_to_string(path).context("failed to read config file")?;
    let raw: RawConfig = toml::from_str(&text).context("failed to parse config TOML")?;

    if raw.atoms.is_empty() {
        bail!("config: `atoms` must be non-empty");
    }
    if raw.items.is_empty() {
        bail!("config: `items` must be non-empty");
    }

    let general = raw.general.unwrap_or_default();
    let blacklist = general.blacklist_atoms.clone().unwrap_or_default();
    let items = raw
        .items
        .iter()
        .map(|ri| {
            compile_item(ri, &raw.atoms, &blacklist)
                .with_context(|| format!("compiling item '{}'", ri.name))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(Config {
        index_threshold: cli.threshold.or(general.index_threshold).unwrap_or(0),
        max_failed_items: cli.max_failed.or(general.max_failed_items).unwrap_or(0),
        delimiters: compile_patterns(&general.delimiters, "delimiter")?,
        record_start: compile_patterns(&general.record_start, "record_start")?,
        items,
    })
}

fn is_delimiter_line(line_without_newline: &str, config: &Config) -> bool {
    config
        .delimiters
        .iter()
        .any(|re| re.is_match(line_without_newline))
}

fn is_record_start_line(line_without_newline: &str, config: &Config) -> bool {
    config
        .record_start
        .iter()
        .any(|re| re.is_match(line_without_newline))
}

fn compile_patterns(value: &Option<PatternList>, field_name: &str) -> Result<Vec<Regex>> {
    value
        .as_ref()
        .map(PatternList::as_slice)
        .unwrap_or(&[])
        .iter()
        .map(|pat| Regex::new(pat).with_context(|| format!("invalid {field_name} regex: {pat}")))
        .collect()
}

fn compile_item(
    raw: &RawItem,
    atoms: &HashMap<String, String>,
    blacklist: &[String],
) -> Result<CompiledItem> {
    if raw.name.is_empty() {
        bail!("item name must be non-empty");
    }

    let parts = raw.parts.as_deref().unwrap_or_default();
    if parts.is_empty() {
        bail!("item '{}': `parts` must be non-empty", raw.name);
    }

    let flags: &[String] = match &raw.flags {
        Some(FlagValue::Single(s)) => std::slice::from_ref(s),
        Some(FlagValue::List(v)) => v,
        None => &[],
    };
    let flag_chars = flags
        .iter()
        .map(|f| match f.as_str() {
            "IGNORECASE" => Ok('i'),
            "MULTILINE" => Ok('m'),
            "DOTALL" => Ok('s'),
            other => bail!("unknown flag: {}", other),
        })
        .collect::<Result<String>>()?;
    let flags_prefix = if flag_chars.is_empty() {
        String::new()
    } else {
        format!("(?{})", flag_chars)
    };

    let mut pattern_str = flags_prefix.clone();
    let mut capture_atoms: Vec<(String, String)> = Vec::new();
    let mut ordinal_counter: HashMap<String, usize> = HashMap::new();
    let mut diagnostic_parts: Vec<DiagnosticPart> = Vec::new();

    for part in parts {
        let wrap = |s: String| {
            if part.optional {
                format!("(?:{})?", s)
            } else {
                s
            }
        };
        match (&part.atom, &part.regex) {
            (Some(atom_name), None) => {
                let atom_regex = atoms
                    .get(atom_name)
                    .with_context(|| format!("atom '{}' not found", atom_name))?;
                let ord = ordinal_counter.entry(atom_name.clone()).or_insert(0);
                let group_name = format!("{}__{}", atom_name, ord);
                *ord += 1;
                capture_atoms.push((atom_name.clone(), group_name.clone()));
                let fragment = wrap(format!("(?P<{}>{})", group_name, atom_regex));
                pattern_str.push_str(&fragment);
                diagnostic_parts.push(DiagnosticPart {
                    label: atom_name.clone(),
                    fragment,
                });
            }
            (None, Some(regex_frag)) => {
                pattern_str.push_str(&wrap(regex_frag.clone()));
                diagnostic_parts.push(DiagnosticPart {
                    label: "(joining-regex)".to_string(),
                    fragment: regex_frag.clone(),
                });
            }
            _ => bail!("part must have exactly one of `atom` or `regex`"),
        }
    }

    debug!(item = %raw.name, pattern = %pattern_str, "compiled pattern");

    let pattern = Regex::new(&pattern_str)
        .with_context(|| format!("invalid regex for item '{}'", raw.name))?;

    let mut ignore_set = blacklist.to_vec();
    ignore_set.extend(raw.ignore_atoms.iter().flatten().cloned());

    Ok(CompiledItem {
        name: raw.name.clone(),
        pattern,
        capture_atoms,
        ignore_set,
        diagnostic_parts,
        flags_prefix,
    })
}

// ── Parsed item ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ParsedItem {
    line_no: usize,
    raw_line: String,
    #[allow(dead_code)]
    atom_values: HashMap<String, Vec<String>>,
    signature: (String, Vec<String>),
}

fn item_from_caps(
    compiled: &CompiledItem,
    caps: &regex::Captures,
    line_no: usize,
    raw_line: &str,
) -> ParsedItem {
    let mut atom_values: HashMap<String, Vec<String>> = HashMap::new();
    let mut sig_values = Vec::new();

    for (atom_name, group_name) in &compiled.capture_atoms {
        if let Some(val) = caps.name(group_name) {
            let val_str = val.as_str().to_string();
            atom_values
                .entry(atom_name.clone())
                .or_default()
                .push(val_str.clone());
            if !compiled.ignore_set.contains(atom_name) {
                sig_values.push(val_str);
            }
        }
    }

    ParsedItem {
        line_no,
        raw_line: raw_line.to_string(),
        atom_values,
        signature: (compiled.name.clone(), sig_values),
    }
}

// ── Log parsing ──────────────────────────────────────────────────────

/// Accumulates lines into blocks for `general.delimiters` and
/// `general.record_start`:
/// - A delimiter line ends the current block and is discarded.
/// - A `record_start` match ends the current block and starts a new one
///   beginning with that line — for consecutive multi-line records with no
///   separator between them.
/// - With neither configured, every line is its own block.
struct BlockSplitter<'a> {
    config: &'a Config,
    per_line: bool,
    block: String,
    block_start_line: usize,
    line_no: usize,
}

impl<'a> BlockSplitter<'a> {
    fn new(config: &'a Config) -> Self {
        BlockSplitter {
            config,
            per_line: config.delimiters.is_empty() && config.record_start.is_empty(),
            block: String::new(),
            block_start_line: 1,
            line_no: 1,
        }
    }

    /// Feed one line, including its trailing newline if any. Returns a
    /// completed block (start line, text) if this line closed one.
    fn push(&mut self, line: &str) -> Option<(usize, String)> {
        let stripped = line.trim_end_matches(['\n', '\r']);
        let mut completed = None;

        if is_delimiter_line(stripped, self.config) {
            completed = self.take();
        } else {
            let starts_new_record = !self.block.is_empty() && is_record_start_line(stripped, self.config);
            if starts_new_record {
                completed = self.take();
            }
            if self.block.is_empty() {
                self.block_start_line = self.line_no;
            }
            self.block.push_str(line);
            if self.per_line {
                completed = self.take();
            }
        }

        self.line_no += 1;
        completed
    }

    fn take(&mut self) -> Option<(usize, String)> {
        if self.block.is_empty() {
            return None;
        }
        Some((self.block_start_line, std::mem::take(&mut self.block)))
    }

    fn finish(mut self) -> Option<(usize, String)> {
        self.take()
    }
}

/// Split `content` into blocks (see `BlockSplitter`) and parse each one.
/// A block parses only if an item pattern matches it in full.
fn parse_log(content: &str, config: &Config) -> (Vec<ParsedItem>, Vec<usize>) {
    let mut items = Vec::new();
    let mut unparsed_blocks = Vec::new();
    let mut splitter = BlockSplitter::new(config);

    let mut record = |start: usize, block: &str| match parse_block(block, start, config) {
        Some(item) => items.push(item),
        None => unparsed_blocks.push(start),
    };

    for line in content.split_inclusive('\n') {
        if let Some((start, block)) = splitter.push(line) {
            record(start, &block);
        }
    }
    if let Some((start, block)) = splitter.finish() {
        record(start, &block);
    }

    (items, unparsed_blocks)
}

/// Captures for `item` if its pattern matches the whole of `text`.
fn full_match<'t>(item: &CompiledItem, text: &'t str) -> Option<regex::Captures<'t>> {
    item.pattern.captures(text).filter(|caps| {
        let m = caps.get(0).unwrap();
        m.start() == 0 && m.end() == text.len()
    })
}

fn parse_block(block: &str, start_line_no: usize, config: &Config) -> Option<ParsedItem> {
    let text = block.trim_end_matches(['\n', '\r']);
    config
        .items
        .iter()
        .find_map(|item| Some(item_from_caps(item, &full_match(item, text)?, start_line_no, text)))
}

// ── Comparison ───────────────────────────────────────────────────────

#[derive(Debug)]
enum CompareEvent {
    Match { dirty_idx: usize },
    Extra { dirty_idx: usize },
    Missing { clean_idx: usize },
}

struct CompareResult {
    events: Vec<CompareEvent>,
    stopped: bool,
    stop_reason: Option<String>,
    /// Full match assignment from Phase 1 (dirty index -> matched clean
    /// index), independent of early-stop truncation. Used by the
    /// side-by-side view to lay out the whole comparison regardless of
    /// where the plain-text output would have stopped.
    dirty_to_clean: Vec<Option<usize>>,
}

fn compare(
    clean_items: &[ParsedItem],
    dirty_items: &[ParsedItem],
    threshold: usize,
    max_failed_items: usize,
) -> CompareResult {
    // Phase 1: find matches — scan dirty left-to-right, find closest unmatched clean
    let mut clean_matched = vec![false; clean_items.len()];
    let mut dirty_to_clean: Vec<Option<usize>> = vec![None; dirty_items.len()];

    for (di, dirty_item) in dirty_items.iter().enumerate() {
        let lo = di.saturating_sub(threshold);
        let hi = (di + threshold + 1).min(clean_items.len());
        let best = (lo..hi)
            .filter(|&ci| !clean_matched[ci] && clean_items[ci].signature == dirty_item.signature)
            .min_by_key(|&ci| di.abs_diff(ci));
        if let Some(ci) = best {
            clean_matched[ci] = true;
            dirty_to_clean[di] = Some(ci);
        }
    }

    // Phase 2: emit events
    let mut events = Vec::new();
    let mut failed_run: usize = 0;
    let mut stopped = false;
    let mut stop_reason: Option<String> = None;

    for (di, mapped) in dirty_to_clean.iter().enumerate() {
        if mapped.is_some() {
            events.push(CompareEvent::Match { dirty_idx: di });
            failed_run = 0;
        } else {
            events.push(CompareEvent::Extra { dirty_idx: di });
            failed_run += 1;
            if max_failed_items > 0 && failed_run >= max_failed_items {
                stopped = true;
                stop_reason = Some(format!(
                    "stopped after {} consecutive failures at dirty index {}",
                    failed_run, di
                ));
                break;
            }
        }
    }

    // Append Missing for unmatched clean items (skip if stopped)
    if !stopped {
        for (ci, matched) in clean_matched.iter().enumerate() {
            if !matched {
                events.push(CompareEvent::Missing { clean_idx: ci });
            }
        }
    }

    CompareResult {
        events,
        stopped,
        stop_reason,
        dirty_to_clean,
    }
}

// ── Output ───────────────────────────────────────────────────────────

fn print_output(result: &CompareResult, clean_items: &[ParsedItem], dirty_items: &[ParsedItem]) {
    for event in &result.events {
        match event {
            CompareEvent::Match { dirty_idx } => {
                println!("{}", dirty_items[*dirty_idx].raw_line);
            }
            CompareEvent::Extra { dirty_idx } => {
                let dirty = &dirty_items[*dirty_idx];
                println!("--- DIVERGENCE ---");
                println!(
                    "Unexpected extra in dirty log: '{}' (dirty line {})",
                    dirty.raw_line, dirty.line_no
                );
                return;
            }
            CompareEvent::Missing { clean_idx } => {
                let clean = &clean_items[*clean_idx];
                println!("--- DIVERGENCE ---");
                println!(
                    "Expected item missing from dirty log: '{}' (clean line {})",
                    clean.raw_line, clean.line_no
                );
                return;
            }
        }
    }

    if result.stopped {
        if let Some(reason) = &result.stop_reason {
            println!("--- STOPPED ---");
            println!("{}", reason);
        }
    }
}

// ── Validate ─────────────────────────────────────────────────────────

struct ValidateResult {
    output: String,
    error: Option<String>,
}

fn validation_failure(
    processed: usize,
    line_no: usize,
    content: &str,
    config: &Config,
) -> ValidateResult {
    let first_line = content.lines().next().unwrap_or("").trim();
    // Plain, uncolored: used for the exit-code decision and asserted on directly
    // by callers/tests, not meant for display.
    let error = format!(
        "validation error at line {}: no pattern matched '{}'",
        line_no, first_line
    );
    let output = format!(
        "Processed {} items\n{}\n{}\n{}",
        processed,
        style(RED_BOLD, &error),
        diagnose_mismatch(content, config).trim_end(),
        style(RED_BOLD, "Validation failed, issue with Config.toml 🔴"),
    );
    ValidateResult {
        output,
        error: Some(error),
    }
}

/// Replace literal `\n` and `\r\n` text sequences with actual newlines.
/// If the sequence is already followed by an actual newline, the literal
/// sequence is removed without inserting a duplicate newline.
fn clean_log_content(content: &str) -> String {
    let mut result = String::with_capacity(content.len());
    let mut rest = content;

    while let Some(i) = rest.find('\\') {
        result.push_str(&rest[..i]);
        rest = &rest[i..];
        let literal_len = if rest.starts_with("\\r\\n") {
            4
        } else if rest.starts_with("\\n") {
            2
        } else {
            0
        };
        if literal_len > 0 {
            rest = &rest[literal_len..];
            if !rest.starts_with('\n') {
                result.push('\n');
            }
        } else {
            result.push('\\');
            rest = &rest[1..];
        }
    }
    result.push_str(rest);

    result
}

// ── Mismatch diagnostics ─────────────────────────────────────────────

struct FailedPart {
    label: String,
    pattern: String,
    got: String,
}

/// Matched parts as (label, captured value) pairs.
type MatchedParts = Vec<(String, Option<String>)>;

/// Match progressively longer prefixes of `item`'s parts against the start
/// of `content`. Returns the matched parts and the part that broke the
/// match, if any.
fn diagnose_item(item: &CompiledItem, content: &str) -> (MatchedParts, Option<FailedPart>) {
    let mut matched: MatchedParts = Vec::new();
    let mut prefix_pattern = item.flags_prefix.clone();
    let mut last_match_end: usize = 0;

    for part in &item.diagnostic_parts {
        prefix_pattern.push_str(&part.fragment);

        let hit = Regex::new(&prefix_pattern).ok().and_then(|re| {
            let m = re.find(content).filter(|m| m.start() == 0)?;
            // Extract the capture value of the group just added, if it's an atom part
            let captured = if part.label != "(joining-regex)" {
                re.captures(content)
                    .and_then(|caps| caps.get(caps.len() - 1).map(|m| m.as_str().to_string()))
            } else {
                None
            };
            Some((m.end(), captured))
        });

        match hit {
            Some((end, captured)) => {
                matched.push((part.label.clone(), captured));
                last_match_end = end;
            }
            None => {
                let failed = FailedPart {
                    label: part.label.clone(),
                    pattern: part.fragment.clone(),
                    got: snippet(content, last_match_end),
                };
                return (matched, Some(failed));
            }
        }
    }

    (matched, None)
}

/// Diagnose why no pattern matched `content` by progressively testing
/// longer prefixes of each item's pattern. Returns a formatted string
/// showing the best partial match and where it broke.
fn diagnose_mismatch(content: &str, config: &Config) -> String {
    let mut best: Option<(&CompiledItem, MatchedParts, Option<FailedPart>)> = None;

    for item in &config.items {
        let (matched, failed) = diagnose_item(item, content);
        let better = match &best {
            None => true,
            Some((best_item, best_matched, _)) => {
                matched.len() > best_matched.len()
                    || (matched.len() == best_matched.len()
                        && item.diagnostic_parts.len() < best_item.diagnostic_parts.len())
            }
        };
        if better {
            best = Some((item, matched, failed));
        }
    }

    let Some((item, matched, failed)) = best else {
        return String::new();
    };
    let total = item.diagnostic_parts.len();

    let mut out = String::new();
    out.push_str(&style(
        BOLD,
        &format!(
            "  Best match: item '{}' (matched {}/{} parts)",
            item.name,
            matched.len(),
            total
        ),
    ));
    out.push('\n');

    for (label, captured) in &matched {
        let text = match captured {
            Some(val) => format!("{} = \"{}\"", label, val),
            None => label.clone(),
        };
        out.push_str(&style(GREEN, &format!("    {:40} [matched]", text)));
        out.push('\n');
    }

    if let Some(ref f) = failed {
        out.push_str(&style(RED_BOLD, &format!("    {:40} [no match]", f.label)));
        out.push('\n');
        out.push_str(&style(RED, &format!("      pattern: {}", f.pattern)));
        out.push('\n');
        out.push_str(&style(RED, &format!("      got:     \"{}\"", f.got)));
        out.push('\n');
    }

    let remaining = total
        .saturating_sub(matched.len())
        .saturating_sub(failed.is_some() as usize);
    if remaining > 0 {
        out.push_str(&style(DIM, "    ..."));
        out.push('\n');
    }

    out
}

/// Extract a short snippet of text starting at `offset`, for diagnostic display.
/// Truncates to 60 chars and escapes newlines for readability.
fn snippet(content: &str, offset: usize) -> String {
    let remaining = &content[offset..];
    let max_len = 60;
    let truncated = if remaining.len() > max_len {
        &remaining[..max_len]
    } else {
        remaining
    };
    let escaped = truncated
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    if remaining.len() > max_len {
        format!("{}...", escaped)
    } else {
        escaped
    }
}

/// Check a block against the item patterns. Returns the failure result if
/// no pattern matched it in full.
fn check_block(
    start_line: usize,
    block: &str,
    processed: &mut usize,
    config: &Config,
) -> Option<ValidateResult> {
    if parse_block(block, start_line, config).is_none() {
        return Some(validation_failure(
            *processed,
            start_line,
            block.trim_end_matches(['\n', '\r']),
            config,
        ));
    }
    *processed += 1;
    None
}

/// Stream-based validation: reads line by line, accumulating blocks the same
/// way as `parse_log`, and stops at the first block no pattern matches.
fn validate(mut reader: impl BufRead, config: &Config) -> Result<ValidateResult> {
    let mut processed: usize = 0;
    let mut splitter = BlockSplitter::new(config);
    let mut raw = String::new();

    loop {
        raw.clear();
        if reader.read_line(&mut raw)? == 0 {
            break;
        }

        let mut cleaned = clean_log_content(&raw);
        if !cleaned.ends_with('\n') && !cleaned.is_empty() {
            cleaned.push('\n');
        }

        for line in cleaned.split_inclusive('\n') {
            if let Some((start, block)) = splitter.push(line) {
                if let Some(fail) = check_block(start, &block, &mut processed, config) {
                    return Ok(fail);
                }
            }
        }
    }

    if let Some((start, block)) = splitter.finish() {
        if let Some(fail) = check_block(start, &block, &mut processed, config) {
            return Ok(fail);
        }
    }

    Ok(ValidateResult {
        output: format!(
            "Processed {} items\n{}",
            processed,
            style(GREEN_BOLD, "Config.toml correct 🟢")
        ),
        error: None,
    })
}

// ── main ─────────────────────────────────────────────────────────────

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    if let Err(err) = run() {
        let _ = writeln!(anstream::stderr(), "{} {err:?}", style(RED_BOLD, "Error:"));
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    info!(config = %cli.config.display(), "loading configuration");
    let config = load_config(&cli.config, &cli)?;

    if cli.validate {
        let file = fs::File::open(&cli.clean_log)
            .with_context(|| format!("failed to open '{}'", cli.clean_log.display()))?;
        let reader = std::io::BufReader::new(file);
        let result = validate(reader, &config)?;
        writeln!(anstream::stdout(), "{}", result.output)?;
        if result.error.is_some() {
            std::process::exit(1);
        }
        return Ok(());
    }

    let dirty_log = cli
        .dirty_log
        .as_ref()
        .context("missing required argument: <DIRTY_LOG>")?;

    let clean_content = read_file_lossy(&cli.clean_log)?;
    let dirty_content = read_file_lossy(dirty_log)?;

    info!("parsing clean log");
    let (clean_items, clean_unparsed) = parse_log(&clean_content, &config);
    info!("parsing dirty log");
    let (dirty_items, dirty_unparsed) = parse_log(&dirty_content, &config);

    debug!(
        clean_items = clean_items.len(),
        dirty_items = dirty_items.len(),
        clean_unparsed = clean_unparsed.len(),
        dirty_unparsed = dirty_unparsed.len(),
        "parsing complete"
    );

    info!("comparing logs");
    let result = compare(
        &clean_items,
        &dirty_items,
        config.index_threshold,
        config.max_failed_items,
    );

    if cli.side_by_side {
        tui::run_side_by_side(&clean_items, &dirty_items, &result)?;
    } else {
        print_output(&result, &clean_items, &dirty_items);
    }

    Ok(())
}

fn read_file_lossy(path: &PathBuf) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("failed to read '{}'", path.display()))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

mod tui;

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
