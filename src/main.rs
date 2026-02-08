use std::collections::HashMap;
use std::fs;
use std::io::BufRead;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Parser;
use regex::Regex;
use serde::Deserialize;
use tracing::{debug, info};

const VERSION: &str = env!("CARGO_PKG_VERSION");

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

#[derive(Deserialize)]
#[serde(untagged)]
enum DelimiterValue {
    Single(String),
    List(Vec<String>),
}

#[derive(Deserialize, Default)]
struct RawGeneral {
    index_threshold: Option<usize>,
    max_failed_items: Option<usize>,
    blacklist_atoms: Option<Vec<String>>,
    delimiters: Option<DelimiterValue>, // <-- add
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
    #[allow(dead_code)]
    blacklist_atoms: Vec<String>,
    delimiters: Vec<Regex>,
    items: Vec<CompiledItem>,
}

struct DiagnosticPart {
    label: String,    // atom name or "(regex)" for inline regex
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
    let delimiters = compile_delimiters(&general)?;
    let index_threshold = cli
        .threshold
        .unwrap_or(general.index_threshold.unwrap_or(0));
    let max_failed_items = cli
        .max_failed
        .unwrap_or(general.max_failed_items.unwrap_or(0));
    let blacklist_atoms = general.blacklist_atoms.unwrap_or_default();

    let mut compiled_items = Vec::new();
    for raw_item in &raw.items {
        let item = compile_item(raw_item, &raw.atoms, &blacklist_atoms)
            .with_context(|| format!("compiling item '{}'", raw_item.name))?;
        compiled_items.push(item);
    }
    Ok(Config {
        index_threshold,
        max_failed_items,
        blacklist_atoms,
        items: compiled_items,
        delimiters,
    })
}

fn is_delimiter_line(line_without_newline: &str, config: &Config) -> bool {
    config
        .delimiters
        .iter()
        .any(|re| re.is_match(line_without_newline))
}

fn compile_delimiters(general: &RawGeneral) -> Result<Vec<Regex>> {
    let raw: Vec<String> = match &general.delimiters {
        Some(DelimiterValue::Single(s)) => vec![s.clone()],
        Some(DelimiterValue::List(v)) => v.clone(),
        None => vec![],
    };

    raw.into_iter()
        .map(|pat| Regex::new(&pat).with_context(|| format!("invalid delimiter regex: {}", pat)))
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

    let mut pattern_str = String::new();
    let mut capture_atoms: Vec<(String, String)> = Vec::new();
    let mut ordinal_counter: HashMap<String, usize> = HashMap::new();
    let mut diagnostic_parts: Vec<DiagnosticPart> = Vec::new();

    for part in parts {
        match (&part.atom, &part.regex) {
            (Some(atom_name), None) => {
                let atom_regex = atoms
                    .get(atom_name)
                    .with_context(|| format!("atom '{}' not found", atom_name))?;
                let ord = ordinal_counter.entry(atom_name.clone()).or_insert(0);
                let group_name = format!("{}__{}", atom_name, ord);
                *ord += 1;
                capture_atoms.push((atom_name.clone(), group_name.clone()));
                let core = format!("(?P<{}>{})", group_name, atom_regex);
                let fragment = if part.optional {
                    format!("(?:{})?", core)
                } else {
                    core
                };
                pattern_str.push_str(&fragment);
                diagnostic_parts.push(DiagnosticPart {
                    label: atom_name.clone(),
                    fragment,
                });
            }
            (None, Some(regex_frag)) => {
                let fragment = if part.optional {
                    format!("(?:{})?", regex_frag)
                } else {
                    regex_frag.clone()
                };
                pattern_str.push_str(&fragment);
                diagnostic_parts.push(DiagnosticPart {
                    label: "(joining-regex)".to_string(),
                    fragment: regex_frag.clone(),
                });
            }
            _ => bail!("part must have exactly one of `atom` or `regex`"),
        }
    }

    let flags: &[String] = match &raw.flags {
        Some(FlagValue::Single(s)) => std::slice::from_ref(s),
        Some(FlagValue::List(v)) => v,
        None => &[],
    };
    let mut flag_str = String::new();
    for flag in flags {
        match flag.as_str() {
            "IGNORECASE" => flag_str.push('i'),
            "MULTILINE" => flag_str.push('m'),
            "DOTALL" => flag_str.push('s'),
            other => bail!("unknown flag: {}", other),
        }
    }

    let flags_prefix = if !flag_str.is_empty() {
        let prefix = format!("(?{})", flag_str);
        pattern_str = format!("{}{}", prefix, pattern_str);
        prefix
    } else {
        String::new()
    };

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

// ── Log parsing ──────────────────────────────────────────────────────

fn parse_log(content: &str, config: &Config) -> (Vec<ParsedItem>, Vec<usize>) {
    if config.delimiters.is_empty() {
        return parse_log_legacy(content, config); // your old logic but with anchored removed
    }

    let lines = split_lines_keepends(content);
    let mut items = Vec::new();
    let mut unparsed_blocks = Vec::new();

    let mut block = String::new();
    let mut block_start_line: usize = 1;

    for (i, line) in lines.iter().enumerate() {
        let stripped = line.trim_end_matches(['\n', '\r']);
        if is_delimiter_line(stripped, config) {
            if !block.is_empty() {
                if let Some(item) = parse_block(&block, block_start_line, config) {
                    items.push(item);
                } else {
                    unparsed_blocks.push(block_start_line);
                }
                block.clear();
            }
            continue;
        }

        if block.is_empty() {
            block_start_line = i + 1; // 1-based
        }
        block.push_str(line);
    }

    if !block.is_empty() {
        if let Some(item) = parse_block(&block, block_start_line, config) {
            items.push(item);
        } else {
            unparsed_blocks.push(block_start_line);
        }
    }

    (items, unparsed_blocks)
}

fn parse_block(block: &str, start_line_no: usize, config: &Config) -> Option<ParsedItem> {
    let text = block.trim_end_matches(['\n', '\r']);

    for compiled in &config.items {
        // Require full-block match:
        let m = compiled.pattern.find(text)?;
        if m.start() != 0 || m.end() != text.len() {
            continue;
        }

        let caps = compiled.pattern.captures(text)?;

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

        return Some(ParsedItem {
            line_no: start_line_no,
            raw_line: text.to_string(),
            atom_values,
            signature: (compiled.name.clone(), sig_values),
        });
    }

    None
}

fn parse_log_legacy(content: &str, config: &Config) -> (Vec<ParsedItem>, Vec<usize>) {
    let lines: Vec<&str> = split_lines_keepends(content);
    let mut items = Vec::new();
    let mut unparsed_lines = Vec::new();
    let mut pos = 0;

    while pos < lines.len() {
        let remaining: String = lines[pos..].concat();
        let mut matched = false;

        for compiled in &config.items {
            if let Some(m) = compiled.pattern.find(&remaining) {
                // Match must start at the beginning of the remaining text
                if m.start() != 0 {
                    continue;
                }

                // Extract captures
                let caps = compiled.pattern.captures(&remaining).unwrap();
                let matched_text = m.as_str();

                // Count how many lines the match spans
                let lines_spanned = matched_text.lines().count().max(1);

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

                let raw_line = matched_text.trim_end_matches(['\n', '\r']).to_string();

                items.push(ParsedItem {
                    line_no: pos + 1,
                    raw_line,
                    atom_values,
                    signature: (compiled.name.clone(), sig_values),
                });

                pos += lines_spanned;
                matched = true;
                break;
            }
        }

        if !matched {
            unparsed_lines.push(pos + 1);
            pos += 1;
        }
    }

    (items, unparsed_lines)
}

fn split_lines_keepends(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let bytes = text.as_bytes();
    let len = bytes.len();

    while start < len {
        let mut end = start;
        while end < len && bytes[end] != b'\n' {
            end += 1;
        }
        if end < len {
            end += 1; // include the \n
        }
        lines.push(&text[start..end]);
        start = end;
    }

    lines
}

// ── Comparison ───────────────────────────────────────────────────────

#[derive(Debug)]
enum CompareEvent {
    Match {
        #[allow(dead_code)]
        clean_idx: usize,
        dirty_idx: usize,
    },
    Extra {
        dirty_idx: usize,
    },
    Missing {
        clean_idx: usize,
    },
}

struct CompareResult {
    events: Vec<CompareEvent>,
    stopped: bool,
    stop_reason: Option<String>,
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
        let hi = (di + threshold).min(clean_items.len().saturating_sub(1));

        if lo >= clean_items.len() {
            continue;
        }

        let mut best: Option<usize> = None;
        let mut best_dist: usize = usize::MAX;
        for ci in lo..=hi {
            if clean_matched[ci] {
                continue;
            }
            if dirty_item.signature == clean_items[ci].signature {
                let dist = di.abs_diff(ci);
                if dist < best_dist {
                    best = Some(ci);
                    best_dist = dist;
                }
            }
        }

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

    for (di, _) in dirty_to_clean.iter().enumerate().take(dirty_items.len()) {
        if let Some(ci) = dirty_to_clean[di] {
            events.push(CompareEvent::Match {
                clean_idx: ci,
                dirty_idx: di,
            });
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
        for (ci, _) in clean_matched.iter().enumerate().take(clean_items.len()) {
            if !clean_matched[ci] {
                events.push(CompareEvent::Missing { clean_idx: ci });
            }
        }
    }

    CompareResult {
        events,
        stopped,
        stop_reason,
    }
}

// ── Output ───────────────────────────────────────────────────────────

fn print_output(result: &CompareResult, clean_items: &[ParsedItem], dirty_items: &[ParsedItem]) {
    for event in &result.events {
        match event {
            CompareEvent::Match { dirty_idx, .. } => {
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

/// Replace literal `\n` and `\r\n` text sequences with actual newlines.
/// If the sequence is already followed by an actual newline, the literal
/// sequence is removed without inserting a duplicate newline.
fn clean_log_content(content: &str) -> String {
    let chars: Vec<char> = content.chars().collect();
    let len = chars.len();
    let mut result = String::with_capacity(content.len());
    let mut i = 0;

    while i < len {
        if chars[i] == '\\' {
            // Check for literal \r\n (4 chars: \, r, \, n)
            if i + 3 < len && chars[i + 1] == 'r' && chars[i + 2] == '\\' && chars[i + 3] == 'n' {
                if i + 4 >= len || chars[i + 4] != '\n' {
                    result.push('\n');
                }
                i += 4;
                continue;
            }
            // Check for literal \n (2 chars: \, n)
            if i + 1 < len && chars[i + 1] == 'n' {
                if i + 2 >= len || chars[i + 2] != '\n' {
                    result.push('\n');
                }
                i += 2;
                continue;
            }
        }
        result.push(chars[i]);
        i += 1;
    }

    result
}

/// Compute the maximum number of lines any single pattern might span
/// by counting `\n` escape sequences in each compiled regex.
fn max_pattern_line_span(config: &Config) -> usize {
    config
        .items
        .iter()
        .map(|item| {
            let bytes = item.pattern.as_str().as_bytes();
            let newline_escapes = bytes
                .windows(2)
                .filter(|w| w[0] == b'\\' && w[1] == b'n')
                .count();
            newline_escapes + 1
        })
        .max()
        .unwrap_or(1)
}

/// Diagnose why no pattern matched `content` by progressively testing
/// longer prefixes of each item's pattern. Returns a formatted string
/// showing the best partial match and where it broke.
fn diagnose_mismatch(content: &str, config: &Config) -> String {
    let mut best_item_name = "";
    let mut best_total_parts = 0;
    let mut best_matched_count: Option<usize> = None;
    let mut best_matched_labels: Vec<(String, Option<String>)> = Vec::new(); // (label, captured_value)
    let mut best_failed_label: Option<String> = None;
    let mut best_remaining_count = 0;

    for item in &config.items {
        let parts = &item.diagnostic_parts;
        let total = parts.len();
        let mut matched_count: usize = 0;
        let mut matched_labels: Vec<(String, Option<String>)> = Vec::new();
        let mut failed_label: Option<String> = None;

        for i in 0..total {
            // Build prefix pattern from parts[0..=i]
            let mut prefix_pattern = item.flags_prefix.clone();
            for p in &parts[..=i] {
                prefix_pattern.push_str(&p.fragment);
            }

            // Try to compile and match at the start of content
            let Ok(re) = Regex::new(&prefix_pattern) else {
                failed_label = Some(parts[i].label.clone());
                break;
            };

            if let Some(m) = re.find(content) {
                if m.start() != 0 {
                    failed_label = Some(parts[i].label.clone());
                    break;
                }
                // This prefix matched — extract capture value if it's an atom part
                let captured = if parts[i].label != "(joining-regex)" {
                    re.captures(content).and_then(|caps| {
                        // Find the last capture group (the one just added in this prefix)
                        caps.get(caps.len() - 1).map(|m| m.as_str().to_string())
                    })
                } else {
                    None
                };
                matched_labels.push((parts[i].label.clone(), captured));
                matched_count = i + 1;
            } else {
                failed_label = Some(parts[i].label.clone());
                break;
            }
        }

        let dominated = match best_matched_count {
            None => true,
            Some(best) => {
                matched_count > best || (matched_count == best && total < best_total_parts)
            }
        };
        if dominated {
            best_item_name = &item.name;
            best_total_parts = total;
            best_matched_count = Some(matched_count);
            best_matched_labels = matched_labels;
            best_failed_label = failed_label;
            best_remaining_count = total
                .saturating_sub(matched_count)
                .saturating_sub(if best_failed_label.is_some() { 1 } else { 0 });
        }
    }

    let mut out = String::new();
    let matched = best_matched_count.unwrap_or(0);
    out.push_str(&format!(
        "  Best match: item '{}' (matched {}/{} parts)\n",
        best_item_name, matched, best_total_parts
    ));

    for (label, captured) in &best_matched_labels {
        if label == "(regex)" {
            out.push_str(&format!("    {:40} [matched]\n", format!("\"{}\"", label)));
        } else if let Some(val) = captured {
            out.push_str(&format!(
                "    {:40} [matched]\n",
                format!("{} = \"{}\"", label, val)
            ));
        } else {
            out.push_str(&format!("    {:40} [matched]\n", label));
        }
    }

    if let Some(ref label) = best_failed_label {
        out.push_str(&format!("    {:40} [no match]\n", label));
    }

    if best_remaining_count > 0 {
        out.push_str("    ...\n");
    }

    out
}

fn validate(mut reader: impl BufRead, config: &Config) -> Result<ValidateResult> {
    if config.delimiters.is_empty() {
        return validate_legacy(reader, config); // your current validate() but anchored removed
    }

    let mut processed: usize = 0;

    let mut block = String::new();
    let mut block_start_line: usize = 1;
    let mut line_no: usize = 1;

    loop {
        let mut raw = String::new();
        let n = reader.read_line(&mut raw)?;
        let eof = n == 0;

        if !eof {
            // Keep your cleaning behavior, but split into real lines afterward
            let mut cleaned = clean_log_content(&raw);
            if !cleaned.ends_with('\n') && !cleaned.is_empty() {
                cleaned.push('\n');
            }

            for line in split_lines_keepends(&cleaned) {
                let stripped = line.trim_end_matches(['\n', '\r']);

                if is_delimiter_line(stripped, config) {
                    if !block.is_empty() {
                        if !block_matches_any_item(&block, config) {
                            let first_line = block.lines().next().unwrap_or("").trim();
                            let error_msg = format!(
                                "validation error at line {}: no pattern matched '{}'",
                                block_start_line, first_line
                            );
                            let diagnostic =
                                diagnose_mismatch(block.trim_end_matches(['\n', '\r']), config);
                            let mut out = format!("Processed {} items", processed);
                            out.push_str(&format!("\n{}", error_msg));
                            out.push_str(&format!("\n{}", diagnostic.trim_end()));
                            out.push_str("\nValidation failed, issue with Config.toml 🔴");
                            return Ok(ValidateResult {
                                output: out,
                                error: Some(error_msg),
                            });
                        }

                        processed += 1;
                        block.clear();
                    }
                    line_no += 1;
                    continue;
                }

                if block.is_empty() {
                    block_start_line = line_no;
                }
                block.push_str(line);
                line_no += 1;
            }
        }

        if eof {
            break;
        }
    }

    if !block.is_empty() {
        if !block_matches_any_item(&block, config) {
            let first_line = block.lines().next().unwrap_or("").trim();
            let error_msg = format!(
                "validation error at line {}: no pattern matched '{}'",
                block_start_line, first_line
            );
            let diagnostic = diagnose_mismatch(block.trim_end_matches(['\n', '\r']), config);
            let mut out = format!("Processed {} items", processed);
            out.push_str(&format!("\n{}", error_msg));
            out.push_str(&format!("\n{}", diagnostic.trim_end()));
            out.push_str("\nValidation failed, issue with Config.toml 🔴");
            return Ok(ValidateResult {
                output: out,
                error: Some(error_msg),
            });
        }
        processed += 1;
    }

    Ok(ValidateResult {
        output: format!("Processed {} items\nConfig.toml correct 🟢", processed),
        error: None,
    })
}

fn block_matches_any_item(block: &str, config: &Config) -> bool {
    let text = block.trim_end_matches(['\n', '\r']);
    config.items.iter().any(|item| {
        item.pattern
            .find(text)
            .is_some_and(|m| m.start() == 0 && m.end() == text.len())
    })
}

/// Stream-based validation: reads from any `BufRead` source line by line,
/// keeping only a small buffer for multi-line pattern look-ahead.
/// Stops immediately at the first non-matching line.
fn validate_legacy(mut reader: impl BufRead, config: &Config) -> Result<ValidateResult> {
    let max_span = max_pattern_line_span(config);
    let mut buf = String::new();
    let mut line_no: usize = 1;
    let mut processed: usize = 0;
    let mut raw_line = String::new();
    let mut at_eof = false;

    loop {
        // Read one raw line (preserves trailing newline)
        if !at_eof {
            raw_line.clear();
            match reader.read_line(&mut raw_line) {
                Ok(0) => at_eof = true,
                Ok(_) => {
                    let cleaned = clean_log_content(&raw_line);
                    buf.push_str(&cleaned);
                    if !cleaned.ends_with('\n') && !cleaned.is_empty() {
                        buf.push('\n');
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }

        // Consume matches from the front of buf
        loop {
            if buf.is_empty() {
                break;
            }
            let mut matched = false;
            for compiled in &config.items {
                if let Some(m) = compiled.pattern.find(&buf) {
                    if m.start() != 0 {
                        continue;
                    }

                    let span = m.as_str().lines().count().max(1);

                    // Advance past the complete matched lines
                    let mut consumed = 0;
                    let mut counted = 0;
                    let bytes = buf.as_bytes();
                    while counted < span && consumed < bytes.len() {
                        if bytes[consumed] == b'\n' {
                            counted += 1;
                        }
                        consumed += 1;
                    }

                    buf.drain(..consumed);
                    line_no += span;
                    processed += 1;
                    matched = true;
                    break;
                }
            }
            if !matched {
                break;
            }
        }

        // Check for non-matching content in the buffer
        if !buf.is_empty() {
            let newlines_in_buf = buf.as_bytes().iter().filter(|&&b| b == b'\n').count();
            if at_eof || newlines_in_buf >= max_span {
                let first_line = buf.lines().next().unwrap_or("").trim();
                let error_msg = format!(
                    "validation error at line {}: no pattern matched '{}'",
                    line_no, first_line
                );
                let diagnostic = diagnose_mismatch(&buf, config);
                let mut out = format!("Processed {} items", processed);
                out.push_str(&format!("\n{}", error_msg));
                out.push_str(&format!("\n{}", diagnostic.trim_end()));
                out.push_str("\nValidation failed, issue with Config.toml 🔴");
                return Ok(ValidateResult {
                    output: out,
                    error: Some(error_msg),
                });
            }
        }

        if at_eof {
            break;
        }
    }

    let mut out = format!("Processed {} items", processed);
    out.push_str("\nConfig.toml correct 🟢");
    Ok(ValidateResult {
        output: out,
        error: None,
    })
}

// ── main ─────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    info!(config = %cli.config.display(), "loading configuration");
    let config = load_config(&cli.config, &cli)?;

    if cli.validate {
        let file = fs::File::open(&cli.clean_log)
            .with_context(|| format!("failed to open '{}'", cli.clean_log.display()))?;
        let reader = std::io::BufReader::new(file);
        let result = validate(reader, &config)?;
        println!("{}", result.output);
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

    print_output(&result, &clean_items, &dirty_items);

    Ok(())
}

fn read_file_lossy(path: &PathBuf) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("failed to read '{}'", path.display()))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
