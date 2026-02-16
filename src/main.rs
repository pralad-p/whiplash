use std::collections::HashMap;
use std::fs;
use std::io::BufRead;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Parser;
use regex::{Regex, RegexSet};
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
struct CaptureGroup {
    group_name: Box<str>,
    include_in_sig: bool,
}

struct Config {
    index_threshold: usize,
    max_failed_items: usize,
    delimiters: Vec<Regex>,
    items: Vec<CompiledItem>,
    // Fast "which pattern matches" prefilter
    full_set: Option<RegexSet>,
    prefix_set: RegexSet,
}

struct DiagnosticPart {
    label: String,    // atom name or "(regex)" for inline regex
    fragment: String, // the raw regex fragment for this part
}

struct CompiledItem {
    name: String,
    full: Regex,
    prefix: Regex,
    capture_groups: Vec<CaptureGroup>,
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
    let full_set = if !delimiters.is_empty() && compiled_items.len() > 1 {
        Some(
            RegexSet::new(compiled_items.iter().map(|i| i.full.as_str()))
                .context("failed to build full RegexSet")?,
        )
    } else {
        None
    };

    let prefix_set = RegexSet::new(compiled_items.iter().map(|i| i.prefix.as_str()))
        .context("failed to build prefix RegexSet")?;
    Ok(Config {
        index_threshold,
        max_failed_items,
        items: compiled_items,
        delimiters,
        full_set,
        prefix_set,
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

    let mut ignore = std::collections::HashSet::<String>::new();
    for a in blacklist {
        ignore.insert(a.clone());
    }
    for a in raw.ignore_atoms.iter().flatten() {
        ignore.insert(a.clone());
    }
    let mut body = String::new();
    let mut capture_groups: Vec<CaptureGroup> = Vec::new();
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

                capture_groups.push(CaptureGroup {
                    group_name: group_name.clone().into_boxed_str(),
                    include_in_sig: !ignore.contains(atom_name),
                });

                let core = format!("(?P<{}>{})", group_name, atom_regex);
                let fragment = if part.optional {
                    format!("(?:{})?", core)
                } else {
                    core
                };

                body.push_str(&fragment);
                diagnostic_parts.push(DiagnosticPart {
                    label: atom_name.clone(),
                    fragment,
                });
            }
            (None, Some(regex_frag)) => {
                let frag = format!("(?:{})", regex_frag);
                let fragment = if part.optional {
                    format!("(?:{})?", frag)
                } else {
                    frag
                };

                body.push_str(&fragment);
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
        format!("(?{})", flag_str)
    } else {
        String::new()
    };

    let mut full_pat = format!(r"\A(?:{})\z", body);
    let mut prefix_pat = format!(r"\A(?:{})", body);

    if !flags_prefix.is_empty() {
        full_pat = format!("{}{}", flags_prefix, full_pat);
        prefix_pat = format!("{}{}", flags_prefix, prefix_pat);
    }

    let full =
        Regex::new(&full_pat).with_context(|| format!("invalid full regex for '{}'", raw.name))?;
    let prefix = Regex::new(&prefix_pat)
        .with_context(|| format!("invalid prefix regex for '{}'", raw.name))?;

    debug!(item = %raw.name, pattern = %body, "compiled pattern");

    Ok(CompiledItem {
        name: raw.name.clone(),
        full,
        prefix,
        capture_groups,
        diagnostic_parts,
        flags_prefix,
    })
}

// ── Parsed item ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Signature<'a> {
    item_id: usize,
    values: Vec<&'a str>,
}

impl<'a, 'b> PartialEq<Signature<'b>> for Signature<'a> {
    fn eq(&self, other: &Signature<'b>) -> bool {
        self.item_id == other.item_id
            && self.values.len() == other.values.len()
            && self
                .values
                .iter()
                .zip(other.values.iter())
                .all(|(a, b)| a == b)
    }
}

impl<'a> Eq for Signature<'a> {}

#[derive(Debug, Clone)]
struct ParsedItem<'a> {
    line_no: usize,
    raw_line: &'a str,
    sig_hash: u64,
    signature: Signature<'a>,
}

// ── Log parsing ──────────────────────────────────────────────────────
#[inline]
fn signature_hash(item_id: usize, values: &[&str]) -> u64 {
    const FNV_OFFSET: u64 = 14695981039346656037;
    const FNV_PRIME: u64 = 1099511628211;

    let mut h = FNV_OFFSET;
    for b in item_id.to_le_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    for v in values {
        for &b in v.as_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        // separator
        h ^= 0xFF;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

fn parse_log<'a>(content: &'a str, config: &Config) -> (Vec<ParsedItem<'a>>, Vec<usize>) {
    if config.delimiters.is_empty() {
        return parse_log_legacy(content, config); // your old logic but with anchored removed
    }
    parse_log_delimited(content, config)
}

fn parse_log_delimited<'a>(content: &'a str, config: &Config) -> (Vec<ParsedItem<'a>>, Vec<usize>) {
    let mut items = Vec::new();
    let mut unparsed_blocks = Vec::new();

    let bytes = content.as_bytes();
    let len = bytes.len();

    let mut i = 0usize;
    let mut line_no = 1usize;

    let mut block_start_byte: Option<usize> = None;
    let mut block_start_line: usize = 1;

    while i < len {
        let line_start = i;
        while i < len && bytes[i] != b'\n' {
            i += 1;
        }
        if i < len {
            i += 1;
        } // include '\n'
        let line_end = i;

        let line = &content[line_start..line_end];
        let stripped = line.trim_end_matches(['\n', '\r']);

        if is_delimiter_line(stripped, config) {
            if let Some(bs) = block_start_byte.take() {
                let block = &content[bs..line_start];
                if let Some(item) = parse_block(block, block_start_line, config) {
                    items.push(item);
                } else {
                    unparsed_blocks.push(block_start_line);
                }
            }
        } else if block_start_byte.is_none() {
            block_start_byte = Some(line_start);
            block_start_line = line_no;
        }

        line_no += 1;
    }

    if let Some(bs) = block_start_byte {
        let block = &content[bs..len];
        if let Some(item) = parse_block(block, block_start_line, config) {
            items.push(item);
        } else {
            unparsed_blocks.push(block_start_line);
        }
    }

    (items, unparsed_blocks)
}

fn parse_block<'a>(
    block: &'a str,
    start_line_no: usize,
    config: &Config,
) -> Option<ParsedItem<'a>> {
    let text = block.trim_end_matches(['\n', '\r']);
    if text.is_empty() {
        return None;
    }

    let idx = if let Some(set) = &config.full_set {
        set.matches(text).iter().next()?
    } else {
        // small number of items: linear scan
        config.items.iter().position(|it| it.full.is_match(text))?
    };

    let item = &config.items[idx];
    let caps = item.full.captures(text)?;

    let mut values = Vec::with_capacity(item.capture_groups.len());
    for cg in &item.capture_groups {
        if cg.include_in_sig {
            if let Some(m) = caps.name(&cg.group_name) {
                values.push(m.as_str());
            }
        }
    }

    let signature = Signature {
        item_id: idx,
        values,
    };
    let sig_hash = signature_hash(signature.item_id, &signature.values);

    Some(ParsedItem {
        line_no: start_line_no,
        raw_line: text,
        sig_hash,
        signature,
    })
}

#[inline]
fn consume_n_lines(bytes: &[u8], mut pos: usize, lines: usize) -> usize {
    let mut seen = 0usize;
    while pos < bytes.len() && seen < lines {
        if bytes[pos] == b'\n' {
            seen += 1;
        }
        pos += 1;
    }
    pos
}

fn parse_log_legacy<'a>(content: &'a str, config: &Config) -> (Vec<ParsedItem<'a>>, Vec<usize>) {
    let bytes = content.as_bytes();
    let len = bytes.len();

    let mut items = Vec::new();
    let mut unparsed_lines = Vec::new();

    let mut pos = 0usize;
    let mut line_no = 1usize;

    while pos < len {
        let remaining = &content[pos..];

        // Pick the longest match among candidate patterns
        let candidates = config.prefix_set.matches(remaining);
        let mut best_idx: Option<usize> = None;
        let mut best_end: usize = 0;

        for idx in candidates.iter() {
            let item = &config.items[idx];
            if let Some(m) = item.prefix.find(remaining) {
                if m.start() == 0 && m.end() > best_end {
                    best_end = m.end();
                    best_idx = Some(idx);
                }
            }
        }

        let Some(idx) = best_idx else {
            unparsed_lines.push(line_no);
            if let Some(off) = bytes[pos..].iter().position(|&b| b == b'\n') {
                pos += off + 1;
            } else {
                pos = len;
            }
            line_no += 1;
            continue;
        };

        let item = &config.items[idx];

        // Run captures only once for the selected regex
        let Some(caps) = item.prefix.captures(remaining) else {
            // extremely rare if find() succeeded, but be safe
            unparsed_lines.push(line_no);
            if let Some(off) = bytes[pos..].iter().position(|&b| b == b'\n') {
                pos += off + 1;
            } else {
                pos = len;
            }
            line_no += 1;
            continue;
        };

        let m0 = match caps.get(0) {
            Some(m) => m,
            None => {
                unparsed_lines.push(line_no);
                if let Some(off) = bytes[pos..].iter().position(|&b| b == b'\n') {
                    pos += off + 1;
                } else {
                    pos = len;
                }
                line_no += 1;
                continue;
            }
        };

        let matched = m0.as_str();

        let mut values = Vec::with_capacity(item.capture_groups.len());
        for cg in &item.capture_groups {
            if cg.include_in_sig {
                if let Some(m) = caps.name(&cg.group_name) {
                    values.push(m.as_str());
                }
            }
        }

        let signature = Signature {
            item_id: idx,
            values,
        };
        let sig_hash = signature_hash(signature.item_id, &signature.values);

        let raw_line = matched.trim_end_matches(['\n', '\r']);
        items.push(ParsedItem {
            line_no,
            raw_line,
            sig_hash,
            signature,
        });

        let span = matched.lines().count().max(1);
        pos = consume_n_lines(bytes, pos, span);
        line_no += span;
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

fn compare<'c, 'd>(
    clean_items: &[ParsedItem<'c>],
    dirty_items: &[ParsedItem<'d>],
    threshold: usize,
    max_failed_items: usize,
) -> CompareResult {
    use std::collections::HashMap;

    let mut clean_matched = vec![false; clean_items.len()];
    let mut dirty_to_clean: Vec<Option<usize>> = vec![None; dirty_items.len()];

    // Index clean items by sig_hash -> sorted list of indices
    let mut index: HashMap<u64, Vec<usize>> = HashMap::with_capacity(clean_items.len() * 2);
    for (ci, it) in clean_items.iter().enumerate() {
        index.entry(it.sig_hash).or_default().push(ci);
    }

    for (di, dirty_item) in dirty_items.iter().enumerate() {
        if clean_items.is_empty() {
            continue;
        }

        let lo = di.saturating_sub(threshold);
        let hi = (di + threshold).min(clean_items.len().saturating_sub(1));
        if lo >= clean_items.len() {
            continue;
        }

        let Some(cands) = index.get(&dirty_item.sig_hash) else {
            continue;
        };

        // restrict to candidate indices within [lo, hi]
        let l = cands.partition_point(|&x| x < lo);
        let r = cands.partition_point(|&x| x <= hi);

        let mut best: Option<usize> = None;
        let mut best_dist: usize = usize::MAX;

        for &ci in &cands[l..r] {
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

    // Phase 2 unchanged (emit events) ...
    let mut events = Vec::new();
    let mut failed_run: usize = 0;
    let mut stopped = false;
    let mut stop_reason: Option<String> = None;

    for (di, _) in dirty_to_clean.iter().enumerate() {
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

    if !stopped {
        for (ci, _) in clean_matched.iter().enumerate() {
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

fn print_output<'c, 'd>(
    result: &CompareResult,
    clean_items: &[ParsedItem<'c>],
    dirty_items: &[ParsedItem<'d>],
) {
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
            let bytes = item.prefix.as_str().as_bytes();
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
    config.items.iter().any(|item| item.full.is_match(text))
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
            let candidates = config.prefix_set.matches(&buf);

            let mut best_end: usize = 0;
            let mut best_idx: Option<usize> = None;

            for idx in candidates.iter() {
                let compiled = &config.items[idx];
                if let Some(m) = compiled.prefix.find(&buf) {
                    if m.start() == 0 && m.end() > best_end {
                        best_end = m.end();
                        best_idx = Some(idx);
                    }
                }
            }
            if let Some(idx) = best_idx {
                let m = config.items[idx].prefix.find(&buf).unwrap();
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
