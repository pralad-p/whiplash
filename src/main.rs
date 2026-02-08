use std::collections::HashMap;
use std::fs;
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

#[derive(Deserialize, Default)]
struct RawGeneral {
    index_threshold: Option<usize>,
    max_failed_items: Option<usize>,
    blacklist_atoms: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct RawItem {
    name: String,
    parts: Option<Vec<RawPart>>,
    anchored: Option<bool>,
    flags: Option<FlagValue>,
    ignore_atoms: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum FlagValue {
    Single(String),
    List(Vec<String>),
}

#[derive(Deserialize, Clone)]
struct RawPart {
    atom: Option<String>,
    regex: Option<String>,
}

// ── Resolved config ──────────────────────────────────────────────────

struct Config {
    index_threshold: usize,
    max_failed_items: usize,
    #[allow(dead_code)]
    blacklist_atoms: Vec<String>,
    items: Vec<CompiledItem>,
}

struct CompiledItem {
    name: String,
    pattern: Regex,
    anchored: bool,
    /// Atom names that participate in this item's captures (in order).
    capture_atoms: Vec<(String, String)>, // (atom_name, capture_group_name)
    /// Atoms to ignore in signature.
    ignore_set: Vec<String>,
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
    })
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
                pattern_str.push_str(&format!("(?P<{}>{})", group_name, atom_regex));
            }
            (None, Some(regex_frag)) => {
                pattern_str.push_str(regex_frag);
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

    if !flag_str.is_empty() {
        pattern_str = format!("(?{}){}", flag_str, pattern_str);
    }

    debug!(item = %raw.name, pattern = %pattern_str, "compiled pattern");

    let pattern = Regex::new(&pattern_str)
        .with_context(|| format!("invalid regex for item '{}'", raw.name))?;

    let mut ignore_set = blacklist.to_vec();
    ignore_set.extend(raw.ignore_atoms.iter().flatten().cloned());

    Ok(CompiledItem {
        name: raw.name.clone(),
        pattern,
        anchored: raw.anchored.unwrap_or(false),
        capture_atoms,
        ignore_set,
    })
}

// ── Parsed item ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ParsedItem {
    name: String,
    line_no: usize,
    raw_line: String,
    #[allow(dead_code)]
    atom_values: HashMap<String, Vec<String>>,
    signature: (String, Vec<String>),
}

// ── Log parsing ──────────────────────────────────────────────────────

fn parse_log(content: &str, config: &Config) -> (Vec<ParsedItem>, Vec<usize>) {
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

                // Check anchor: match must end at a line boundary
                if compiled.anchored {
                    let match_end = m.end();
                    let remaining_bytes = remaining.as_bytes();
                    if match_end < remaining_bytes.len() {
                        // Must end at newline
                        let prev_byte = if match_end > 0 {
                            remaining_bytes[match_end - 1]
                        } else {
                            0
                        };
                        if prev_byte != b'\n' && prev_byte != b'\r' {
                            continue;
                        }
                    }
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
                    name: compiled.name.clone(),
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
                let dist = if di >= ci { di - ci } else { ci - di };
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

    for di in 0..dirty_items.len() {
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
        for ci in 0..clean_items.len() {
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
            if i + 3 < len
                && chars[i + 1] == 'r'
                && chars[i + 2] == '\\'
                && chars[i + 3] == 'n'
            {
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

fn validate(content: &str, config: &Config) -> ValidateResult {
    let cleaned = clean_log_content(content);
    let content_lines: Vec<&str> = cleaned.lines().collect();
    let (items, unparsed) = parse_log(&cleaned, config);

    let first_unparsed = unparsed.first().copied();

    let processed_count = if let Some(up_line) = first_unparsed {
        items.iter().filter(|item| item.line_no < up_line).count()
    } else {
        items.len()
    };

    let mut out = format!("Processed {} items", processed_count);

    if let Some(up_line) = first_unparsed {
        let line_content = content_lines
            .get(up_line - 1)
            .map(|s| s.trim())
            .unwrap_or("");
        let error_msg = format!(
            "validation error at line {}: no pattern matched '{}'",
            up_line, line_content
        );
        out.push_str(&format!("\n{}", error_msg));
        out.push_str("\nValidation failed, issue with Config.toml 🔴");
        ValidateResult {
            output: out,
            error: Some(error_msg),
        }
    } else {
        out.push_str("\nConfig.toml correct 🟢");
        ValidateResult {
            output: out,
            error: None,
        }
    }
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
        let content = read_file_lossy(&cli.clean_log)?;
        let result = validate(&content, &config);
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
