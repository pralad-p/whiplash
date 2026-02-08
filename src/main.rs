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

    /// Clean (reference) log file
    clean_log: PathBuf,

    /// Dirty (test) log file
    dirty_log: PathBuf,
}

// ── Config types (raw TOML deserialization) ──────────────────────────

#[derive(Deserialize)]
struct RawConfig {
    general: Option<RawGeneral>,
    elements: HashMap<String, String>,
    items: Vec<RawItem>,
}

#[derive(Deserialize, Default)]
struct RawGeneral {
    index_threshold: Option<usize>,
    max_failed_items: Option<usize>,
    blacklist_elements: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct RawItem {
    name: String,
    parts: Option<Vec<RawPart>>,
    elements: Option<Vec<String>>,
    joiner: Option<String>,
    anchored: Option<bool>,
    flags: Option<FlagValue>,
    ignore_elements: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum FlagValue {
    Single(String),
    List(Vec<String>),
}

#[derive(Deserialize)]
struct RawPart {
    element: Option<String>,
    regex: Option<String>,
}

// ── Resolved config ──────────────────────────────────────────────────

struct Config {
    index_threshold: usize,
    max_failed_items: usize,
    #[allow(dead_code)]
    blacklist_elements: Vec<String>,
    items: Vec<CompiledItem>,
}

struct CompiledItem {
    name: String,
    pattern: Regex,
    anchored: bool,
    /// Element names that participate in this item's captures (in order).
    capture_elements: Vec<(String, String)>, // (element_name, capture_group_name)
    /// Elements to ignore in signature.
    ignore_set: Vec<String>,
}

// ── Config loading & validation ──────────────────────────────────────

fn load_config(path: &PathBuf, cli: &Cli) -> Result<Config> {
    let text = fs::read_to_string(path).context("failed to read config file")?;
    let raw: RawConfig = toml::from_str(&text).context("failed to parse config TOML")?;

    if raw.elements.is_empty() {
        bail!("config: `elements` must be non-empty");
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
    let blacklist_elements = general.blacklist_elements.unwrap_or_default();

    let mut compiled_items = Vec::new();
    for raw_item in &raw.items {
        let item = compile_item(raw_item, &raw.elements, &blacklist_elements)
            .with_context(|| format!("compiling item '{}'", raw_item.name))?;
        compiled_items.push(item);
    }

    Ok(Config {
        index_threshold,
        max_failed_items,
        blacklist_elements,
        items: compiled_items,
    })
}

fn compile_item(
    raw: &RawItem,
    elements: &HashMap<String, String>,
    blacklist: &[String],
) -> Result<CompiledItem> {
    if raw.name.is_empty() {
        bail!("item name must be non-empty");
    }

    let has_parts = raw.parts.is_some();
    let has_elements = raw.elements.is_some();
    if has_parts && has_elements {
        bail!(
            "item '{}': cannot specify both `parts` and `elements`",
            raw.name
        );
    }
    if !has_parts && !has_elements {
        bail!(
            "item '{}': must specify either `parts` or `elements`",
            raw.name
        );
    }

    let mut pattern_str = String::new();
    let mut capture_elements: Vec<(String, String)> = Vec::new();
    let mut ordinal_counter: HashMap<String, usize> = HashMap::new();

    if let Some(parts) = &raw.parts {
        if parts.is_empty() {
            bail!("item '{}': `parts` must be non-empty", raw.name);
        }
        for part in parts {
            match (&part.element, &part.regex) {
                (Some(elem_name), None) => {
                    let elem_regex = elements
                        .get(elem_name)
                        .with_context(|| format!("element '{}' not found", elem_name))?;
                    let ord = ordinal_counter.entry(elem_name.clone()).or_insert(0);
                    let group_name = format!("{}__{}", elem_name, ord);
                    *ord += 1;
                    capture_elements.push((elem_name.clone(), group_name.clone()));
                    pattern_str.push_str(&format!("(?P<{}>{})", group_name, elem_regex));
                }
                (None, Some(regex_frag)) => {
                    pattern_str.push_str(regex_frag);
                }
                (Some(_), Some(_)) => {
                    bail!("part must have exactly one of `element` or `regex`");
                }
                (None, None) => {
                    bail!("part must have exactly one of `element` or `regex`");
                }
            }
        }
    } else if let Some(elem_names) = &raw.elements {
        if elem_names.is_empty() {
            bail!("item '{}': `elements` must be non-empty", raw.name);
        }
        let joiner = raw.joiner.as_deref().unwrap_or(".*?");
        for (i, elem_name) in elem_names.iter().enumerate() {
            if i > 0 {
                pattern_str.push_str(joiner);
            }
            let elem_regex = elements
                .get(elem_name)
                .with_context(|| format!("element '{}' not found", elem_name))?;
            let ord = ordinal_counter.entry(elem_name.clone()).or_insert(0);
            let group_name = format!("{}__{}", elem_name, ord);
            *ord += 1;
            capture_elements.push((elem_name.clone(), group_name.clone()));
            pattern_str.push_str(&format!("(?P<{}>{})", group_name, elem_regex));
        }
    }

    // Apply flags
    let flags = match &raw.flags {
        Some(FlagValue::Single(s)) => vec![s.clone()],
        Some(FlagValue::List(v)) => v.clone(),
        None => vec![],
    };
    let mut flag_str = String::new();
    for flag in &flags {
        match flag.as_str() {
            "IGNORECASE" => flag_str.push('i'),
            "MULTILINE" => flag_str.push('m'),
            "DOTALL" => flag_str.push('s'),
            other => bail!("unknown flag: {}", other),
        }
    }

    let full_pattern = if flag_str.is_empty() {
        pattern_str
    } else {
        format!("(?{}){}", flag_str, pattern_str)
    };

    debug!(item = %raw.name, pattern = %full_pattern, "compiled pattern");

    let pattern = Regex::new(&full_pattern)
        .with_context(|| format!("invalid regex for item '{}'", raw.name))?;

    let anchored = raw.anchored.unwrap_or(false);

    let mut ignore_set: Vec<String> = blacklist.to_vec();
    if let Some(ignore) = &raw.ignore_elements {
        ignore_set.extend(ignore.iter().cloned());
    }

    Ok(CompiledItem {
        name: raw.name.clone(),
        pattern,
        anchored,
        capture_elements,
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
    element_values: HashMap<String, Vec<String>>,
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
                let lines_spanned = matched_text.matches('\n').count().max(1);

                // Build element_values
                let mut element_values: HashMap<String, Vec<String>> = HashMap::new();
                for (elem_name, group_name) in &compiled.capture_elements {
                    if let Some(val) = caps.name(group_name) {
                        element_values
                            .entry(elem_name.clone())
                            .or_default()
                            .push(val.as_str().to_string());
                    }
                }

                // Build signature: (name, values excluding ignored elements)
                let mut sig_values = Vec::new();
                for (elem_name, group_name) in &compiled.capture_elements {
                    if compiled.ignore_set.contains(elem_name) {
                        continue;
                    }
                    if let Some(val) = caps.name(group_name) {
                        sig_values.push(val.as_str().to_string());
                    }
                }

                let raw_line = matched_text.trim_end_matches(['\n', '\r']).to_string();

                items.push(ParsedItem {
                    name: compiled.name.clone(),
                    line_no: pos + 1,
                    raw_line,
                    element_values,
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
    Mismatch {
        clean_idx: usize,
        reason: String,
    },
    DirtyExtra {
        dirty_idx: usize,
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
    let mut events = Vec::new();
    let mut j: usize = 0; // next unmatched dirty index
    let mut failed_run: usize = 0;
    let mut stopped = false;
    let mut stop_reason: Option<String> = None;
    let mut dirty_matched = vec![false; dirty_items.len()];

    for (i, clean_item) in clean_items.iter().enumerate() {
        // Check early stop
        if max_failed_items > 0 && failed_run >= max_failed_items {
            stopped = true;
            stop_reason = Some(format!(
                "stopped after {} consecutive failures at clean index {}",
                failed_run, i
            ));
            break;
        }

        let min_k = i.saturating_sub(threshold);
        let min_k = min_k.max(j);
        let max_k = (i + threshold).min(dirty_items.len().saturating_sub(1));

        if min_k >= dirty_items.len() || min_k > max_k {
            events.push(CompareEvent::Mismatch {
                clean_idx: i,
                reason: "no candidate within threshold".to_string(),
            });
            failed_run += 1;
            continue;
        }

        // Search within window
        let mut found = None;
        for k in min_k..=max_k {
            if dirty_matched[k] {
                continue;
            }
            if clean_item.signature == dirty_items[k].signature {
                found = Some(k);
                break;
            }
        }

        match found {
            Some(k) => {
                // Record extras between j and k
                for e in dirty_matched.iter().enumerate().take(k).skip(j) {
                    if dirty_matched[e.0] {
                        continue;
                    }
                    events.push(CompareEvent::DirtyExtra { dirty_idx: e.0 });
                    failed_run += 1;

                    if max_failed_items != 0 && failed_run >= max_failed_items {
                        stopped = true;
                        stop_reason = Some(format!(
                            "stopped after {} consecutive failures at clean index {}",
                            failed_run, i
                        ));
                        break;
                    }
                }

                if stopped {
                    break;
                }

                dirty_matched[k] = true;
                events.push(CompareEvent::Match {
                    clean_idx: i,
                    dirty_idx: k,
                });
                j = k + 1;
                failed_run = 0;
            }
            None => {
                events.push(CompareEvent::Mismatch {
                    clean_idx: i,
                    reason: "no match within window".to_string(),
                });
                failed_run += 1;
            }
        }
    }

    // Remaining dirty items as extras
    if !stopped {
        for k in dirty_matched
            .iter()
            .enumerate()
            .take(dirty_items.len())
            .skip(j)
        {
            if !dirty_matched[k.0] {
                events.push(CompareEvent::DirtyExtra { dirty_idx: k.0 });
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
            CompareEvent::Mismatch { clean_idx, reason } => {
                let clean = &clean_items[*clean_idx];
                println!("--- DIVERGENCE ---");
                println!(
                    "Expected: [{}] item '{}' (clean line {})",
                    clean_idx, clean.name, clean.line_no
                );
                println!("Reason: {}", reason);
                return;
            }
            CompareEvent::DirtyExtra { dirty_idx } => {
                let dirty = &dirty_items[*dirty_idx];
                println!("--- DIVERGENCE ---");
                println!(
                    "Unexpected extra in dirty log: '{}' (dirty line {})",
                    dirty.raw_line, dirty.line_no
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

    let clean_content = read_file_lossy(&cli.clean_log)?;
    let dirty_content = read_file_lossy(&cli.dirty_log)?;

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
