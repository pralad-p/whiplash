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
    let index_threshold = cli.threshold.unwrap_or(general.index_threshold.unwrap_or(0));
    let max_failed_items = cli.max_failed.unwrap_or(general.max_failed_items.unwrap_or(0));
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
        bail!("item '{}': cannot specify both `parts` and `elements`", raw.name);
    }
    if !has_parts && !has_elements {
        bail!("item '{}': must specify either `parts` or `elements`", raw.name);
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

                let raw_line = matched_text.trim_end_matches(|c| c == '\n' || c == '\r').to_string();

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

        let min_k = if threshold <= i { i - threshold } else { 0 };
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
                for e in j..k {
                    if !dirty_matched[e] {
                        events.push(CompareEvent::DirtyExtra { dirty_idx: e });
                        failed_run += 1;

                        if max_failed_items > 0 && failed_run >= max_failed_items {
                            stopped = true;
                            stop_reason = Some(format!(
                                "stopped after {} consecutive failures at clean index {}",
                                failed_run, i
                            ));
                            break;
                        }
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
        for k in j..dirty_items.len() {
            if !dirty_matched[k] {
                events.push(CompareEvent::DirtyExtra { dirty_idx: k });
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

fn print_output(
    result: &CompareResult,
    clean_items: &[ParsedItem],
    dirty_items: &[ParsedItem],
) {
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
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────

    fn make_elements() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("timestamp".into(), r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}".into());
        m.insert("level".into(), r"INFO|WARN|ERROR".into());
        m.insert("message".into(), r".+".into());
        m
    }

    fn raw_item_with_elements(name: &str, elems: Vec<&str>, joiner: Option<&str>) -> RawItem {
        RawItem {
            name: name.into(),
            parts: None,
            elements: Some(elems.into_iter().map(String::from).collect()),
            joiner: joiner.map(String::from),
            anchored: None,
            flags: None,
            ignore_elements: None,
        }
    }

    fn raw_item_with_parts(name: &str, parts: Vec<RawPart>) -> RawItem {
        RawItem {
            name: name.into(),
            parts: Some(parts),
            elements: None,
            joiner: None,
            anchored: None,
            flags: None,
            ignore_elements: None,
        }
    }

    fn simple_config() -> Config {
        let elements = make_elements();
        let raw = raw_item_with_elements("log_entry", vec!["timestamp", "level", "message"], Some(" "));
        let item = compile_item(&raw, &elements, &[]).unwrap();
        Config {
            index_threshold: 0,
            max_failed_items: 0,
            blacklist_elements: vec![],
            items: vec![item],
        }
    }

    fn make_parsed_item(name: &str, line_no: usize, raw_line: &str, sig_vals: Vec<&str>) -> ParsedItem {
        ParsedItem {
            name: name.into(),
            line_no,
            raw_line: raw_line.into(),
            element_values: HashMap::new(),
            signature: (name.into(), sig_vals.into_iter().map(String::from).collect()),
        }
    }

    fn count_events(result: &CompareResult) -> (usize, usize, usize) {
        let mut matches = 0;
        let mut mismatches = 0;
        let mut extras = 0;
        for e in &result.events {
            match e {
                CompareEvent::Match { .. } => matches += 1,
                CompareEvent::Mismatch { .. } => mismatches += 1,
                CompareEvent::DirtyExtra { .. } => extras += 1,
            }
        }
        (matches, mismatches, extras)
    }

    // ── split_lines_keepends ─────────────────────────────────────────

    #[test]
    fn split_lines_empty() {
        assert_eq!(split_lines_keepends(""), Vec::<&str>::new());
    }

    #[test]
    fn split_lines_single_no_newline() {
        assert_eq!(split_lines_keepends("hello"), vec!["hello"]);
    }

    #[test]
    fn split_lines_single_with_newline() {
        assert_eq!(split_lines_keepends("hello\n"), vec!["hello\n"]);
    }

    #[test]
    fn split_lines_multiple() {
        assert_eq!(
            split_lines_keepends("a\nb\nc\n"),
            vec!["a\n", "b\n", "c\n"]
        );
    }

    #[test]
    fn split_lines_trailing_no_newline() {
        assert_eq!(
            split_lines_keepends("a\nb\nc"),
            vec!["a\n", "b\n", "c"]
        );
    }

    // ── compile_item ─────────────────────────────────────────────────

    #[test]
    fn compile_item_with_elements_and_default_joiner() {
        let elements = make_elements();
        let raw = raw_item_with_elements("entry", vec!["level", "message"], None);
        let item = compile_item(&raw, &elements, &[]).unwrap();
        assert_eq!(item.name, "entry");
        assert!(!item.anchored);
        assert!(item.pattern.is_match("INFO something happened"));
    }

    #[test]
    fn compile_item_with_elements_and_custom_joiner() {
        let elements = make_elements();
        let raw = raw_item_with_elements("entry", vec!["level", "message"], Some(" "));
        let item = compile_item(&raw, &elements, &[]).unwrap();
        assert!(item.pattern.is_match("ERROR crash"));
        // Joiner is literal space, so "ERROR\tcrash" should not match (tab instead of space)
        assert!(!item.pattern.is_match("ERROR\tcrash"));
    }

    #[test]
    fn compile_item_with_parts() {
        let elements = make_elements();
        let parts = vec![
            RawPart { element: Some("level".into()), regex: None },
            RawPart { element: None, regex: Some(": ".into()) },
            RawPart { element: Some("message".into()), regex: None },
        ];
        let raw = raw_item_with_parts("entry", parts);
        let item = compile_item(&raw, &elements, &[]).unwrap();
        assert!(item.pattern.is_match("INFO: hello world"));
        assert!(!item.pattern.is_match("INFO hello world"));
    }

    #[test]
    fn compile_item_empty_name_rejected() {
        let elements = make_elements();
        let raw = raw_item_with_elements("", vec!["level"], None);
        assert!(compile_item(&raw, &elements, &[]).is_err());
    }

    #[test]
    fn compile_item_both_parts_and_elements_rejected() {
        let elements = make_elements();
        let raw = RawItem {
            name: "bad".into(),
            parts: Some(vec![RawPart { element: None, regex: Some("x".into()) }]),
            elements: Some(vec!["level".into()]),
            joiner: None,
            anchored: None,
            flags: None,
            ignore_elements: None,
        };
        assert!(compile_item(&raw, &elements, &[]).is_err());
    }

    #[test]
    fn compile_item_neither_parts_nor_elements_rejected() {
        let elements = make_elements();
        let raw = RawItem {
            name: "bad".into(),
            parts: None,
            elements: None,
            joiner: None,
            anchored: None,
            flags: None,
            ignore_elements: None,
        };
        assert!(compile_item(&raw, &elements, &[]).is_err());
    }

    #[test]
    fn compile_item_unknown_element_rejected() {
        let elements = make_elements();
        let raw = raw_item_with_elements("entry", vec!["nonexistent"], None);
        assert!(compile_item(&raw, &elements, &[]).is_err());
    }

    #[test]
    fn compile_item_empty_parts_rejected() {
        let elements = make_elements();
        let raw = raw_item_with_parts("entry", vec![]);
        assert!(compile_item(&raw, &elements, &[]).is_err());
    }

    #[test]
    fn compile_item_empty_elements_rejected() {
        let elements = make_elements();
        let raw = raw_item_with_elements("entry", vec![], None);
        assert!(compile_item(&raw, &elements, &[]).is_err());
    }

    #[test]
    fn compile_item_part_with_both_element_and_regex_rejected() {
        let elements = make_elements();
        let parts = vec![RawPart {
            element: Some("level".into()),
            regex: Some("x".into()),
        }];
        let raw = raw_item_with_parts("entry", parts);
        assert!(compile_item(&raw, &elements, &[]).is_err());
    }

    #[test]
    fn compile_item_part_with_neither_rejected() {
        let elements = make_elements();
        let parts = vec![RawPart { element: None, regex: None }];
        let raw = raw_item_with_parts("entry", parts);
        assert!(compile_item(&raw, &elements, &[]).is_err());
    }

    #[test]
    fn compile_item_flags_ignorecase() {
        let elements = make_elements();
        let mut raw = raw_item_with_elements("entry", vec!["level"], None);
        raw.flags = Some(FlagValue::Single("IGNORECASE".into()));
        let item = compile_item(&raw, &elements, &[]).unwrap();
        assert!(item.pattern.is_match("info"));
        assert!(item.pattern.is_match("INFO"));
    }

    #[test]
    fn compile_item_flags_list() {
        let elements = make_elements();
        let mut raw = raw_item_with_elements("entry", vec!["level"], None);
        raw.flags = Some(FlagValue::List(vec!["IGNORECASE".into(), "MULTILINE".into()]));
        let item = compile_item(&raw, &elements, &[]).unwrap();
        assert!(item.pattern.is_match("info"));
    }

    #[test]
    fn compile_item_unknown_flag_rejected() {
        let elements = make_elements();
        let mut raw = raw_item_with_elements("entry", vec!["level"], None);
        raw.flags = Some(FlagValue::Single("BADFLAG".into()));
        assert!(compile_item(&raw, &elements, &[]).is_err());
    }

    #[test]
    fn compile_item_ignore_set_merges_blacklist_and_item() {
        let elements = make_elements();
        let mut raw = raw_item_with_elements("entry", vec!["timestamp", "level"], None);
        raw.ignore_elements = Some(vec!["level".into()]);
        let item = compile_item(&raw, &elements, &["timestamp".to_string()]).unwrap();
        assert!(item.ignore_set.contains(&"timestamp".to_string()));
        assert!(item.ignore_set.contains(&"level".to_string()));
    }

    #[test]
    fn compile_item_anchored() {
        let elements = make_elements();
        let mut raw = raw_item_with_elements("entry", vec!["level"], None);
        raw.anchored = Some(true);
        let item = compile_item(&raw, &elements, &[]).unwrap();
        assert!(item.anchored);
    }

    #[test]
    fn compile_item_duplicate_element_gets_unique_groups() {
        let elements = make_elements();
        let raw = raw_item_with_elements("entry", vec!["level", "level"], None);
        let item = compile_item(&raw, &elements, &[]).unwrap();
        assert_eq!(item.capture_elements.len(), 2);
        assert_ne!(item.capture_elements[0].1, item.capture_elements[1].1);
    }

    // ── Config TOML parsing ──────────────────────────────────────────

    #[test]
    fn config_toml_valid_minimal() {
        let toml_str = r#"
[elements]
level = "INFO|WARN"

[[items]]
name = "entry"
elements = ["level"]
"#;
        let raw: RawConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(raw.items.len(), 1);
        assert_eq!(raw.items[0].name, "entry");
    }

    #[test]
    fn config_toml_with_general() {
        let toml_str = r#"
[general]
index_threshold = 5
max_failed_items = 3
blacklist_elements = ["timestamp"]

[elements]
level = "INFO"

[[items]]
name = "entry"
elements = ["level"]
"#;
        let raw: RawConfig = toml::from_str(toml_str).unwrap();
        let general = raw.general.unwrap();
        assert_eq!(general.index_threshold, Some(5));
        assert_eq!(general.max_failed_items, Some(3));
        assert_eq!(general.blacklist_elements.unwrap(), vec!["timestamp"]);
    }

    #[test]
    fn config_toml_with_parts() {
        let toml_str = r#"
[elements]
level = "INFO|WARN"

[[items]]
name = "entry"
[[items.parts]]
element = "level"
[[items.parts]]
regex = ": "
"#;
        let raw: RawConfig = toml::from_str(toml_str).unwrap();
        assert!(raw.items[0].parts.is_some());
        assert_eq!(raw.items[0].parts.as_ref().unwrap().len(), 2);
    }

    // ── parse_log ────────────────────────────────────────────────────

    #[test]
    fn parse_log_empty_content() {
        let config = simple_config();
        let (items, unparsed) = parse_log("", &config);
        assert!(items.is_empty());
        assert!(unparsed.is_empty());
    }

    #[test]
    fn parse_log_single_matching_line() {
        let config = simple_config();
        let (items, unparsed) = parse_log("2024-01-01 10:00:00 INFO hello\n", &config);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "log_entry");
        assert_eq!(items[0].line_no, 1);
        assert_eq!(items[0].raw_line, "2024-01-01 10:00:00 INFO hello");
        assert!(unparsed.is_empty());
    }

    #[test]
    fn parse_log_multiple_lines() {
        let config = simple_config();
        let content = "2024-01-01 10:00:00 INFO first\n2024-01-01 10:00:01 WARN second\n";
        let (items, unparsed) = parse_log(content, &config);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].line_no, 1);
        assert_eq!(items[1].line_no, 2);
        assert!(unparsed.is_empty());
    }

    #[test]
    fn parse_log_unparsed_lines() {
        let config = simple_config();
        let content = "garbage line\n2024-01-01 10:00:00 INFO valid\nmore garbage\n";
        let (items, unparsed) = parse_log(content, &config);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].line_no, 2);
        assert_eq!(unparsed, vec![1, 3]);
    }

    #[test]
    fn parse_log_signature_includes_all_elements() {
        let config = simple_config();
        let (items, _) = parse_log("2024-01-01 10:00:00 INFO hello\n", &config);
        let (ref name, ref vals) = items[0].signature;
        assert_eq!(name, "log_entry");
        assert_eq!(vals.len(), 3); // timestamp, level, message
    }

    #[test]
    fn parse_log_signature_excludes_ignored_elements() {
        let elements = make_elements();
        let mut raw = raw_item_with_elements("entry", vec!["timestamp", "level", "message"], Some(" "));
        raw.ignore_elements = Some(vec!["timestamp".into()]);
        let item = compile_item(&raw, &elements, &[]).unwrap();
        let config = Config {
            index_threshold: 0,
            max_failed_items: 0,
            blacklist_elements: vec![],
            items: vec![item],
        };
        let (items, _) = parse_log("2024-01-01 10:00:00 INFO hello\n", &config);
        let (_, ref vals) = items[0].signature;
        assert_eq!(vals.len(), 2); // level, message only
        assert_eq!(vals[0], "INFO");
    }

    #[test]
    fn parse_log_element_values_populated() {
        let config = simple_config();
        let (items, _) = parse_log("2024-01-01 10:00:00 ERROR boom\n", &config);
        assert_eq!(
            items[0].element_values.get("level").unwrap(),
            &vec!["ERROR".to_string()]
        );
    }

    #[test]
    fn parse_log_first_pattern_wins() {
        let elements = make_elements();
        let raw1 = raw_item_with_elements("first", vec!["level", "message"], Some(" "));
        let raw2 = raw_item_with_elements("second", vec!["level", "message"], Some(" "));
        let item1 = compile_item(&raw1, &elements, &[]).unwrap();
        let item2 = compile_item(&raw2, &elements, &[]).unwrap();
        let config = Config {
            index_threshold: 0,
            max_failed_items: 0,
            blacklist_elements: vec![],
            items: vec![item1, item2],
        };
        let (items, _) = parse_log("INFO hello\n", &config);
        assert_eq!(items[0].name, "first");
    }

    #[test]
    fn parse_log_no_trailing_newline() {
        let config = simple_config();
        let (items, _) = parse_log("2024-01-01 10:00:00 INFO hello", &config);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].raw_line, "2024-01-01 10:00:00 INFO hello");
    }

    // ── compare ──────────────────────────────────────────────────────

    #[test]
    fn compare_empty_inputs() {
        let result = compare(&[], &[], 0, 0);
        assert!(result.events.is_empty());
        assert!(!result.stopped);
    }

    #[test]
    fn compare_identical_items() {
        let items: Vec<ParsedItem> = (0..3)
            .map(|i| make_parsed_item("entry", i + 1, &format!("line {}", i), vec!["A"]))
            .collect();
        let result = compare(&items, &items, 0, 0);
        let (m, mm, ex) = count_events(&result);
        assert_eq!(m, 3);
        assert_eq!(mm, 0);
        assert_eq!(ex, 0);
        assert!(!result.stopped);
    }

    #[test]
    fn compare_all_different() {
        let clean = vec![make_parsed_item("entry", 1, "a", vec!["A"])];
        let dirty = vec![make_parsed_item("entry", 1, "b", vec!["B"])];
        let result = compare(&clean, &dirty, 0, 0);
        let (m, mm, ex) = count_events(&result);
        assert_eq!(m, 0);
        assert_eq!(mm, 1);
        assert_eq!(ex, 1); // dirty[0] becomes trailing extra
    }

    #[test]
    fn compare_dirty_has_extra_items() {
        let clean = vec![make_parsed_item("e", 1, "a", vec!["A"])];
        let dirty = vec![
            make_parsed_item("e", 1, "a", vec!["A"]),
            make_parsed_item("e", 2, "b", vec!["B"]),
        ];
        let result = compare(&clean, &dirty, 0, 0);
        let (m, _, ex) = count_events(&result);
        assert_eq!(m, 1);
        assert_eq!(ex, 1);
    }

    #[test]
    fn compare_clean_has_more_items() {
        let clean = vec![
            make_parsed_item("e", 1, "a", vec!["A"]),
            make_parsed_item("e", 2, "b", vec!["B"]),
        ];
        let dirty = vec![make_parsed_item("e", 1, "a", vec!["A"])];
        let result = compare(&clean, &dirty, 0, 0);
        let (m, mm, _) = count_events(&result);
        assert_eq!(m, 1);
        assert_eq!(mm, 1); // second clean item has no candidate
    }

    #[test]
    fn compare_threshold_allows_offset_match() {
        let clean = vec![
            make_parsed_item("e", 1, "a", vec!["A"]),
            make_parsed_item("e", 2, "b", vec!["B"]),
        ];
        let dirty = vec![
            make_parsed_item("e", 1, "x", vec!["X"]),
            make_parsed_item("e", 2, "a", vec!["A"]),
            make_parsed_item("e", 3, "b", vec!["B"]),
        ];
        let result = compare(&clean, &dirty, 1, 0);
        let (m, mm, ex) = count_events(&result);
        assert_eq!(m, 2);
        assert_eq!(mm, 0);
        assert_eq!(ex, 1); // dirty[0] "X" is an extra
    }

    #[test]
    fn compare_threshold_zero_strict() {
        let clean = vec![
            make_parsed_item("e", 1, "a", vec!["A"]),
            make_parsed_item("e", 2, "b", vec!["B"]),
        ];
        // Dirty has them swapped
        let dirty = vec![
            make_parsed_item("e", 1, "b", vec!["B"]),
            make_parsed_item("e", 2, "a", vec!["A"]),
        ];
        let result = compare(&clean, &dirty, 0, 0);
        let (m, mm, _) = count_events(&result);
        // With threshold=0 each clean[i] can only look at dirty[i], no match
        assert_eq!(m, 0);
        assert_eq!(mm, 2);
    }

    #[test]
    fn compare_early_stop() {
        let clean: Vec<ParsedItem> = (0..5)
            .map(|i| make_parsed_item("e", i + 1, &format!("c{}", i), vec![&format!("C{}", i)]))
            .collect();
        let dirty: Vec<ParsedItem> = (0..5)
            .map(|i| make_parsed_item("e", i + 1, &format!("d{}", i), vec![&format!("D{}", i)]))
            .collect();
        let result = compare(&clean, &dirty, 0, 2);
        assert!(result.stopped);
        assert!(result.stop_reason.is_some());
        // Should stop after 2 consecutive failures, not process all 5
        let (m, mm, _) = count_events(&result);
        assert_eq!(m, 0);
        assert_eq!(mm, 2);
    }

    #[test]
    fn compare_early_stop_disabled_with_zero() {
        let clean = vec![
            make_parsed_item("e", 1, "a", vec!["A"]),
            make_parsed_item("e", 2, "b", vec!["B"]),
            make_parsed_item("e", 3, "c", vec!["C"]),
        ];
        let dirty = vec![
            make_parsed_item("e", 1, "x", vec!["X"]),
            make_parsed_item("e", 2, "y", vec!["Y"]),
            make_parsed_item("e", 3, "z", vec!["Z"]),
        ];
        let result = compare(&clean, &dirty, 0, 0);
        assert!(!result.stopped);
        let (_, mm, _) = count_events(&result);
        assert_eq!(mm, 3); // all processed
    }

    #[test]
    fn compare_failed_run_resets_on_match() {
        // With threshold=0, a mismatch at clean[1] leaves dirty[1] unmatched.
        // When clean[2] matches dirty[2], dirty[1] is recorded as an extra first
        // (incrementing failed_run), then the match resets it. Use max_failed=10
        // so the intermediate extras don't trigger early stop.
        let clean = vec![
            make_parsed_item("e", 1, "a", vec!["A"]),
            make_parsed_item("e", 2, "b", vec!["B"]),
            make_parsed_item("e", 3, "c", vec!["C"]),
            make_parsed_item("e", 4, "d", vec!["D"]),
        ];
        let dirty = vec![
            make_parsed_item("e", 1, "a", vec!["A"]),   // match for clean[0], reset
            make_parsed_item("e", 2, "x", vec!["X"]),   // mismatch for clean[1], fail=1
            make_parsed_item("e", 3, "c", vec!["C"]),   // extra(dirty[1]) fail=2, then match clean[2], reset
            make_parsed_item("e", 4, "d", vec!["D"]),   // match for clean[3]
        ];
        let result = compare(&clean, &dirty, 0, 10);
        assert!(!result.stopped);
        let (m, mm, ex) = count_events(&result);
        assert_eq!(m, 3);
        assert_eq!(mm, 1);
        assert_eq!(ex, 1);
    }

    #[test]
    fn compare_dirty_extras_before_match() {
        let clean = vec![make_parsed_item("e", 1, "b", vec!["B"])];
        let dirty = vec![
            make_parsed_item("e", 1, "x", vec!["X"]),
            make_parsed_item("e", 2, "b", vec!["B"]),
        ];
        let result = compare(&clean, &dirty, 1, 0);
        let (m, _, ex) = count_events(&result);
        assert_eq!(m, 1);
        assert_eq!(ex, 1); // dirty[0] is extra
    }

    #[test]
    fn compare_mismatch_reason_no_candidate() {
        let clean = vec![
            make_parsed_item("e", 1, "a", vec!["A"]),
            make_parsed_item("e", 2, "b", vec!["B"]),
        ];
        let dirty = vec![]; // no dirty items at all
        let result = compare(&clean, &dirty, 0, 0);
        let (_, mm, _) = count_events(&result);
        assert_eq!(mm, 2);
        if let CompareEvent::Mismatch { reason, .. } = &result.events[0] {
            assert!(reason.contains("no candidate"));
        } else {
            panic!("expected mismatch event");
        }
    }

    #[test]
    fn compare_mismatch_reason_no_match_within_window() {
        let clean = vec![make_parsed_item("e", 1, "a", vec!["A"])];
        let dirty = vec![make_parsed_item("e", 1, "b", vec!["B"])];
        let result = compare(&clean, &dirty, 0, 0);
        if let CompareEvent::Mismatch { reason, .. } = &result.events[0] {
            assert!(reason.contains("no match within window"));
        } else {
            panic!("expected mismatch event");
        }
    }

    // ── Integration: parse + compare ─────────────────────────────────

    #[test]
    fn integration_identical_logs() {
        let config = simple_config();
        let log = "2024-01-01 10:00:00 INFO start\n2024-01-01 10:00:01 INFO end\n";
        let (clean, _) = parse_log(log, &config);
        let (dirty, _) = parse_log(log, &config);
        let result = compare(&clean, &dirty, 0, 0);
        let (m, mm, ex) = count_events(&result);
        assert_eq!(m, 2);
        assert_eq!(mm, 0);
        assert_eq!(ex, 0);
    }

    #[test]
    fn integration_divergence_at_third_line() {
        let config = simple_config();
        let clean_log = "2024-01-01 10:00:00 INFO a\n2024-01-01 10:00:01 INFO b\n2024-01-01 10:00:02 INFO c\n";
        let dirty_log = "2024-01-01 10:00:00 INFO a\n2024-01-01 10:00:01 INFO b\n2024-01-01 10:00:02 ERROR x\n";
        let (clean, _) = parse_log(clean_log, &config);
        let (dirty, _) = parse_log(dirty_log, &config);
        let result = compare(&clean, &dirty, 0, 0);
        let (m, mm, _) = count_events(&result);
        assert_eq!(m, 2);
        assert_eq!(mm, 1);
    }

    #[test]
    fn integration_blacklist_ignores_timestamp() {
        let elements = make_elements();
        let raw = raw_item_with_elements("entry", vec!["timestamp", "level", "message"], Some(" "));
        let item = compile_item(&raw, &elements, &["timestamp".to_string()]).unwrap();
        let config = Config {
            index_threshold: 0,
            max_failed_items: 0,
            blacklist_elements: vec!["timestamp".into()],
            items: vec![item],
        };
        let clean_log = "2024-01-01 10:00:00 INFO hello\n";
        let dirty_log = "2099-12-31 23:59:59 INFO hello\n";
        let (clean, _) = parse_log(clean_log, &config);
        let (dirty, _) = parse_log(dirty_log, &config);
        let result = compare(&clean, &dirty, 0, 0);
        let (m, mm, _) = count_events(&result);
        assert_eq!(m, 1);
        assert_eq!(mm, 0);
    }

    #[test]
    fn integration_dirty_extra_at_start() {
        let config = simple_config();
        let clean_log = "2024-01-01 10:00:01 INFO b\n";
        let dirty_log = "2024-01-01 10:00:00 INFO a\n2024-01-01 10:00:01 INFO b\n";
        let (clean, _) = parse_log(clean_log, &config);
        let (dirty, _) = parse_log(dirty_log, &config);
        let result = compare(&clean, &dirty, 1, 0);
        let (m, _, ex) = count_events(&result);
        assert_eq!(m, 1);
        assert_eq!(ex, 1);
    }

    #[test]
    fn integration_unparsed_lines_skipped() {
        let config = simple_config();
        let log = "not a log line\n2024-01-01 10:00:00 INFO valid\nalso not a log\n";
        let (items, unparsed) = parse_log(log, &config);
        assert_eq!(items.len(), 1);
        assert_eq!(unparsed.len(), 2);
        assert_eq!(unparsed, vec![1, 3]);
    }
}
