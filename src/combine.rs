//! Irregular combine mode (`--irregular --combine`): merge records from
//! multiple irregular log files into one chronological case log, without
//! parsing them into the configured item types.
//!
//! Each input file starts with a one-line metadata header:
//!
//! ```text
//! { marker_regex : "^(?<timestamp>\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?Z)" }
//! ```
//!
//! The value is a double-quoted, JSON-escaped string (`\\` for a literal
//! backslash, `\"` for a quote). A record begins at each line matching that
//! file's `marker_regex` and runs up to (not including) the next match or
//! EOF. The regex match supplies the chronological key: the named
//! `timestamp` capture when present, otherwise the complete match.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use regex::Regex;

// ── Inputs ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub(crate) struct InputSpec {
    pub label: String,
    pub path: PathBuf,
}

/// Turn the flat `--file-label LABEL PATH ...` argument list into input
/// specs, validating labels as it goes.
pub(crate) fn parse_file_labels(args: &[String]) -> Result<Vec<InputSpec>> {
    // clap enforces num_args = 2, so the list is always even.
    let pairs: Vec<InputSpec> = args
        .chunks(2)
        .map(|pair| InputSpec {
            label: pair[0].clone(),
            path: PathBuf::from(&pair[1]),
        })
        .collect();

    if pairs.len() < 2 {
        bail!("--combine requires at least two --file-label <LABEL> <PATH> pairs");
    }

    let label_re = Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$").unwrap();
    for (i, spec) in pairs.iter().enumerate() {
        if spec.label.is_empty() {
            bail!("--file-label pair {}: label must be non-empty", i + 1);
        }
        if !label_re.is_match(&spec.label) {
            bail!(
                "invalid label '{}': labels must start with an alphanumeric character and contain only alphanumerics, '_', '.', or '-'",
                spec.label
            );
        }
        if pairs[..i].iter().any(|other| other.label == spec.label) {
            bail!("duplicate label '{}'", spec.label);
        }
    }

    Ok(pairs)
}

// ── Metadata header ──────────────────────────────────────────────────

/// Parse the required first-line metadata header and return the
/// `marker_regex` pattern string.
///
/// Accepted serialization: `{ marker_regex : "<pattern>" }` — braces around
/// a single key/value pair, key `marker_regex` (double quotes around the key
/// are optional), a colon separator, and a double-quoted JSON-escaped string
/// value. Whitespace between tokens is ignored.
fn parse_metadata_header(line: &str) -> Result<String> {
    let inner = line
        .trim()
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .context("metadata header must be a braced object: { marker_regex : \"...\" }")?;

    let (key, value) = inner
        .split_once(':')
        .context("metadata header must contain `marker_regex : \"...\"`")?;

    let key = key.trim();
    let key = key.strip_prefix('"').and_then(|k| k.strip_suffix('"')).unwrap_or(key);
    if key != "marker_regex" {
        bail!("metadata header key must be `marker_regex`, got `{}`", key);
    }

    let value = value.trim();
    let quoted = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .context("marker_regex value must be a double-quoted string")?;

    unescape_json_string(quoted)
}

/// Undo JSON string escaping: `\\`, `\"`, `\/`, `\n`, `\r`, `\t`.
fn unescape_json_string(s: &str) -> Result<String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some('"') => out.push('"'),
            Some('/') => out.push('/'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some(other) => bail!("unsupported escape sequence `\\{}` in marker_regex value", other),
            None => bail!("marker_regex value ends with a dangling backslash"),
        }
    }
    Ok(out)
}

// ── Timestamps ───────────────────────────────────────────────────────

/// Parse a chronological key. Accepts RFC 3339 (`Z` or a numeric offset)
/// and the naive forms `YYYY-MM-DDTHH:MM:SS[.frac]` /
/// `YYYY-MM-DD HH:MM:SS[.frac]`, which are treated as UTC.
fn parse_timestamp(text: &str) -> Option<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(text) {
        return Some(dt.with_timezone(&Utc));
    }
    const NAIVE_FORMATS: &[&str] = &["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"];
    NAIVE_FORMATS
        .iter()
        .find_map(|fmt| NaiveDateTime::parse_from_str(text, fmt).ok())
        .map(|naive| naive.and_utc())
}

// ── Records ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub(crate) struct Record {
    timestamp: DateTime<Utc>,
    /// Index into the input specs; supplies the output label.
    source: usize,
    /// The record's lines, marker line first, without trailing newlines.
    lines: Vec<String>,
}

/// Read one input file, parse its metadata header, and split the remainder
/// into records at marker matches.
fn load_input(spec: &InputSpec, source: usize) -> Result<Vec<Record>> {
    let content = fs::read_to_string(&spec.path)
        .with_context(|| format!("failed to read input '{}'", spec.path.display()))?;

    let mut lines = content.lines().enumerate();
    let Some((_, header)) = lines.next() else {
        bail!("{}: input is empty (missing metadata header)", spec.path.display());
    };
    let pattern = parse_metadata_header(header)
        .with_context(|| format!("{}: invalid metadata header on line 1", spec.path.display()))?;
    let marker = Regex::new(&pattern)
        .with_context(|| format!("{}: invalid marker_regex", spec.path.display()))?;

    let mut records: Vec<Record> = Vec::new();
    for (idx, line) in lines {
        let line_no = idx + 1;
        if let Some(caps) = marker.captures(line) {
            let key = caps
                .name("timestamp")
                .map_or_else(|| caps.get(0).unwrap().as_str(), |m| m.as_str());
            let timestamp = parse_timestamp(key).ok_or_else(|| {
                anyhow!(
                    "{}:{}: cannot interpret timestamp key '{}'",
                    spec.path.display(),
                    line_no,
                    key
                )
            })?;
            records.push(Record {
                timestamp,
                source,
                lines: vec![line.to_string()],
            });
        } else if let Some(current) = records.last_mut() {
            current.lines.push(line.to_string());
        } else {
            bail!(
                "{}:{}: content before the first marker line is not allowed",
                spec.path.display(),
                line_no
            );
        }
    }

    if records.is_empty() {
        bail!(
            "{}: no records found (no line after the header matches marker_regex)",
            spec.path.display()
        );
    }
    Ok(records)
}

/// Load every input and merge all records by ascending timestamp. Equal
/// timestamps keep input-file order, then source-record order (stable sort
/// over per-file record lists concatenated in `--file-label` order).
pub(crate) fn merge_records(inputs: &[InputSpec]) -> Result<Vec<Record>> {
    let mut all = Vec::new();
    for (i, spec) in inputs.iter().enumerate() {
        all.extend(load_input(spec, i)?);
    }
    all.sort_by_key(|r| r.timestamp);
    Ok(all)
}

/// Render the merged records, prefixing each record's marker line with its
/// source label. Every line is newline-terminated.
pub(crate) fn render(records: &[Record], inputs: &[InputSpec]) -> String {
    let mut out = String::new();
    for record in records {
        for (i, line) in record.lines.iter().enumerate() {
            if i == 0 {
                out.push('[');
                out.push_str(&inputs[record.source].label);
                out.push_str("] ");
            }
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

// ── Output ───────────────────────────────────────────────────────────

/// Write atomically: everything goes to a sibling temp file which replaces
/// the destination only on success, so a failure never leaves a partially
/// replaced output.
pub(crate) fn write_output(path: &Path, content: &str) -> Result<()> {
    let mut tmp_name = path
        .file_name()
        .with_context(|| format!("output path '{}' has no file name", path.display()))?
        .to_os_string();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);

    let write_and_rename = || -> Result<()> {
        fs::write(&tmp, content)
            .with_context(|| format!("failed to write '{}'", tmp.display()))?;
        fs::rename(&tmp, path)
            .with_context(|| format!("failed to move output into place at '{}'", path.display()))
    };
    write_and_rename().inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
}

// ── Entry point ──────────────────────────────────────────────────────

pub(crate) fn run(cli: &crate::Cli) -> Result<()> {
    let inputs = parse_file_labels(&cli.file_label)?;
    let output = cli
        .output
        .as_ref()
        .context("--combine requires --output <PATH>")?;

    let records = merge_records(&inputs)?;
    write_output(output, &render(&records, &inputs))
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn record(ts: &str, source: usize, lines: &[&str]) -> Record {
        Record {
            timestamp: parse_timestamp(ts).unwrap(),
            source,
            lines: lines.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn specs(labels: &[&str]) -> Vec<InputSpec> {
        labels
            .iter()
            .map(|l| InputSpec {
                label: l.to_string(),
                path: PathBuf::from(format!("{l}.log")),
            })
            .collect()
    }

    // ── Metadata header ──────────────────────────────────────────────

    #[test]
    fn header_unquoted_key() {
        let pat = parse_metadata_header(r#"{ marker_regex : "^\\d+" }"#).unwrap();
        assert_eq!(pat, r"^\d+");
    }

    #[test]
    fn header_quoted_key_and_tight_spacing() {
        let pat = parse_metadata_header(r#"{"marker_regex":"^abc"}"#).unwrap();
        assert_eq!(pat, "^abc");
    }

    #[test]
    fn header_unescapes_json_sequences() {
        let pat = parse_metadata_header(r#"{ marker_regex : "a\\b\"c\td" }"#).unwrap();
        assert_eq!(pat, "a\\b\"c\td");
    }

    #[test]
    fn header_rejects_missing_braces() {
        assert!(parse_metadata_header(r#"marker_regex : "^x""#).is_err());
    }

    #[test]
    fn header_rejects_wrong_key() {
        assert!(parse_metadata_header(r#"{ marker : "^x" }"#).is_err());
    }

    #[test]
    fn header_rejects_unquoted_value() {
        assert!(parse_metadata_header(r"{ marker_regex : ^x }").is_err());
    }

    #[test]
    fn header_rejects_bad_escape() {
        assert!(parse_metadata_header(r#"{ marker_regex : "^\d+" }"#).is_err());
    }

    // ── Timestamps ───────────────────────────────────────────────────

    #[test]
    fn timestamp_rfc3339_with_fraction_and_zone() {
        let a = parse_timestamp("2026-07-13T09:42:01.120Z").unwrap();
        let b = parse_timestamp("2026-07-13T11:42:01.120+02:00").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn timestamp_naive_forms_are_utc() {
        let a = parse_timestamp("2026-07-13T09:42:01").unwrap();
        let b = parse_timestamp("2026-07-13 09:42:01").unwrap();
        let c = parse_timestamp("2026-07-13T09:42:01Z").unwrap();
        assert_eq!(a, c);
        assert_eq!(b, c);
    }

    #[test]
    fn timestamp_rejects_garbage() {
        assert!(parse_timestamp("not a time").is_none());
        assert!(parse_timestamp("2026-13-40T99:00:00Z").is_none());
    }

    // ── Labels ───────────────────────────────────────────────────────

    fn label_args(pairs: &[(&str, &str)]) -> Vec<String> {
        pairs
            .iter()
            .flat_map(|(l, p)| [l.to_string(), p.to_string()])
            .collect()
    }

    #[test]
    fn labels_valid_pairs() {
        let specs = parse_file_labels(&label_args(&[("API", "a.log"), ("db-1", "b.log")])).unwrap();
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].label, "API");
        assert_eq!(specs[1].path, PathBuf::from("b.log"));
    }

    #[test]
    fn labels_require_two_pairs() {
        let err = parse_file_labels(&label_args(&[("API", "a.log")])).unwrap_err();
        assert!(err.to_string().contains("at least two"));
    }

    #[test]
    fn labels_reject_malformed_and_duplicate() {
        assert!(parse_file_labels(&label_args(&[("A]B", "a.log"), ("C", "c.log")])).is_err());
        assert!(parse_file_labels(&label_args(&[("has space", "a.log"), ("C", "c.log")])).is_err());
        let err =
            parse_file_labels(&label_args(&[("API", "a.log"), ("API", "b.log")])).unwrap_err();
        assert!(err.to_string().contains("duplicate label"));
    }

    // ── Merge & render ───────────────────────────────────────────────

    #[test]
    fn render_prefixes_marker_line_only() {
        let inputs = specs(&["API"]);
        let recs = vec![record("2026-07-13T09:00:00Z", 0, &["first line", "  continuation"])];
        assert_eq!(render(&recs, &inputs), "[API] first line\n  continuation\n");
    }

    #[test]
    fn equal_timestamps_keep_stable_order() {
        let inputs = specs(&["A", "B"]);
        let mut recs = vec![
            record("2026-07-13T09:00:00Z", 0, &["a1"]),
            record("2026-07-13T09:00:00Z", 0, &["a2"]),
            record("2026-07-13T09:00:00Z", 1, &["b1"]),
        ];
        recs.sort_by_key(|r| r.timestamp);
        assert_eq!(render(&recs, &inputs), "[A] a1\n[A] a2\n[B] b1\n");
    }

}
