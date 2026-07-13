//! CLI integration tests for the irregular combine mode
//! (`--irregular --combine`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const HEADER_ISO_Z: &str = r#"{ marker_regex : "^(?<timestamp>\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?Z)" }"#;
const HEADER_BRACKETED: &str = r#"{ marker_regex : "^\\[(?<timestamp>\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})\\]" }"#;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_whiplash")
}

fn tmpdir(test: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(test);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(dir: &Path, name: &str, content: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, content).unwrap();
    path
}

fn combine(dir: &Path, inputs: &[(&str, &Path)], extra: &[&str]) -> (Output, PathBuf) {
    let out_path = dir.join("case.log");
    let mut cmd = Command::new(bin());
    cmd.args(["--irregular", "--combine"]);
    for (label, path) in inputs {
        cmd.arg("--file-label").arg(label).arg(path);
    }
    cmd.arg("--output").arg(&out_path);
    cmd.args(extra);
    (cmd.output().unwrap(), out_path)
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Two well-formed inputs with interleaving timestamps and a multiline
/// record in the API log.
fn standard_inputs(dir: &Path) -> (PathBuf, PathBuf) {
    let api = write(
        dir,
        "api.log",
        &format!(
            "{HEADER_ISO_Z}\n\
             2026-07-13T09:42:01.120Z request started\n\
             continuation line one\n\
             continuation line two\n\
             2026-07-13T09:42:03.000Z request finished\n"
        ),
    );
    // Different marker shape on purpose: bracketed naive timestamps.
    let worker = write(
        dir,
        "worker.log",
        &format!(
            "{HEADER_BRACKETED}\n\
             [2026-07-13 09:42:01] job received\n\
             [2026-07-13 09:42:02] job running\n"
        ),
    );
    (api, worker)
}

// ── Combine (#14) ────────────────────────────────────────────────────

#[test]
fn combine_merges_chronologically_with_labels() {
    let dir = tmpdir("combine_basic");
    let (api, worker) = standard_inputs(&dir);
    let (output, out_path) = combine(&dir, &[("API", &api), ("WORKER", &worker)], &[]);
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));

    let combined = fs::read_to_string(out_path).unwrap();
    assert_eq!(
        combined,
        "[WORKER] [2026-07-13 09:42:01] job received\n\
         [API] 2026-07-13T09:42:01.120Z request started\n\
         continuation line one\n\
         continuation line two\n\
         [WORKER] [2026-07-13 09:42:02] job running\n\
         [API] 2026-07-13T09:42:03.000Z request finished\n"
    );
    // Metadata headers never reach the output.
    assert!(!combined.contains("marker_regex"));
}

#[test]
fn combine_equal_timestamps_keep_file_label_order() {
    let dir = tmpdir("combine_equal_ts");
    let a = write(
        &dir,
        "a.log",
        &format!("{HEADER_ISO_Z}\n2026-07-13T09:00:00Z from A one\n2026-07-13T09:00:00Z from A two\n"),
    );
    let b = write(
        &dir,
        "b.log",
        &format!("{HEADER_ISO_Z}\n2026-07-13T09:00:00Z from B\n"),
    );
    let (output, out_path) = combine(&dir, &[("A", &a), ("B", &b)], &[]);
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    assert_eq!(
        fs::read_to_string(out_path).unwrap(),
        "[A] 2026-07-13T09:00:00Z from A one\n\
         [A] 2026-07-13T09:00:00Z from A two\n\
         [B] 2026-07-13T09:00:00Z from B\n"
    );
}

#[test]
fn combine_requires_two_file_label_pairs() {
    let dir = tmpdir("combine_one_pair");
    let (api, _) = standard_inputs(&dir);
    let (output, _) = combine(&dir, &[("API", &api)], &[]);
    assert!(!output.status.success());
    assert!(stderr_of(&output).contains("at least two"));
}

#[test]
fn combine_rejects_missing_header() {
    let dir = tmpdir("combine_no_header");
    let bad = write(&dir, "bad.log", "2026-07-13T09:00:00Z no header here\n");
    let (_, worker) = standard_inputs(&dir);
    let (output, _) = combine(&dir, &[("BAD", &bad), ("WORKER", &worker)], &[]);
    assert!(!output.status.success());
    let err = stderr_of(&output);
    assert!(err.contains("bad.log"), "stderr: {err}");
    assert!(err.contains("metadata header"), "stderr: {err}");
}

#[test]
fn combine_rejects_empty_input() {
    let dir = tmpdir("combine_empty");
    let empty = write(&dir, "empty.log", "");
    let (api, _) = standard_inputs(&dir);
    let (output, _) = combine(&dir, &[("E", &empty), ("API", &api)], &[]);
    assert!(!output.status.success());
    let err = stderr_of(&output);
    assert!(err.contains("empty.log") && err.contains("empty"), "stderr: {err}");
}

#[test]
fn combine_rejects_invalid_marker_regex() {
    let dir = tmpdir("combine_bad_regex");
    let bad = write(
        &dir,
        "bad.log",
        "{ marker_regex : \"(unclosed\" }\n2026-07-13T09:00:00Z x\n",
    );
    let (api, _) = standard_inputs(&dir);
    let (output, _) = combine(&dir, &[("BAD", &bad), ("API", &api)], &[]);
    assert!(!output.status.success());
    let err = stderr_of(&output);
    assert!(err.contains("bad.log") && err.contains("marker_regex"), "stderr: {err}");
}

#[test]
fn combine_rejects_preamble_before_first_marker() {
    let dir = tmpdir("combine_preamble");
    let bad = write(
        &dir,
        "bad.log",
        &format!("{HEADER_ISO_Z}\nstray preamble line\n2026-07-13T09:00:00Z real record\n"),
    );
    let (api, _) = standard_inputs(&dir);
    let (output, _) = combine(&dir, &[("BAD", &bad), ("API", &api)], &[]);
    assert!(!output.status.success());
    let err = stderr_of(&output);
    assert!(err.contains("bad.log:2"), "stderr: {err}");
    assert!(err.contains("before the first marker"), "stderr: {err}");
}

#[test]
fn combine_rejects_unparseable_timestamp_with_location() {
    let dir = tmpdir("combine_bad_ts");
    let bad = write(
        &dir,
        "bad.log",
        "{ marker_regex : \"^(?<timestamp>\\\\S+)\" }\nnot-a-time something happened\n",
    );
    let (api, _) = standard_inputs(&dir);
    let (output, _) = combine(&dir, &[("BAD", &bad), ("API", &api)], &[]);
    assert!(!output.status.success());
    let err = stderr_of(&output);
    assert!(err.contains("bad.log:2"), "stderr: {err}");
    assert!(err.contains("not-a-time"), "stderr: {err}");
}

#[test]
fn combine_rejects_duplicate_and_invalid_labels() {
    let dir = tmpdir("combine_labels");
    let (api, worker) = standard_inputs(&dir);

    let (output, _) = combine(&dir, &[("API", &api), ("API", &worker)], &[]);
    assert!(!output.status.success());
    assert!(stderr_of(&output).contains("duplicate label"));

    let (output, _) = combine(&dir, &[("A]B", &api), ("WORKER", &worker)], &[]);
    assert!(!output.status.success());
    assert!(stderr_of(&output).contains("invalid label"));
}

#[test]
fn combine_failure_leaves_existing_output_untouched() {
    let dir = tmpdir("combine_atomic");
    let out_path = dir.join("case.log");
    fs::write(&out_path, "SENTINEL\n").unwrap();

    let bad = write(&dir, "bad.log", "no header\n");
    let (api, _) = standard_inputs(&dir);
    let (output, _) = combine(&dir, &[("BAD", &bad), ("API", &api)], &[]);
    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(&out_path).unwrap(), "SENTINEL\n");
}

#[test]
fn combine_requires_irregular_and_conflicts_with_config() {
    let dir = tmpdir("combine_flag_rules");
    let (api, worker) = standard_inputs(&dir);

    // --combine without --irregular
    let output = Command::new(bin())
        .args(["--combine", "--file-label", "A"])
        .arg(&api)
        .args(["--file-label", "B"])
        .arg(&worker)
        .arg("--output")
        .arg(dir.join("case.log"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(stderr_of(&output).contains("--irregular"));

    // --combine alongside --config
    let output = Command::new(bin())
        .args(["--irregular", "--combine", "--config", "config.toml"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(stderr_of(&output).contains("cannot be used with"));
}
