use super::*;

// ── Helpers ──────────────────────────────────────────────────────────

fn make_atoms() -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert(
        "timestamp".into(),
        r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}".into(),
    );
    m.insert("level".into(), r"INFO|WARN|ERROR".into());
    m.insert("message".into(), r".+".into());
    m
}

fn raw_item_with_parts(name: &str, parts: Vec<RawPart>) -> RawItem {
    RawItem {
        name: name.into(),
        parts: Some(parts),
        anchored: None,
        flags: None,
        ignore_atoms: None,
    }
}

/// Build parts from atom names with a regex joiner between them.
fn atom_parts(atom_names: &[&str], joiner: Option<&str>) -> Vec<RawPart> {
    let joiner = joiner.unwrap_or(".*?");
    let mut parts = Vec::new();
    for (i, name) in atom_names.iter().enumerate() {
        if i > 0 {
            parts.push(RawPart {
                atom: None,
                regex: Some(joiner.into()),
                ..Default::default()
            });
        }
        parts.push(RawPart {
            atom: Some((*name).into()),
            regex: None,
            ..Default::default()
        });
    }
    parts
}

fn simple_config() -> Config {
    let atoms = make_atoms();
    let parts = atom_parts(&["timestamp", "level", "message"], Some(" "));
    let raw = raw_item_with_parts("log_entry", parts);
    let item = compile_item(&raw, &atoms, &[]).unwrap();
    Config {
        index_threshold: 0,
        max_failed_items: 0,
        blacklist_atoms: vec![],
        items: vec![item],
    }
}

fn make_parsed_item(name: &str, line_no: usize, raw_line: &str, sig_vals: Vec<&str>) -> ParsedItem {
    ParsedItem {
        line_no,
        raw_line: raw_line.into(),
        atom_values: HashMap::new(),
        signature: (
            name.into(),
            sig_vals.into_iter().map(String::from).collect(),
        ),
    }
}

fn count_events(result: &CompareResult) -> (usize, usize, usize) {
    let mut matches = 0;
    let mut extras = 0;
    let mut missing = 0;
    for e in &result.events {
        match e {
            CompareEvent::Match { .. } => matches += 1,
            CompareEvent::Extra { .. } => extras += 1,
            CompareEvent::Missing { .. } => missing += 1,
        }
    }
    (matches, extras, missing)
}

// ── split_lines_keepends ─────────────────────────────────────────────

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
    assert_eq!(split_lines_keepends("a\nb\nc\n"), vec!["a\n", "b\n", "c\n"]);
}

#[test]
fn split_lines_trailing_no_newline() {
    assert_eq!(split_lines_keepends("a\nb\nc"), vec!["a\n", "b\n", "c"]);
}

// ── compile_item ─────────────────────────────────────────────────────

#[test]
fn compile_item_with_parts_atom_and_regex() {
    let atoms = make_atoms();
    let parts = vec![
        RawPart {
            atom: Some("level".into()),
            regex: None,
            ..Default::default()
        },
        RawPart {
            atom: None,
            regex: Some(": ".into()),
            ..Default::default()
        },
        RawPart {
            atom: Some("message".into()),
            regex: None,
            ..Default::default()
        },
    ];
    let raw = raw_item_with_parts("entry", parts);
    let item = compile_item(&raw, &atoms, &[]).unwrap();
    assert!(item.pattern.is_match("INFO: hello world"));
    assert!(!item.pattern.is_match("INFO hello world"));
}

#[test]
fn compile_item_with_wildcard_regex_between_atoms() {
    let atoms = make_atoms();
    let parts = atom_parts(&["level", "message"], None);
    let raw = raw_item_with_parts("entry", parts);
    let item = compile_item(&raw, &atoms, &[]).unwrap();
    assert_eq!(item.name, "entry");
    assert!(!item.anchored);
    assert!(item.pattern.is_match("INFO something happened"));
}

#[test]
fn compile_item_with_space_regex_between_atoms() {
    let atoms = make_atoms();
    let parts = atom_parts(&["level", "message"], Some(" "));
    let raw = raw_item_with_parts("entry", parts);
    let item = compile_item(&raw, &atoms, &[]).unwrap();
    assert!(item.pattern.is_match("ERROR crash"));
    // Joiner is literal space, so "ERROR\tcrash" should not match (tab instead of space)
    assert!(!item.pattern.is_match("ERROR\tcrash"));
}

#[test]
fn compile_item_empty_name_rejected() {
    let atoms = make_atoms();
    let parts = atom_parts(&["level"], None);
    let raw = raw_item_with_parts("", parts);
    assert!(compile_item(&raw, &atoms, &[]).is_err());
}

#[test]
fn compile_item_no_parts_rejected() {
    let atoms = make_atoms();
    let raw = RawItem {
        name: "bad".into(),
        parts: None,
        anchored: None,
        flags: None,
        ignore_atoms: None,
    };
    assert!(compile_item(&raw, &atoms, &[]).is_err());
}

#[test]
fn compile_item_unknown_atom_in_part_rejected() {
    let atoms = make_atoms();
    let parts = vec![RawPart {
        atom: Some("nonexistent".into()),
        regex: None,
        ..Default::default()
    }];
    let raw = raw_item_with_parts("entry", parts);
    assert!(compile_item(&raw, &atoms, &[]).is_err());
}

#[test]
fn compile_item_empty_parts_rejected() {
    let atoms = make_atoms();
    let raw = raw_item_with_parts("entry", vec![]);
    assert!(compile_item(&raw, &atoms, &[]).is_err());
}

#[test]
fn compile_item_part_with_both_atom_and_regex_rejected() {
    let atoms = make_atoms();
    let parts = vec![RawPart {
        atom: Some("level".into()),
        regex: Some("x".into()),
        ..Default::default()
    }];
    let raw = raw_item_with_parts("entry", parts);
    assert!(compile_item(&raw, &atoms, &[]).is_err());
}

#[test]
fn compile_item_part_with_neither_rejected() {
    let atoms = make_atoms();
    let parts = vec![RawPart {
        atom: None,
        regex: None,
        ..Default::default()
    }];
    let raw = raw_item_with_parts("entry", parts);
    assert!(compile_item(&raw, &atoms, &[]).is_err());
}

#[test]
fn compile_item_flags_ignorecase() {
    let atoms = make_atoms();
    let parts = atom_parts(&["level"], None);
    let mut raw = raw_item_with_parts("entry", parts);
    raw.flags = Some(FlagValue::Single("IGNORECASE".into()));
    let item = compile_item(&raw, &atoms, &[]).unwrap();
    assert!(item.pattern.is_match("info"));
    assert!(item.pattern.is_match("INFO"));
}

#[test]
fn compile_item_flags_list() {
    let atoms = make_atoms();
    let parts = atom_parts(&["level"], None);
    let mut raw = raw_item_with_parts("entry", parts);
    raw.flags = Some(FlagValue::List(vec![
        "IGNORECASE".into(),
        "MULTILINE".into(),
    ]));
    let item = compile_item(&raw, &atoms, &[]).unwrap();
    assert!(item.pattern.is_match("info"));
}

#[test]
fn compile_item_unknown_flag_rejected() {
    let atoms = make_atoms();
    let parts = atom_parts(&["level"], None);
    let mut raw = raw_item_with_parts("entry", parts);
    raw.flags = Some(FlagValue::Single("BADFLAG".into()));
    assert!(compile_item(&raw, &atoms, &[]).is_err());
}

#[test]
fn compile_item_ignore_set_merges_blacklist_and_item() {
    let atoms = make_atoms();
    let parts = atom_parts(&["timestamp", "level"], Some(" "));
    let mut raw = raw_item_with_parts("entry", parts);
    raw.ignore_atoms = Some(vec!["level".into()]);
    let item = compile_item(&raw, &atoms, &["timestamp".to_string()]).unwrap();
    assert!(item.ignore_set.contains(&"timestamp".to_string()));
    assert!(item.ignore_set.contains(&"level".to_string()));
}

#[test]
fn compile_item_anchored() {
    let atoms = make_atoms();
    let parts = atom_parts(&["level"], None);
    let mut raw = raw_item_with_parts("entry", parts);
    raw.anchored = Some(true);
    let item = compile_item(&raw, &atoms, &[]).unwrap();
    assert!(item.anchored);
}

#[test]
fn compile_item_duplicate_atom_gets_unique_groups() {
    let atoms = make_atoms();
    let parts = atom_parts(&["level", "level"], Some(" "));
    let raw = raw_item_with_parts("entry", parts);
    let item = compile_item(&raw, &atoms, &[]).unwrap();
    assert_eq!(item.capture_atoms.len(), 2);
    assert_ne!(item.capture_atoms[0].1, item.capture_atoms[1].1);
}

// ── Config TOML parsing ──────────────────────────────────────────────

#[test]
fn config_toml_valid_minimal_with_parts() {
    let toml_str = r#"
[atoms]
level = "INFO|WARN"

[[items]]
name = "entry"
[[items.parts]]
atom = "level"
"#;
    let raw: RawConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(raw.items.len(), 1);
    assert_eq!(raw.items[0].name, "entry");
    assert!(raw.items[0].parts.is_some());
    assert_eq!(raw.items[0].parts.as_ref().unwrap().len(), 1);
}

#[test]
fn config_toml_with_general() {
    let toml_str = r#"
[general]
index_threshold = 5
max_failed_items = 3
blacklist_atoms = ["timestamp"]

[atoms]
level = "INFO"

[[items]]
name = "entry"
[[items.parts]]
atom = "level"
"#;
    let raw: RawConfig = toml::from_str(toml_str).unwrap();
    let general = raw.general.unwrap();
    assert_eq!(general.index_threshold, Some(5));
    assert_eq!(general.max_failed_items, Some(3));
    assert_eq!(general.blacklist_atoms.unwrap(), vec!["timestamp"]);
}

#[test]
fn config_toml_with_parts_atom_and_regex() {
    let toml_str = r#"
[atoms]
level = "INFO|WARN"

[[items]]
name = "entry"
[[items.parts]]
atom = "level"
[[items.parts]]
regex = ": "
"#;
    let raw: RawConfig = toml::from_str(toml_str).unwrap();
    assert!(raw.items[0].parts.is_some());
    let parts = raw.items[0].parts.as_ref().unwrap();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].atom.as_deref(), Some("level"));
    assert_eq!(parts[1].regex.as_deref(), Some(": "));
}

// ── parse_log ────────────────────────────────────────────────────────

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
fn parse_log_signature_includes_all_atoms() {
    let config = simple_config();
    let (items, _) = parse_log("2024-01-01 10:00:00 INFO hello\n", &config);
    let (ref name, ref vals) = items[0].signature;
    assert_eq!(name, "log_entry");
    assert_eq!(vals.len(), 3); // timestamp, level, message
}

#[test]
fn parse_log_signature_excludes_ignored_atoms() {
    let atoms = make_atoms();
    let parts = atom_parts(&["timestamp", "level", "message"], Some(" "));
    let mut raw = raw_item_with_parts("entry", parts);
    raw.ignore_atoms = Some(vec!["timestamp".into()]);
    let item = compile_item(&raw, &atoms, &[]).unwrap();
    let config = Config {
        index_threshold: 0,
        max_failed_items: 0,
        blacklist_atoms: vec![],
        items: vec![item],
    };
    let (items, _) = parse_log("2024-01-01 10:00:00 INFO hello\n", &config);
    let (_, ref vals) = items[0].signature;
    assert_eq!(vals.len(), 2); // level, message only
    assert_eq!(vals[0], "INFO");
}

#[test]
fn parse_log_atom_values_populated() {
    let config = simple_config();
    let (items, _) = parse_log("2024-01-01 10:00:00 ERROR boom\n", &config);
    assert_eq!(
        items[0].atom_values.get("level").unwrap(),
        &vec!["ERROR".to_string()]
    );
}

#[test]
fn parse_log_no_trailing_newline() {
    let config = simple_config();
    let (items, _) = parse_log("2024-01-01 10:00:00 INFO hello", &config);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].raw_line, "2024-01-01 10:00:00 INFO hello");
}

// ── compare ──────────────────────────────────────────────────────────

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
    let (m, ex, mi) = count_events(&result);
    assert_eq!(m, 3);
    assert_eq!(ex, 0);
    assert_eq!(mi, 0);
    assert!(!result.stopped);
}

#[test]
fn compare_all_different() {
    let clean = vec![make_parsed_item("entry", 1, "a", vec!["A"])];
    let dirty = vec![make_parsed_item("entry", 1, "b", vec!["B"])];
    let result = compare(&clean, &dirty, 0, 0);
    let (m, ex, mi) = count_events(&result);
    assert_eq!(m, 0);
    assert_eq!(ex, 1); // dirty[0] is extra
    assert_eq!(mi, 1); // clean[0] is missing
}

#[test]
fn compare_dirty_has_extra_items() {
    let clean = vec![make_parsed_item("e", 1, "a", vec!["A"])];
    let dirty = vec![
        make_parsed_item("e", 1, "a", vec!["A"]),
        make_parsed_item("e", 2, "b", vec!["B"]),
    ];
    let result = compare(&clean, &dirty, 0, 0);
    let (m, ex, mi) = count_events(&result);
    assert_eq!(m, 1);
    assert_eq!(ex, 1);
    assert_eq!(mi, 0);
}

#[test]
fn compare_clean_has_more_items() {
    let clean = vec![
        make_parsed_item("e", 1, "a", vec!["A"]),
        make_parsed_item("e", 2, "b", vec!["B"]),
    ];
    let dirty = vec![make_parsed_item("e", 1, "a", vec!["A"])];
    let result = compare(&clean, &dirty, 0, 0);
    let (m, ex, mi) = count_events(&result);
    assert_eq!(m, 1);
    assert_eq!(ex, 0);
    assert_eq!(mi, 1); // second clean item is missing
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
    let (m, ex, mi) = count_events(&result);
    assert_eq!(m, 2);
    assert_eq!(ex, 1); // dirty[0] "X" is an extra
    assert_eq!(mi, 0);
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
    let (m, ex, mi) = count_events(&result);
    // With threshold=0 each dirty[i] can only look at clean[i], no match
    assert_eq!(m, 0);
    assert_eq!(ex, 2);
    assert_eq!(mi, 2);
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
    // Should stop after 2 consecutive dirty extras, not process all 5
    let (m, ex, mi) = count_events(&result);
    assert_eq!(m, 0);
    assert_eq!(ex, 2);
    assert_eq!(mi, 0); // no missing appended when stopped
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
    let (_, ex, mi) = count_events(&result);
    assert_eq!(ex, 3); // all dirty processed as extras
    assert_eq!(mi, 3); // all clean are missing
}

#[test]
fn compare_failed_run_resets_on_match() {
    let clean = vec![
        make_parsed_item("e", 1, "a", vec!["A"]),
        make_parsed_item("e", 2, "b", vec!["B"]),
        make_parsed_item("e", 3, "c", vec!["C"]),
        make_parsed_item("e", 4, "d", vec!["D"]),
    ];
    let dirty = vec![
        make_parsed_item("e", 1, "a", vec!["A"]), // matches clean[0], reset
        make_parsed_item("e", 2, "x", vec!["X"]), // extra, fail=1
        make_parsed_item("e", 3, "c", vec!["C"]), // matches clean[2], reset
        make_parsed_item("e", 4, "d", vec!["D"]), // matches clean[3]
    ];
    let result = compare(&clean, &dirty, 0, 10);
    assert!(!result.stopped);
    let (m, ex, mi) = count_events(&result);
    assert_eq!(m, 3);
    assert_eq!(ex, 1);
    assert_eq!(mi, 1); // clean[1] "B" is missing
}

#[test]
fn compare_dirty_extras_before_match() {
    let clean = vec![make_parsed_item("e", 1, "b", vec!["B"])];
    let dirty = vec![
        make_parsed_item("e", 1, "x", vec!["X"]),
        make_parsed_item("e", 2, "b", vec!["B"]),
    ];
    let result = compare(&clean, &dirty, 1, 0);
    let (m, ex, mi) = count_events(&result);
    assert_eq!(m, 1);
    assert_eq!(ex, 1); // dirty[0] is extra
    assert_eq!(mi, 0);
}

#[test]
fn compare_dirty_empty() {
    let clean = vec![
        make_parsed_item("e", 1, "a", vec!["A"]),
        make_parsed_item("e", 2, "b", vec!["B"]),
    ];
    let dirty = vec![]; // no dirty items at all
    let result = compare(&clean, &dirty, 0, 0);
    let (m, ex, mi) = count_events(&result);
    assert_eq!(m, 0);
    assert_eq!(ex, 0);
    assert_eq!(mi, 2);
}

#[test]
fn compare_threshold_handles_swap() {
    let clean = vec![
        make_parsed_item("e", 1, "a", vec!["A"]),
        make_parsed_item("e", 2, "b", vec!["B"]),
    ];
    let dirty = vec![
        make_parsed_item("e", 1, "b", vec!["B"]),
        make_parsed_item("e", 2, "a", vec!["A"]),
    ];
    let result = compare(&clean, &dirty, 1, 0);
    let (m, ex, mi) = count_events(&result);
    assert_eq!(m, 2);
    assert_eq!(ex, 0);
    assert_eq!(mi, 0);
}

// ── Integration: parse + compare ─────────────────────────────────────

#[test]
fn integration_identical_logs() {
    let config = simple_config();
    let log = "2024-01-01 10:00:00 INFO start\n2024-01-01 10:00:01 INFO end\n";
    let (clean, _) = parse_log(log, &config);
    let (dirty, _) = parse_log(log, &config);
    let result = compare(&clean, &dirty, 0, 0);
    let (m, ex, mi) = count_events(&result);
    assert_eq!(m, 2);
    assert_eq!(ex, 0);
    assert_eq!(mi, 0);
}

#[test]
fn integration_divergence_at_third_line() {
    let config = simple_config();
    let clean_log =
        "2024-01-01 10:00:00 INFO a\n2024-01-01 10:00:01 INFO b\n2024-01-01 10:00:02 INFO c\n";
    let dirty_log =
        "2024-01-01 10:00:00 INFO a\n2024-01-01 10:00:01 INFO b\n2024-01-01 10:00:02 ERROR x\n";
    let (clean, _) = parse_log(clean_log, &config);
    let (dirty, _) = parse_log(dirty_log, &config);
    let result = compare(&clean, &dirty, 0, 0);
    let (m, ex, mi) = count_events(&result);
    assert_eq!(m, 2);
    assert_eq!(ex, 1); // dirty[2] is extra
    assert_eq!(mi, 1); // clean[2] is missing
}

#[test]
fn integration_blacklist_ignores_timestamp() {
    let atoms = make_atoms();
    let parts = atom_parts(&["timestamp", "level", "message"], Some(" "));
    let raw = raw_item_with_parts("entry", parts);
    let item = compile_item(&raw, &atoms, &["timestamp".to_string()]).unwrap();
    let config = Config {
        index_threshold: 0,
        max_failed_items: 0,
        blacklist_atoms: vec!["timestamp".into()],
        items: vec![item],
    };
    let clean_log = "2024-01-01 10:00:00 INFO hello\n";
    let dirty_log = "2099-12-31 23:59:59 INFO hello\n";
    let (clean, _) = parse_log(clean_log, &config);
    let (dirty, _) = parse_log(dirty_log, &config);
    let result = compare(&clean, &dirty, 0, 0);
    let (m, ex, mi) = count_events(&result);
    assert_eq!(m, 1);
    assert_eq!(ex, 0);
    assert_eq!(mi, 0);
}

#[test]
fn integration_dirty_extra_at_start() {
    let config = simple_config();
    let clean_log = "2024-01-01 10:00:01 INFO b\n";
    let dirty_log = "2024-01-01 10:00:00 INFO a\n2024-01-01 10:00:01 INFO b\n";
    let (clean, _) = parse_log(clean_log, &config);
    let (dirty, _) = parse_log(dirty_log, &config);
    let result = compare(&clean, &dirty, 1, 0);
    let (m, ex, mi) = count_events(&result);
    assert_eq!(m, 1);
    assert_eq!(ex, 1);
    assert_eq!(mi, 0);
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

// ── clean_log_content ────────────────────────────────────────────────

#[test]
fn clean_log_literal_backslash_n() {
    // Literal \n (two chars: backslash + n) replaced with actual newline
    let input = "hello\\nworld";
    let output = clean_log_content(input);
    assert_eq!(output, "hello\nworld");
}

#[test]
fn clean_log_literal_backslash_r_backslash_n() {
    // Literal \r\n (four chars) replaced with actual newline
    let input = "hello\\r\\nworld";
    let output = clean_log_content(input);
    assert_eq!(output, "hello\nworld");
}

#[test]
fn clean_log_no_double_newline() {
    // Literal \n followed by actual newline should not produce double newline
    let input = "hello\\n\nworld";
    let output = clean_log_content(input);
    assert_eq!(output, "hello\nworld");
}

#[test]
fn clean_log_crlf_no_double_newline() {
    // Literal \r\n followed by actual newline should not produce double newline
    let input = "hello\\r\\n\nworld";
    let output = clean_log_content(input);
    assert_eq!(output, "hello\nworld");
}

#[test]
fn clean_log_no_false_positives() {
    // Regular backslashes not followed by n should be preserved
    let input = "path\\to\\file\n";
    let output = clean_log_content(input);
    assert_eq!(output, "path\\to\\file\n");
}

#[test]
fn clean_log_empty() {
    assert_eq!(clean_log_content(""), "");
}

// ── validate ─────────────────────────────────────────────────────────

#[test]
fn validate_single_match() {
    let config = simple_config();
    let log = "2024-01-01 10:00:00 INFO hello world\n";
    let result = validate(log.as_bytes(), &config).unwrap();
    assert!(result.error.is_none());
    assert!(result.output.contains("Processed 1 items"));
    assert!(result.output.contains("Config.toml correct 🟢"));
}

#[test]
fn validate_no_match_is_error() {
    let config = simple_config();
    let log = "this does not match anything\n";
    let result = validate(log.as_bytes(), &config).unwrap();
    assert!(result.error.is_some());
    assert!(result.output.contains("Processed 0 items"));
    assert!(result
        .output
        .contains("Validation failed, issue with Config.toml 🔴"));
    let err = result.error.unwrap();
    assert!(err.contains("validation error at line 1"));
    assert!(err.contains("this does not match anything"));
}

#[test]
fn validate_empty_input() {
    let config = simple_config();
    let result = validate("".as_bytes(), &config).unwrap();
    assert!(result.error.is_none());
    assert!(result.output.contains("Processed 0 items"));
    assert!(result.output.contains("Config.toml correct 🟢"));
}

#[test]
fn validate_multiple_items_all_pass() {
    let config = simple_config();
    let log = "2024-01-01 10:00:00 INFO first\n2024-01-01 10:00:01 WARN second\n";
    let result = validate(log.as_bytes(), &config).unwrap();
    assert!(result.error.is_none());
    assert!(result.output.contains("Processed 2 items"));
    assert!(result.output.contains("Config.toml correct 🟢"));
}

#[test]
fn validate_multiline_item_counted() {
    let atoms = make_atoms();
    let parts = vec![
        RawPart {
            atom: Some("timestamp".into()),
            regex: None,
            ..Default::default()
        },
        RawPart {
            atom: None,
            regex: Some(" ".into()),
            ..Default::default()
        },
        RawPart {
            atom: Some("level".into()),
            regex: None,
            ..Default::default()
        },
        RawPart {
            atom: None,
            regex: Some(r"\n".into()),
            ..Default::default()
        },
        RawPart {
            atom: Some("message".into()),
            regex: None,
            ..Default::default()
        },
    ];
    let raw = raw_item_with_parts("multiline_entry", parts);
    let item = compile_item(&raw, &atoms, &[]).unwrap();
    let config = Config {
        index_threshold: 0,
        max_failed_items: 0,
        blacklist_atoms: vec![],
        items: vec![item],
    };
    let log = "2024-01-01 10:00:00 INFO\nhello world\n";
    let result = validate(log.as_bytes(), &config).unwrap();
    assert!(result.error.is_none());
    assert!(result.output.contains("Processed 1 items"));
    assert!(result.output.contains("Config.toml correct 🟢"));
}

#[test]
fn validate_stops_at_first_non_matching() {
    let config = simple_config();
    let log = "2024-01-01 10:00:00 INFO first\ngarbage line\n2024-01-01 10:00:02 INFO third\n";
    let result = validate(log.as_bytes(), &config).unwrap();
    assert!(result.output.contains("Processed 1 items"));
    assert!(result
        .output
        .contains("Validation failed, issue with Config.toml 🔴"));
    let err = result.error.unwrap();
    assert!(err.contains("validation error at line 2"));
    assert!(err.contains("garbage line"));
}

#[test]
fn validate_error_at_first_line() {
    let config = simple_config();
    let log = "garbage\n2024-01-01 10:00:00 INFO valid\n";
    let result = validate(log.as_bytes(), &config).unwrap();
    assert!(result.output.contains("Processed 0 items"));
    assert!(result
        .output
        .contains("Validation failed, issue with Config.toml 🔴"));
    let err = result.error.unwrap();
    assert!(err.contains("validation error at line 1"));
}

#[test]
fn validate_cleans_literal_newlines_in_content() {
    let config = simple_config();
    let log = "2024-01-01 10:00:00 INFO hello\\n2024-01-01 10:00:01 WARN world\n";
    let result = validate(log.as_bytes(), &config).unwrap();
    assert!(result.error.is_none());
    assert!(result.output.contains("Processed 2 items"));
    assert!(result.output.contains("Config.toml correct 🟢"));
}

// ── max_pattern_line_span ────────────────────────────────────────────

#[test]
fn max_span_single_line_patterns() {
    let config = simple_config();
    assert_eq!(max_pattern_line_span(&config), 1);
}

#[test]
fn max_span_multiline_pattern() {
    let atoms = make_atoms();
    let parts = vec![
        RawPart {
            atom: Some("level".into()),
            regex: None,
            ..Default::default()
        },
        RawPart {
            atom: None,
            regex: Some(r"\n".into()),
            ..Default::default()
        },
        RawPart {
            atom: Some("message".into()),
            regex: None,
            ..Default::default()
        },
    ];
    let raw = raw_item_with_parts("entry", parts);
    let item = compile_item(&raw, &atoms, &[]).unwrap();
    let config = Config {
        index_threshold: 0,
        max_failed_items: 0,
        blacklist_atoms: vec![],
        items: vec![item],
    };
    assert_eq!(max_pattern_line_span(&config), 2);
}

// ── diagnose_mismatch ────────────────────────────────────────────────

#[test]
fn diagnose_partial_match_single_item() {
    let config = simple_config();
    // timestamp matches, space matches, but "BADLEVEL" doesn't match level atom
    let content = "2024-01-01 10:00:00 BADLEVEL hello\n";
    let diag = diagnose_mismatch(content, &config);
    assert!(diag.contains("item 'log_entry'"));
    assert!(diag.contains("matched 2/5 parts")); // timestamp + " " matched, level fails
    assert!(diag.contains("timestamp"));
    assert!(diag.contains("[matched]"));
    assert!(diag.contains("level"));
    assert!(diag.contains("[no match]"));
}

#[test]
fn diagnose_no_parts_match() {
    let config = simple_config();
    // nothing matches even the first atom (timestamp)
    let content = "completely random garbage\n";
    let diag = diagnose_mismatch(content, &config);
    assert!(diag.contains("item 'log_entry'"));
    assert!(diag.contains("matched 0/5 parts"));
    assert!(diag.contains("timestamp"));
    assert!(diag.contains("[no match]"));
}

#[test]
fn diagnose_best_match_selection_multiple_items() {
    let atoms = make_atoms();
    // Item 1: level + " " + message (3 parts)
    let parts1 = atom_parts(&["level", "message"], Some(" "));
    let raw1 = raw_item_with_parts("short_entry", parts1);
    let item1 = compile_item(&raw1, &atoms, &[]).unwrap();

    // Item 2: timestamp + " " + level + " " + message (5 parts)
    let parts2 = atom_parts(&["timestamp", "level", "message"], Some(" "));
    let raw2 = raw_item_with_parts("full_entry", parts2);
    let item2 = compile_item(&raw2, &atoms, &[]).unwrap();

    let config = Config {
        index_threshold: 0,
        max_failed_items: 0,
        blacklist_atoms: vec![],
        items: vec![item1, item2],
    };

    // Content: timestamp and space match in full_entry, but level fails
    // short_entry: level fails immediately (0 parts)
    // full_entry: timestamp + " " match (2 parts), level fails
    let content = "2024-01-01 10:00:00 BADLEVEL hello\n";
    let diag = diagnose_mismatch(content, &config);
    // full_entry should be the best match since it matched more parts
    assert!(diag.contains("item 'full_entry'"));
    assert!(diag.contains("matched 2/5 parts")); // timestamp + (regex " ") matched, level fails
}

#[test]
fn diagnose_with_flags_ignorecase() {
    let atoms = make_atoms();
    let parts = atom_parts(&["level", "message"], Some(" "));
    let mut raw = raw_item_with_parts("entry", parts);
    raw.flags = Some(FlagValue::Single("IGNORECASE".into()));
    let item = compile_item(&raw, &atoms, &[]).unwrap();
    let config = Config {
        index_threshold: 0,
        max_failed_items: 0,
        blacklist_atoms: vec![],
        items: vec![item],
    };

    // With IGNORECASE, "info" should match the level atom
    let content = "info hello\n";
    let diag = diagnose_mismatch(content, &config);
    // All parts should match
    assert!(diag.contains("matched 3/3 parts"));
}

#[test]
fn validate_diagnostic_in_error_output() {
    let config = simple_config();
    let log = "2024-01-01 10:00:00 BADLEVEL hello\n";
    let result = validate(log.as_bytes(), &config).unwrap();
    assert!(result.error.is_some());
    assert!(result.output.contains("Best match: item 'log_entry'"));
    assert!(result.output.contains("[matched]"));
    assert!(result.output.contains("[no match]"));
    assert!(result
        .output
        .contains("Validation failed, issue with Config.toml 🔴"));
}
