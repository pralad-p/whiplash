# Whiplash Log Diff Specification

This document specifies the application behavior and implementation details for Whiplash Log Diff.

## Purpose
Whiplash compares two log files (“clean” and “dirty”) by parsing them into structured items using configurable regex definitions, then comparing those items in order with a configurable index window and early-stop behavior.

## Components
- CLI entrypoint: argument parsing, configuration loading, output formatting.
- Config loader: TOML parsing/validation and in-memory config model.
- Parser: pattern compilation and log parsing into structured items.
- Comparator: item comparison algorithm and result model.

## Configuration (TOML)

### Top-level sections
- `general` (optional)
- `atoms` (required, non-empty)
- `items` (required, non-empty list)

### `general`
- `index_threshold` (int, default `0`, must be >= 0)
  - Maximum offset allowed between clean and dirty item indices when matching.
- `max_failed_items` (int, default `0`, must be >= 0)
  - Maximum number of consecutive failures before stopping. `0` disables early stop.
- `delimiters` (string or list of strings, optional)
  - Regex(es) identifying delimiter lines that split the log into blocks.
  - Without delimiters or `record_start`, every line is its own block (per-line records).
- `record_start` (string or list of strings, optional)
  - Regex(es) matching the first line of a new record. A block ends (and a new one begins) right before any line matching any of these patterns, even with no delimiter line between records.
  - Lets consecutive multi-line records be split by recognizing where the next one begins, instead of requiring an explicit separator. A list is useful when different record types start differently (e.g. one pattern per record type). Can be combined with `delimiters`: either mechanism can end a block.

### `atoms`
- A map of atom names to regex strings.
- Example key/value shape: `timestamp = "\\d{4}-..."`.

### `items`
Each item defines how to match a log entry (possibly multi-line).

Required:
- `name` (non-empty string)

Pattern definition:
- `parts` (required, non-empty list of pattern parts)

#### `parts`
- Non-empty list of tables.
- Each part must include exactly one of:
  - `atom = "atom_name"` (must reference a name defined in `atoms`)
  - `regex = "..."` (raw regex fragment)
- `parts` are concatenated in order to form the full regex.
- `optional` (bool, default `false`)
  - The part may be absent from the log entry (e.g. records whose trailing lines only sometimes appear); its absence does not fail the match.
- `include_for_match` (bool, default `false`, atom parts only)
  - Opts the item into whitelist matching: when any part of an item sets it, the item's signature contains **only** the values of the marked parts, instead of all captured values.
  - Per-occurrence: the same atom used twice can be marked on one occurrence only.
  - Setting it on a `regex` part (which captures no value) is a config error.
  - Distinct from `optional`: `optional` controls whether the part must be present to parse; `include_for_match` controls whether its value participates in cross-record matching.

#### Additional item fields
- `flags` (string or list of strings, optional)
  - Regex flags by name: `IGNORECASE`, `MULTILINE`, `DOTALL`.

## Pattern Compilation
For each item:
1. Build a full regex by concatenating `parts` in order.
2. Atom parts become named capture groups with unique names (e.g., `<name__ordinal>`).
3. The regex is compiled with the configured flags.
4. If any part sets `include_for_match`, the item's signature is built from the marked parts only (whitelist mode); otherwise every captured value enters the signature.

## Parsing Logs
- Input logs are read as UTF-8; invalid byte sequences are replaced rather than failing.
- The log is split into blocks:
  - With `general.delimiters` configured, a block ends at a line matching a delimiter regex (the delimiter line itself is discarded).
  - With `general.record_start` configured, a block ends right before a line matching any of those regexes (the matching line becomes the first line of the next block). Combinable with `delimiters` — either condition ends a block.
  - With neither configured, every line is its own block.
  - Blocks may span multiple lines under either mechanism.
- For each block, item patterns are tried in config order; the first pattern that matches the **entire block** (start to end, trailing newlines excluded) wins.
- If no pattern fully matches a block, the block's starting line is recorded as unparsed. Partial matches are never accepted.

### Parsed Item Structure
For each matched item:
- `name`: item name.
- `line_no`: 1-based line number where the match started.
- `raw_line`: matched text, with trailing newlines stripped.
- `atom_values`: map of atom name to list of captured values.
- `signature`: tuple used for comparison:
  - `(item_name, tuple(values))`, where `values` are all captured atom values — or, when the item uses `include_for_match`, **only** the values of the marked parts.

## Comparison Algorithm
Inputs: `clean_items`, `dirty_items`, `threshold`, `max_failed_items`.

Core behavior:
- Items are matched in order.
- For each clean item at index `i`, search dirty items within index window:
  - Window bounds: `min_k = max(j, i - threshold)` and `max_k = min(len(dirty)-1, i + threshold)`.
  - `j` is the next dirty index not yet matched.
- A match occurs when `clean.signature == dirty.signature` within the window.

Failures and extras:
- A dirty item with no match in its window is emitted as an `Extra` event.
- A clean item left unmatched after all dirty items are processed is emitted as a `Missing` event (skipped if comparison stopped early).

Early stop:
- `failed_run` counts consecutive `Extra` events, resetting to `0` on each `Match`.
- If `max_failed_items > 0` and `failed_run >= max_failed_items`, comparison stops immediately (no further events emitted, and `Missing` events are not appended).
- The result records `stopped` and a `stop_reason` string.

## CLI Behavior
Command:
```
whiplash --config config.toml [--threshold N] [--max-failed N] [--validate | --side-by-side] clean_log [dirty_log]
```

Arguments:
- Positional: `clean_log` (required), `dirty_log` (required unless `--validate` is set)
- Required: `--config` (path to TOML; not used in combine mode)
- Optional:
  - `--threshold` (overrides `general.index_threshold`)
  - `--max-failed` (overrides `general.max_failed_items`)
  - `--validate` (validate `clean_log` against the config instead of comparing two logs)
  - `--side-by-side` (open the interactive compare view instead of the default divergence output; mutually exclusive with `--validate`)

## Irregular Combine Mode

Command:
```
whiplash --irregular --combine \
  --file-label API api.log \
  --file-label WORKER worker.log \
  --output case.log
```

Merges records from multiple irregular log files into one chronological case log **without** parsing them into the configured item types.

### Flags
- `--irregular` — treat inputs as irregular logs; currently only meaningful with `--combine` (each requires the other).
- `--combine` — enables combine mode. Mutually exclusive with comparison/validation: `--config`, `--validate`, `--side-by-side`, `--threshold`, `--max-failed`, and the positional log arguments.
- `--file-label <LABEL> <PATH>` — one labeled input per occurrence; at least two pairs required. Labels must start with an alphanumeric character and contain only alphanumerics, `_`, `.`, or `-` (so the emitted `[LABEL]` prefix cannot be malformed); duplicates are rejected.
- `--output <PATH>` — required; receives the complete combined log. The output is written to a sibling temporary file and atomically renamed into place, so a failure at any stage (reading, parsing, trimming, writing) never partially replaces an existing file.

### Input metadata header
The first line of every input file must be a metadata header of the form:
```text
{ marker_regex : "^(?<timestamp>\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?Z)" }
```
Serialization: a braced object holding the single key `marker_regex` (double quotes around the key optional), a colon, and a double-quoted string value using JSON escaping (`\\` for a literal backslash, `\"`, `\n`, `\r`, `\t`, `\/`). The header is metadata only and never appears in the combined output. Missing/invalid headers and invalid regexes are errors that name the input path; an empty input is an error.

### Record boundaries
- A record begins at a line matching the file's `marker_regex` and contains that line plus every following line up to, but not including, the next marker match or EOF (records may be multiline).
- Content between the header and the first marker match is an error (reported with file and line number), not silently discarded.
- A file whose body contains no marker match at all is an error.

### Chronological keys
The marker match supplies the record's chronological key: the named `timestamp` capture when present, otherwise the complete match. Keys are parsed as timestamps; accepted formats are RFC 3339 (`Z` or numeric offset, optional fractional seconds) and the naive forms `YYYY-MM-DDTHH:MM:SS[.frac]` / `YYYY-MM-DD HH:MM:SS[.frac]`, which are interpreted as UTC. An unparseable key is an error reported with file and line number.

### Merged output
Records from all inputs are merged by ascending timestamp. Records with equal timestamps keep a deterministic, stable order: `--file-label` order first, then source-record order within a file. The first line of each record is prefixed with `[LABEL] `; continuation lines are emitted verbatim. Every line is newline-terminated.

```text
[API] 2026-07-13T09:42:01.120Z request started
continuation line from the same record
[WORKER] 2026-07-13T09:42:01.240Z job received
```

## Ordering and Precedence Rules
- Item patterns are tried in configuration order; the first match wins.
- For matching, clean items are authoritative; dirty items are matched to them within the index threshold.
- `include_for_match` only affects signatures (matching), not parsing.

## Version
- The implementation should expose a single application version string in one place.
