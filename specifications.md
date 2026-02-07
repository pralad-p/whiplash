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
- `elements` (required, non-empty)
- `items` (required, non-empty list)

### `general`
- `index_threshold` (int, default `0`, must be >= 0)
  - Maximum offset allowed between clean and dirty item indices when matching.
- `max_failed_items` (int, default `0`, must be >= 0)
  - Maximum number of consecutive failures before stopping. `0` disables early stop.
- `blacklist_elements` (list of strings, optional)
  - Element names whose extracted values are excluded from matching signatures for all items.

### `elements`
- A map of element names to regex strings.
- Example key/value shape: `timestamp = "\\d{4}-..."`.

### `items`
Each item defines how to match a log entry (possibly multi-line).

Required:
- `name` (non-empty string)

Pattern definition is **either**:
1. `parts` (explicit, ordered list of pattern parts), or
2. `elements` + optional `joiner` (implicit parts built from elements)

#### `parts`
- Non-empty list of tables.
- Each part must include exactly one of:
  - `element = "element_name"` (must exist in `elements`)
  - `regex = "..."` (raw regex fragment)
- `parts` are concatenated in order to form the full regex.

#### `elements` + `joiner`
- `elements`: non-empty list of element names (must exist in `elements`).
- `joiner`: regex string used between elements (default `".*?"`).
- The full pattern becomes: element, joiner, element, joiner, ...

#### Additional item fields
- `anchored` (bool, default `false`)
  - If true, a match must end on a line boundary (i.e., end of line or end of text).
- `flags` (string or list of strings, optional)
  - Regex flags by name: `IGNORECASE`, `MULTILINE`, `DOTALL`.
- `ignore_elements` (list of strings, optional)
  - Element names whose values are excluded from the item’s signature.

## Pattern Compilation
For each item:
1. Build a full regex by concatenating `parts` in order.
2. Element parts become named capture groups with unique names (e.g., `<name__ordinal>`).
3. The regex is compiled with the configured flags.
4. An item’s effective ignore set is `blacklist_elements ∪ ignore_elements`.

## Parsing Logs
- Input logs are read as UTF-8; invalid byte sequences are replaced rather than failing.
- Logs are split into lines with `keepends=True` to preserve boundaries.
- Parsing proceeds sequentially through the file:
  - For each position, the parser tries item patterns in config order.
  - Matching is attempted from the current offset in the remaining substring.
  - The first pattern that matches (and passes anchor rules) wins.
  - If the match spans multiple lines, the parser advances by the number of lines spanned.
  - If no pattern matches at the current line, that line is recorded as unparsed.

### Parsed Item Structure
For each matched item:
- `name`: item name.
- `line_no`: 1-based line number where the match started.
- `raw_line`: matched text, with trailing newlines stripped.
- `element_values`: map of element name to list of captured values.
- `signature`: tuple used for comparison:
  - `(item_name, tuple(values))`, where `values` are captured element values **excluding** ignored elements.

## Comparison Algorithm
Inputs: `clean_items`, `dirty_items`, `threshold`, `max_failed_items`.

Core behavior:
- Items are matched in order.
- For each clean item at index `i`, search dirty items within index window:
  - Window bounds: `min_k = max(j, i - threshold)` and `max_k = min(len(dirty)-1, i + threshold)`.
  - `j` is the next dirty index not yet matched.
- A match occurs when `clean.signature == dirty.signature` within the window.

Failures and extras:
- If no candidate window exists: record a mismatch (`"no candidate within threshold"`).
- If no match found within the window: record a mismatch (`"no match within window"`).
- If dirty items appear before the matched dirty index, they are recorded as `dirty_extras`.
- Any remaining dirty items after clean processing are recorded as `dirty_extras`.

Early stop:
- `failed_run` counts consecutive failures.
- Failures include mismatches and dirty-only extras added before a match.
- If `max_failed_items > 0` and `failed_run >= max_failed_items`, comparison stops early.
- The result records `stopped`, `stop_clean_index`, `stop_dirty_index`, and a reason.

## CLI Behavior
Command:
```
whiplash --config config.toml [--threshold N] [--max-failed N] [--format text|json] [--max-report N] clean.log dirty.log
```

Arguments:
- Positional: `clean_log`, `dirty_log` (paths)
- Required: `--config` (path to TOML)
- Optional overrides:
  - `--threshold` (overrides `general.index_threshold`)
  - `--max-failed` (overrides `general.max_failed_items`)
  - `--format` (`text` default, or `json`)
  - `--max-report` (text output limit, default `20`)

Validation:
- `--threshold` and `--max-failed` must be >= 0 (otherwise exit with error).

## Output Formats

### Text
- Summary counts:
  - clean items, dirty items, matches, mismatches, dirty-only extras,
    unparsed clean lines, unparsed dirty lines.
- Early stop status and details.
- Lists of first mismatches and dirty-only extras (limited by `--max-report`).

### JSON
- `summary`: same counts and early stop metadata as text.
- `mismatches`: list with clean index, line, item name, and reason.
- `dirty_extras`: list with dirty line and item name.

## Ordering and Precedence Rules
- Item patterns are tried in configuration order; the first match wins.
- For matching, clean items are authoritative; dirty items are matched to them within the index threshold.
- Element blacklisting and ignore lists only affect signatures (matching), not parsing.

## Version
- The implementation should expose a single application version string in one place.
