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
- `blacklist_atoms` (list of strings, optional)
  - Atom names whose extracted values are excluded from matching signatures for all items.
- `delimiters` (string or list of strings, optional)
  - Regex(es) identifying delimiter lines that split the log into blocks.
  - Without delimiters or `record_start`, every line is its own block (per-line records).
- `record_start` (string, optional)
  - Regex matching the first line of a new record. A block ends (and a new one begins) right before any line matching this pattern, even with no delimiter line between records.
  - Lets consecutive multi-line records be split by recognizing where the next one begins, instead of requiring an explicit separator. Can be combined with `delimiters`: either mechanism can end a block.

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

#### Additional item fields
- `flags` (string or list of strings, optional)
  - Regex flags by name: `IGNORECASE`, `MULTILINE`, `DOTALL`.
- `ignore_atoms` (list of strings, optional)
  - Atom names whose values are excluded from the item's signature.

## Pattern Compilation
For each item:
1. Build a full regex by concatenating `parts` in order.
2. Atom parts become named capture groups with unique names (e.g., `<name__ordinal>`).
3. The regex is compiled with the configured flags.
4. An item's effective ignore set is `blacklist_atoms ∪ ignore_atoms`.

## Parsing Logs
- Input logs are read as UTF-8; invalid byte sequences are replaced rather than failing.
- The log is split into blocks:
  - With `general.delimiters` configured, a block ends at a line matching a delimiter regex (the delimiter line itself is discarded).
  - With `general.record_start` configured, a block ends right before a line matching that regex (the matching line becomes the first line of the next block). Combinable with `delimiters` — either condition ends a block.
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
  - `(item_name, tuple(values))`, where `values` are captured atom values **excluding** ignored atoms.

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
- Required: `--config` (path to TOML)
- Optional:
  - `--threshold` (overrides `general.index_threshold`)
  - `--max-failed` (overrides `general.max_failed_items`)
  - `--validate` (validate `clean_log` against the config instead of comparing two logs)
  - `--side-by-side` (open the interactive compare view instead of the default divergence output; mutually exclusive with `--validate`)

## Output

### Comparison (`clean_log` and `dirty_log` given)
- Prints each dirty item's `raw_line` in order for every `Match` event.
- On the first `Extra` or `Missing` event, prints `--- DIVERGENCE ---` followed by a one-line description (dirty line and line number, or clean line and line number) and stops.
- If comparison stopped early with no divergence printed, prints `--- STOPPED ---` followed by the stop reason.
- Colored diagnostics (see `--validate` below) and top-level error messages auto-detect terminal support: colored on a TTY, plain when piped or when `NO_COLOR`/`CLICOLOR=0` is set.

### `--validate`
- Prints `Processed N items` followed by either `Config.toml correct 🟢`, or on the first block with no matching pattern: the validation error, a diagnostic breakdown of the closest-matching item's parts (colored: green for matched parts, red for the part that failed, dim for parts not yet attempted), and `Validation failed, issue with Config.toml 🔴`. Exits with status `1` on failure.

### `--side-by-side`
- Requires an interactive terminal (stdout must be a TTY); errors immediately otherwise.
- Merges clean and dirty items into rows, in document order: a matched pair shares a row; an unmatched item gets its own row with the other side blank. Each row shows the same id number and a status icon on both sides (✓ matched at the same original index, ~ matched only via `--threshold`, ✗ no counterpart) so a shared id/icon signals a matching pair.
- A minimap strip above the table shows one column per row (or, once there are more rows than columns, one column per bucket of rows, colored by the worst status in the bucket): green for an aligned match, gray for a threshold-shifted match (with a connecting line between the clean/dirty strips), red for no match. A live marker tracks the current viewport position on the minimap as you navigate.
- Lays out the full comparison regardless of where `--max-failed` early-stop would have cut off the plain-text output.
- Navigation: `↑`/`↓` or `j`/`k` move one row; `←`/`→` or `h`/`l` jump several rows at once; `PageUp`/`PageDown` scroll a page; `Home`/`g` and `End`/`G` jump to the start/end; `q`/`Esc`/`Ctrl-C` quit.

## Ordering and Precedence Rules
- Item patterns are tried in configuration order; the first match wins.
- For matching, clean items are authoritative; dirty items are matched to them within the index threshold.
- Atom blacklisting and ignore lists only affect signatures (matching), not parsing.

## Version
- The implementation should expose a single application version string in one place.
