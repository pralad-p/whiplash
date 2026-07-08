//! Interactive side-by-side compare view (`--side-by-side`).
//!
//! Clean and dirty items are merged into aligned rows (see `build_rows`),
//! shown two columns wide, with a minimap strip above summarizing the
//! whole comparison and tracking the current viewport position live.

use std::io::{self, IsTerminal};

use anyhow::{bail, Result};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::execute;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row as TableRow, Table, TableState};
use ratatui::{Frame, Terminal};

use crate::{CompareResult, ParsedItem};

// ── Row alignment ────────────────────────────────────────────────────

/// One row of the merged side-by-side view: a clean item, a dirty item, or
/// both, when matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Row {
    clean: Option<usize>,
    dirty: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowStatus {
    /// Matched, and the clean/dirty items sit at the same original index.
    Aligned,
    /// Matched, but only found via the index threshold (positions differ).
    Shifted,
    /// No counterpart on the other side.
    NonMatching,
}

impl Row {
    fn status(&self) -> RowStatus {
        match (self.clean, self.dirty) {
            (Some(c), Some(d)) if c == d => RowStatus::Aligned,
            (Some(_), Some(_)) => RowStatus::Shifted,
            _ => RowStatus::NonMatching,
        }
    }
}

/// Merge clean/dirty items into rows in document order: a matched pair
/// shares a row; an unmatched clean item gets its own row (dirty side
/// blank) inserted just before the first later match, preserving clean's
/// original order; likewise unmatched dirty items appear in dirty order.
fn build_rows(clean_len: usize, dirty_to_clean: &[Option<usize>]) -> Vec<Row> {
    let mut clean_matched = vec![false; clean_len];
    for ci in dirty_to_clean.iter().flatten() {
        clean_matched[*ci] = true;
    }

    let mut rows = Vec::with_capacity(clean_len.max(dirty_to_clean.len()));
    let mut next_clean = 0usize;

    for (di, mapped) in dirty_to_clean.iter().enumerate() {
        match mapped {
            Some(ci) => {
                while next_clean < *ci {
                    if !clean_matched[next_clean] {
                        rows.push(Row { clean: Some(next_clean), dirty: None });
                    }
                    next_clean += 1;
                }
                rows.push(Row { clean: Some(*ci), dirty: Some(di) });
                next_clean = next_clean.max(ci + 1);
            }
            None => rows.push(Row { clean: None, dirty: Some(di) }),
        }
    }

    while next_clean < clean_len {
        if !clean_matched[next_clean] {
            rows.push(Row { clean: Some(next_clean), dirty: None });
        }
        next_clean += 1;
    }

    rows
}

// ── Minimap ──────────────────────────────────────────────────────────

/// Maps a row index into one of `width` display buckets. Dense (one column
/// per row, left-packed) when everything fits; otherwise evenly bucketed,
/// with each bucket showing the worst status among its rows.
fn bucket_index(row_idx: usize, rows_len: usize, width: usize) -> usize {
    if rows_len <= width {
        row_idx
    } else {
        ((row_idx * width) / rows_len).min(width - 1)
    }
}

fn worse(a: RowStatus, b: RowStatus) -> RowStatus {
    fn rank(s: RowStatus) -> u8 {
        match s {
            RowStatus::NonMatching => 2,
            RowStatus::Shifted => 1,
            RowStatus::Aligned => 0,
        }
    }
    if rank(b) > rank(a) {
        b
    } else {
        a
    }
}

fn merge_worst(slot: &mut Option<RowStatus>, status: RowStatus) {
    *slot = Some(match slot {
        Some(existing) => worse(*existing, status),
        None => status,
    });
}

struct MinimapModel {
    clean: Vec<Option<RowStatus>>,
    dirty: Vec<Option<RowStatus>>,
    /// Only set where a bucket contains an actual match (both sides
    /// present); connects the clean and dirty strips.
    connector: Vec<Option<RowStatus>>,
    cursor_bucket: usize,
}

fn build_minimap(rows: &[Row], width: usize, cursor_row: usize) -> MinimapModel {
    let width = width.max(1);
    let mut clean = vec![None; width];
    let mut dirty = vec![None; width];
    let mut connector = vec![None; width];

    for (i, row) in rows.iter().enumerate() {
        let b = bucket_index(i, rows.len(), width);
        let status = row.status();
        if row.clean.is_some() {
            merge_worst(&mut clean[b], status);
        }
        if row.dirty.is_some() {
            merge_worst(&mut dirty[b], status);
        }
        if row.clean.is_some() && row.dirty.is_some() {
            merge_worst(&mut connector[b], status);
        }
    }

    let cursor_bucket = if rows.is_empty() {
        0
    } else {
        bucket_index(cursor_row.min(rows.len() - 1), rows.len(), width)
    };

    MinimapModel { clean, dirty, connector, cursor_bucket }
}

fn status_color(status: RowStatus) -> Color {
    match status {
        RowStatus::Aligned => Color::Green,
        RowStatus::Shifted => Color::DarkGray,
        RowStatus::NonMatching => Color::Red,
    }
}

fn minimap_strip(slots: &[Option<RowStatus>], dot: char) -> Line<'static> {
    let spans = slots
        .iter()
        .map(|slot| match slot {
            Some(status) => Span::styled(dot.to_string(), Style::new().fg(status_color(*status))),
            None => Span::raw(" "),
        })
        .collect::<Vec<_>>();
    Line::from(spans)
}

fn minimap_connector(model: &MinimapModel) -> Line<'static> {
    let spans = model
        .connector
        .iter()
        .enumerate()
        .map(|(i, slot)| {
            let ch = if i == model.cursor_bucket { '▲' } else { '│' };
            match slot {
                Some(status) => Span::styled(ch.to_string(), Style::new().fg(status_color(*status))),
                None if i == model.cursor_bucket => Span::styled(ch.to_string(), Style::new().fg(Color::White)),
                None => Span::raw(" "),
            }
        })
        .collect::<Vec<_>>();
    Line::from(spans)
}

// ── Rendering ────────────────────────────────────────────────────────

fn display_line(raw: &str) -> String {
    raw.replace('\n', " ⏎ ")
}

fn build_table<'a>(clean_items: &[ParsedItem], dirty_items: &[ParsedItem], rows: &'a [Row]) -> Table<'a> {
    let id_width = rows.len().max(1).to_string().len();

    let trows = rows.iter().enumerate().map(|(i, row)| {
        let status = row.status();
        let color = status_color(status);
        let id = i + 1;

        let cell = |item: Option<&ParsedItem>, icon: &str| -> Cell<'a> {
            match item {
                Some(item) => Cell::from(format!(
                    "{icon} {id:>id_width$}  {}",
                    display_line(&item.raw_line)
                ))
                .style(Style::new().fg(color)),
                None => Cell::from(format!("  {id:>id_width$}  (missing)"))
                    .style(Style::new().fg(Color::DarkGray).add_modifier(Modifier::ITALIC)),
            }
        };

        let icon = match status {
            RowStatus::Aligned => "✓",
            RowStatus::Shifted => "~",
            RowStatus::NonMatching => "✗",
        };

        TableRow::new([
            cell(row.clean.map(|ci| &clean_items[ci]), icon),
            cell(row.dirty.map(|di| &dirty_items[di]), icon),
        ])
    });

    Table::new(trows.collect::<Vec<_>>(), [Constraint::Percentage(50), Constraint::Percentage(50)])
        .header(
            TableRow::new(["Clean", "Dirty"]).style(Style::new().add_modifier(Modifier::BOLD)),
        )
        .block(Block::default().borders(Borders::ALL).title(" Side-by-side "))
        .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED))
}

/// Draws one frame. Returns the approximate number of body rows visible,
/// used to size PageUp/PageDown jumps.
fn draw(frame: &mut Frame, clean_items: &[ParsedItem], dirty_items: &[ParsedItem], rows: &[Row], selected: usize) -> usize {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(3), Constraint::Length(1)])
        .split(area);

    let minimap_width = chunks[0].width.saturating_sub(2).max(1) as usize;
    let model = build_minimap(rows, minimap_width, selected);

    let title = format!(
        " minimap — {} rows, cursor {}/{}  (green=match  gray=shifted match  red=no match) ",
        rows.len(),
        rows.len().min(selected + 1),
        rows.len()
    );
    let minimap = Paragraph::new(vec![
        minimap_strip(&model.clean, '●'),
        minimap_connector(&model),
        minimap_strip(&model.dirty, '●'),
    ])
    .block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(minimap, chunks[0]);

    let table = build_table(clean_items, dirty_items, rows);
    let mut state = TableState::default().with_selected(Some(selected));
    frame.render_stateful_widget(table, chunks[1], &mut state);

    let footer = Paragraph::new(
        "↑/↓ j/k: move   ←/→ h/l: jump   PgUp/PgDn: page   Home/End: start/end   q: quit",
    )
    .style(Style::new().add_modifier(Modifier::DIM));
    frame.render_widget(footer, chunks[2]);

    chunks[1].height.saturating_sub(3).max(1) as usize
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    clean_items: &[ParsedItem],
    dirty_items: &[ParsedItem],
    rows: &[Row],
) -> Result<()> {
    let last_row = rows.len().saturating_sub(1);
    let mut selected: usize = 0;
    let mut page_size: usize = 10;
    let jump = (rows.len() / 20).max(1);

    loop {
        terminal.draw(|frame| {
            page_size = draw(frame, clean_items, dirty_items, rows, selected);
        })?;

        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
            KeyCode::Char('q') | KeyCode::Esc => break,
            KeyCode::Down | KeyCode::Char('j') => selected = (selected + 1).min(last_row),
            KeyCode::Up | KeyCode::Char('k') => selected = selected.saturating_sub(1),
            KeyCode::Right | KeyCode::Char('l') => selected = (selected + jump).min(last_row),
            KeyCode::Left | KeyCode::Char('h') => selected = selected.saturating_sub(jump),
            KeyCode::PageDown => selected = (selected + page_size).min(last_row),
            KeyCode::PageUp => selected = selected.saturating_sub(page_size),
            KeyCode::Home | KeyCode::Char('g') => selected = 0,
            KeyCode::End | KeyCode::Char('G') => selected = last_row,
            _ => {}
        }
    }

    Ok(())
}

/// Launch the interactive side-by-side view. Requires stdout to be a
/// terminal; lays out the full comparison regardless of where plain-text
/// early-stop would have cut off (see `CompareResult::dirty_to_clean`).
pub fn run_side_by_side(
    clean_items: &[ParsedItem],
    dirty_items: &[ParsedItem],
    result: &CompareResult,
) -> Result<()> {
    if !io::stdout().is_terminal() {
        bail!("--side-by-side requires an interactive terminal (stdout is not a tty)");
    }

    let rows = build_rows(clean_items.len(), &result.dirty_to_clean);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let app_result = run_app(&mut terminal, clean_items, dirty_items, &rows);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    app_result
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_rows_all_matched_same_position() {
        let rows = build_rows(3, &[Some(0), Some(1), Some(2)]);
        assert_eq!(
            rows,
            vec![
                Row { clean: Some(0), dirty: Some(0) },
                Row { clean: Some(1), dirty: Some(1) },
                Row { clean: Some(2), dirty: Some(2) },
            ]
        );
        assert!(rows.iter().all(|r| r.status() == RowStatus::Aligned));
    }

    #[test]
    fn build_rows_shifted_match() {
        // dirty[1] matches clean[0]: same pair, different original index.
        let rows = build_rows(1, &[Some(0), None]);
        assert_eq!(rows[0], Row { clean: Some(0), dirty: Some(0) });
    }

    #[test]
    fn build_rows_missing_clean_item_inserted_in_order() {
        // clean has 3 items; dirty only matches clean[0] and clean[2].
        // clean[1] should appear as its own row, in between.
        let rows = build_rows(3, &[Some(0), Some(2)]);
        assert_eq!(
            rows,
            vec![
                Row { clean: Some(0), dirty: Some(0) },
                Row { clean: Some(1), dirty: None },
                Row { clean: Some(2), dirty: Some(1) },
            ]
        );
        assert_eq!(rows[1].status(), RowStatus::NonMatching);
    }

    #[test]
    fn build_rows_extra_dirty_item() {
        let rows = build_rows(1, &[None, Some(0)]);
        assert_eq!(
            rows,
            vec![
                Row { clean: None, dirty: Some(0) },
                Row { clean: Some(0), dirty: Some(1) },
            ]
        );
        assert_eq!(rows[0].status(), RowStatus::NonMatching);
    }

    #[test]
    fn build_rows_trailing_unmatched_clean_items() {
        let rows = build_rows(3, &[Some(0)]);
        assert_eq!(
            rows,
            vec![
                Row { clean: Some(0), dirty: Some(0) },
                Row { clean: Some(1), dirty: None },
                Row { clean: Some(2), dirty: None },
            ]
        );
    }

    #[test]
    fn build_rows_out_of_order_matches_do_not_panic_or_duplicate() {
        // di=0 matches clean[2] (a later index), di=1 matches clean[0]
        // (threshold allows non-monotonic assignment).
        let rows = build_rows(3, &[Some(2), Some(0)]);
        // Every clean index 0..3 appears exactly once across all rows.
        let mut seen: Vec<usize> = rows.iter().filter_map(|r| r.clean).collect();
        seen.sort_unstable();
        assert_eq!(seen, vec![0, 1, 2]);
    }

    #[test]
    fn build_rows_empty() {
        assert!(build_rows(0, &[]).is_empty());
    }

    #[test]
    fn bucket_index_dense_when_rows_fit_width() {
        assert_eq!(bucket_index(0, 3, 10), 0);
        assert_eq!(bucket_index(2, 3, 10), 2);
    }

    #[test]
    fn bucket_index_spreads_when_overflowing_width() {
        // 100 rows into 10 buckets: row 0 -> bucket 0, row 99 -> bucket 9.
        assert_eq!(bucket_index(0, 100, 10), 0);
        assert_eq!(bucket_index(99, 100, 10), 9);
        assert_eq!(bucket_index(50, 100, 10), 5);
    }

    #[test]
    fn build_minimap_worst_status_wins_in_bucket() {
        // 4 rows crammed into 2 buckets: bucket 0 gets rows 0-1 (aligned,
        // shifted), bucket 1 gets rows 2-3 (aligned, nonmatching).
        let rows = vec![
            Row { clean: Some(0), dirty: Some(0) }, // aligned
            Row { clean: Some(1), dirty: Some(5) }, // shifted
            Row { clean: Some(2), dirty: Some(2) }, // aligned
            Row { clean: None, dirty: Some(3) },    // nonmatching
        ];
        let model = build_minimap(&rows, 2, 0);
        assert_eq!(model.clean[0], Some(RowStatus::Shifted));
        assert_eq!(model.dirty[1], Some(RowStatus::NonMatching));
    }

    #[test]
    fn build_minimap_connector_only_set_for_actual_matches() {
        let rows = vec![
            Row { clean: Some(0), dirty: None }, // no match: no connector
            Row { clean: None, dirty: Some(0) }, // no match: no connector
        ];
        let model = build_minimap(&rows, 2, 0);
        assert!(model.connector[0].is_none());
        assert!(model.connector[1].is_none());
    }

    #[test]
    fn build_minimap_cursor_bucket_tracks_position() {
        let rows: Vec<Row> = (0..10).map(|i| Row { clean: Some(i), dirty: Some(i) }).collect();
        let model = build_minimap(&rows, 10, 7);
        assert_eq!(model.cursor_bucket, 7);
    }

    #[test]
    fn build_minimap_empty_rows() {
        let model = build_minimap(&[], 5, 0);
        assert_eq!(model.cursor_bucket, 0);
        assert!(model.clean.iter().all(|s| s.is_none()));
    }
}
