use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::tui::theme;
use crate::tui::{App, ButtonAction, WizardStep};
use crate::Args;

/// Identifies an editable scan parameter on the settings step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingField {
    Host,
    Path,
    SamplePerCidr,
    Probes,
    Concurrency,
    TimeoutMs,
    ConnectTimeoutMs,
    Top,
}

impl SettingField {
    /// All settings fields in display order.
    pub const ALL: [SettingField; 8] = [
        SettingField::Host,
        SettingField::Path,
        SettingField::SamplePerCidr,
        SettingField::Probes,
        SettingField::Concurrency,
        SettingField::TimeoutMs,
        SettingField::ConnectTimeoutMs,
        SettingField::Top,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            SettingField::Host => "Host",
            SettingField::Path => "Path",
            SettingField::SamplePerCidr => "Sample per CIDR",
            SettingField::Probes => "Probes",
            SettingField::Concurrency => "Concurrency",
            SettingField::TimeoutMs => "Timeout (ms)",
            SettingField::ConnectTimeoutMs => "Connect timeout (ms)",
            SettingField::Top => "Top results",
        }
    }

    /// Current value of this field as an editable string.
    pub fn value_string(&self, args: &Args) -> String {
        match self {
            SettingField::Host => args.host.clone(),
            SettingField::Path => args.path.clone(),
            SettingField::SamplePerCidr => args.sample_per_cidr.to_string(),
            SettingField::Probes => args.probes.to_string(),
            SettingField::Concurrency => args.concurrency.to_string(),
            SettingField::TimeoutMs => args.timeout_ms.to_string(),
            SettingField::ConnectTimeoutMs => args.connect_timeout_ms.to_string(),
            SettingField::Top => args.top.to_string(),
        }
    }

    fn is_numeric(&self) -> bool {
        !matches!(self, SettingField::Host | SettingField::Path)
    }

    /// Step size used when nudging a numeric field with up/down arrows.
    fn step(&self) -> i64 {
        match self {
            SettingField::TimeoutMs | SettingField::ConnectTimeoutMs => 100,
            SettingField::SamplePerCidr => 10,
            _ => 1,
        }
    }

    /// Parse `raw` and apply it to `args`. Returns an error message on failure.
    pub fn apply(&self, raw: &str, args: &mut Args) -> Result<(), String> {
        let raw = raw.trim();
        match self {
            SettingField::Host => {
                if raw.is_empty() {
                    return Err("host must not be empty".to_string());
                }
                args.host = raw.to_string();
            }
            SettingField::Path => {
                if raw.is_empty() {
                    return Err("path must not be empty".to_string());
                }
                args.path = raw.to_string();
            }
            SettingField::SamplePerCidr => {
                let v = raw.parse::<usize>().map_err(|_| "invalid number".to_string())?;
                if v == 0 {
                    return Err("must be at least 1".to_string());
                }
                args.sample_per_cidr = v;
            }
            SettingField::Probes => {
                let v = raw.parse::<usize>().map_err(|_| "invalid number".to_string())?;
                if v == 0 {
                    return Err("must be at least 1".to_string());
                }
                args.probes = v;
            }
            SettingField::Concurrency => {
                let v = raw.parse::<usize>().map_err(|_| "invalid number".to_string())?;
                if v == 0 {
                    return Err("must be at least 1".to_string());
                }
                args.concurrency = v;
            }
            SettingField::TimeoutMs => {
                let v = raw.parse::<u64>().map_err(|_| "invalid number".to_string())?;
                if v == 0 {
                    return Err("must be at least 1".to_string());
                }
                args.timeout_ms = v;
            }
            SettingField::ConnectTimeoutMs => {
                let v = raw.parse::<u64>().map_err(|_| "invalid number".to_string())?;
                if v == 0 {
                    return Err("must be at least 1".to_string());
                }
                args.connect_timeout_ms = v;
            }
            SettingField::Top => {
                let v = raw.parse::<usize>().map_err(|_| "invalid number".to_string())?;
                if v == 0 {
                    return Err("must be at least 1".to_string());
                }
                args.top = v;
            }
        }
        Ok(())
    }
}

/// Render the active wizard step plus the shared top bar and footer.
pub fn render(app: &mut App, frame: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(area);

    render_step_bar(app, frame, chunks[0]);

    match app.wizard_step {
        WizardStep::Ranges => render_ranges(app, frame, chunks[1]),
        WizardStep::Settings => render_settings(app, frame, chunks[1]),
        WizardStep::Review => render_review(app, frame, chunks[1]),
    }

    render_footer(app, frame, chunks[2]);
    render_hint(app, frame, chunks[3]);
}

fn render_step_bar(app: &App, frame: &mut Frame, area: Rect) {
    let steps = ["1 Ranges", "2 Settings", "3 Review"];
    let current = app.wizard_step as usize;
    let mut spans = vec![Span::styled(
        format!(" cleanscan v{}  ", env!("CARGO_PKG_VERSION")),
        theme::header_style(),
    )];
    for (i, s) in steps.iter().enumerate() {
        let style = if i == current {
            theme::highlight_style()
        } else {
            theme::hint_style()
        };
        spans.push(Span::styled(format!(" {s} "), style));
        if i < steps.len() - 1 {
            spans.push(Span::styled(" ›", theme::hint_style()));
        }
    }
    let line = Line::from(spans);
    let block = Block::default().borders(Borders::ALL);
    let para = Paragraph::new(line).block(block);
    frame.render_widget(para, area);
}

fn render_ranges(app: &mut App, frame: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(3)])
        .split(area);

    let list_block = Block::default()
        .borders(Borders::ALL)
        .title(" Cloudflare CIDR ranges (space toggle, A all, D none) ");
    let inner = list_block.inner(chunks[0]);
    app.ranges_inner = Some(inner);

    let lines: Vec<Line> = app
        .cidr_candidates
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let mark = if e.selected { "[x]" } else { "[ ]" };
            let cursor = if i == app.cursor { "› " } else { "  " };
            let base = if i == app.cursor {
                theme::highlight_style()
            } else if e.selected {
                Style::default()
            } else {
                theme::hint_style()
            };
            Line::from(format!("{}{} {}", cursor, mark, e.cidr)).style(base)
        })
        .collect();

    let para = Paragraph::new(lines).block(list_block);
    frame.render_widget(para, chunks[0]);

    let selected = app.cidr_candidates.iter().filter(|e| e.selected).count();
    let input_line = if app.custom_input_mode {
        let (before, after) = app
            .input_buffer
            .split_at(app.edit_caret.min(app.input_buffer.len()));
        format!("> {}{}_{}", before, after, "")
    } else {
        "  press 'a' to add a custom CIDR   ".to_string()
    };
    let title = format!(" Add CIDR  ({} / {} selected) ", selected, app.cidr_candidates.len());
    let input = Paragraph::new(input_line)
        .block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(input, chunks[1]);
}

fn render_settings(app: &mut App, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Scan parameters (Enter edit, ↑/↓ step numeric) ");
    let inner = block.inner(area);
    app.settings_inner = Some(inner);

    let lines: Vec<Line> = SettingField::ALL
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let cursor = if i == app.cursor { "› " } else { "  " };
            let style = if i == app.cursor {
                theme::highlight_style()
            } else {
                Style::default()
            };
            let value = if app.edit_field == Some(i) {
                let (before, after) = app
                    .edit_buffer
                    .split_at(app.edit_caret.min(app.edit_buffer.len()));
                format!("{}{}_", before, after)
            } else {
                f.value_string(&app.config)
            };
            let label = format!("{:20}", f.label());
            Line::from(format!("{}{} = {}", cursor, label, value)).style(style)
        })
        .collect();

    let para = Paragraph::new(lines).block(block);
    frame.render_widget(para, area);
}

fn render_review(app: &App, frame: &mut Frame, area: Rect) {
    let selected: Vec<&str> = app
        .cidr_candidates
        .iter()
        .filter(|e| e.selected)
        .map(|e| e.cidr.as_str())
        .collect();

    let summary = vec![
        Line::from(vec![
            Span::styled("Target host : ", theme::title_style()),
            Span::raw(app.config.host.clone()),
        ]),
        Line::from(vec![
            Span::styled("Probe path : ", theme::title_style()),
            Span::raw(app.config.path.clone()),
        ]),
        Line::from(vec![
            Span::styled("Ranges     : ", theme::title_style()),
            Span::raw(format!("{} selected", selected.len())),
        ]),
        Line::from(selected.iter().map(|c| format!("  • {c}")).collect::<Vec<_>>().join("\n")),
        Line::from(""),
        Line::from(vec![
            Span::styled("Sample/CIDR: ", theme::title_style()),
            Span::raw(app.config.sample_per_cidr.to_string()),
            Span::raw("   "),
            Span::styled("Probes: ", theme::title_style()),
            Span::raw(app.config.probes.to_string()),
            Span::raw("   "),
            Span::styled("Concurrency: ", theme::title_style()),
            Span::raw(app.config.concurrency.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Timeout: ", theme::title_style()),
            Span::raw(format!("{}ms", app.config.timeout_ms)),
            Span::raw("   "),
            Span::styled("Connect: ", theme::title_style()),
            Span::raw(format!("{}ms", app.config.connect_timeout_ms)),
            Span::raw("   "),
            Span::styled("Top: ", theme::title_style()),
            Span::raw(app.config.top.to_string()),
        ]),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Review & start ");
    let para = Paragraph::new(summary).block(block);
    frame.render_widget(para, area);
}

fn render_footer(app: &mut App, frame: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(16),
            Constraint::Min(0),
            Constraint::Length(16),
        ])
        .split(area);

    let left_action = match app.wizard_step {
        WizardStep::Ranges => ButtonAction::Quit,
        _ => ButtonAction::Back,
    };
    let left_label = match app.wizard_step {
        WizardStep::Ranges => "‹ Quit (q)",
        _ => "‹ Back (←)",
    };
    app.button(frame, chunks[0], left_label, left_action, false);

    let right_action = match app.wizard_step {
        WizardStep::Review => ButtonAction::Start,
        _ => ButtonAction::Next,
    };
    let right_label = match app.wizard_step {
        WizardStep::Review => "Start scan ⏎",
        _ => "Next (→) ›",
    };
    let right_focused = app.wizard_step == WizardStep::Review;
    app.button(frame, chunks[2], right_label, right_action, right_focused);
}

fn render_hint(app: &App, frame: &mut Frame, area: Rect) {
    let text = match app.wizard_step {
        WizardStep::Ranges => {
            if app.custom_input_mode {
                "type CIDR • Enter confirm • Esc cancel"
            } else {
                "↑/↓ move • space toggle • a add • A all • D none • → next • ? help"
            }
        }
        WizardStep::Settings => {
            if app.edit_field.is_some() {
                "type value • ←/→ move • ↑/↓ step • Enter confirm • Esc cancel"
            } else {
                "↑/↓ move • Enter edit • → next • ? help"
            }
        }
        WizardStep::Review => "Enter start • ← back • ? help",
    };
    let para = Paragraph::new(text).style(theme::hint_style());
    frame.render_widget(para, area);
}

/// Handle a key while on the wizard. Delegates to the active step's editor.
pub fn handle_wizard_key(app: &mut App, code: KeyCode) {
    match app.wizard_step {
        WizardStep::Ranges => handle_ranges_key(app, code),
        WizardStep::Settings => handle_settings_key(app, code),
        WizardStep::Review => handle_review_key(app, code),
    }
}

fn handle_ranges_key(app: &mut App, code: KeyCode) {
    if app.custom_input_mode {
        match code {
            KeyCode::Enter => {
                let s = app.input_buffer.trim().to_string();
                if s.is_empty() {
                    app.custom_input_mode = false;
                    app.input_buffer.clear();
                    app.edit_caret = 0;
                    return;
                }
                match crate::scanner::cidr_valid(&s) {
                    Ok(_) => {
                        app.cidr_candidates.push(crate::tui::CidrEntry {
                            cidr: s.clone(),
                            selected: true,
                        });
                        app.input_buffer.clear();
                        app.edit_caret = 0;
                        app.custom_input_mode = false;
                        app.toast(format!("Added {s}"));
                    }
                    Err(e) => app.toast(format!("Invalid CIDR '{s}': {e}")),
                }
            }
            KeyCode::Esc => {
                app.custom_input_mode = false;
                app.input_buffer.clear();
                app.edit_caret = 0;
            }
            KeyCode::Backspace
                if app.edit_caret > 0 => {
                    app.edit_caret -= 1;
                    app.input_buffer.remove(app.edit_caret);
                }
            KeyCode::Delete
                if app.edit_caret < app.input_buffer.len() => {
                    app.input_buffer.remove(app.edit_caret);
                }
            KeyCode::Left
                if app.edit_caret > 0 => {
                    app.edit_caret -= 1;
                }
            KeyCode::Right
                if app.edit_caret < app.input_buffer.len() => {
                    app.edit_caret += 1;
                }
            KeyCode::Home => app.edit_caret = 0,
            KeyCode::End => app.edit_caret = app.input_buffer.len(),
            KeyCode::Char(c) => {
                app.input_buffer.insert(app.edit_caret, c);
                app.edit_caret += 1;
            }
            _ => {}
        }
        return;
    }

    match code {
        KeyCode::Up | KeyCode::Char('k')
            if app.cursor > 0 => {
                app.cursor -= 1;
            }
        KeyCode::Down | KeyCode::Char('j') => {
            let last = app.cidr_candidates.len().saturating_sub(1);
            if app.cursor < last {
                app.cursor += 1;
            }
        }
        KeyCode::Char(' ') => {
            if let Some(e) = app.cidr_candidates.get_mut(app.cursor) {
                e.selected = !e.selected;
            }
        }
        KeyCode::Char('a') => {
            app.custom_input_mode = true;
            app.input_buffer.clear();
            app.edit_caret = 0;
        }
        KeyCode::Char('A') => {
            for e in app.cidr_candidates.iter_mut() {
                e.selected = true;
            }
        }
        KeyCode::Char('d') | KeyCode::Char('D') => {
            for e in app.cidr_candidates.iter_mut() {
                e.selected = false;
            }
        }
        KeyCode::Right | KeyCode::Enter
            if (app.wizard_step as usize) < 2 => {
                app.wizard_step = WizardStep::Settings;
                app.cursor = 0;
            }
        _ => {}
    }
}

fn handle_settings_key(app: &mut App, code: KeyCode) {
    if app.edit_field.is_some() {
        let i = app.edit_field.unwrap();
        let field = SettingField::ALL[i];
        match code {
            KeyCode::Enter => {
                match field.apply(&app.edit_buffer, &mut app.config) {
                    Ok(()) => {
                        app.edit_field = None;
                        app.edit_buffer.clear();
                        app.edit_caret = 0;
                    }
                    Err(e) => app.toast(format!("Invalid {}: {}", field.label(), e)),
                }
            }
            KeyCode::Esc => {
                app.edit_field = None;
                app.edit_buffer.clear();
                app.edit_caret = 0;
            }
            KeyCode::Backspace
                if app.edit_caret > 0 => {
                    app.edit_caret -= 1;
                    app.edit_buffer.remove(app.edit_caret);
                }
            KeyCode::Delete
                if app.edit_caret < app.edit_buffer.len() => {
                    app.edit_buffer.remove(app.edit_caret);
                }
            KeyCode::Left
                if app.edit_caret > 0 => {
                    app.edit_caret -= 1;
                }
            KeyCode::Right
                if app.edit_caret < app.edit_buffer.len() => {
                    app.edit_caret += 1;
                }
            KeyCode::Home => app.edit_caret = 0,
            KeyCode::End => app.edit_caret = app.edit_buffer.len(),
            KeyCode::Up | KeyCode::Down if field.is_numeric() => {
                let delta = if code == KeyCode::Up { field.step() } else { -field.step() };
                if let Ok(v) = app.edit_buffer.parse::<i64>() {
                    let nv = (v + delta).max(1);
                    app.edit_buffer = nv.to_string();
                    app.edit_caret = app.edit_buffer.len();
                }
            }
            KeyCode::Char(c) => {
                app.edit_buffer.insert(app.edit_caret, c);
                app.edit_caret += 1;
            }
            _ => {}
        }
        return;
    }

    match code {
        KeyCode::Up | KeyCode::Char('k')
            if app.cursor > 0 => {
                app.cursor -= 1;
            }
        KeyCode::Down | KeyCode::Char('j') => {
            let last = SettingField::ALL.len().saturating_sub(1);
            if app.cursor < last {
                app.cursor += 1;
            }
        }
        KeyCode::Right
            if (app.wizard_step as usize) < 2 => {
                app.wizard_step = WizardStep::Review;
                app.cursor = 0;
            }
        KeyCode::Left | KeyCode::Esc => {
            app.wizard_step = WizardStep::Ranges;
            app.cursor = 0;
        }
        KeyCode::Enter => {
            app.start_edit(app.cursor);
        }
        _ => {}
    }
}

fn handle_review_key(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Enter => {
            app.pending_start = true;
        }
        KeyCode::Left | KeyCode::Esc => {
            app.wizard_step = WizardStep::Settings;
            app.cursor = 0;
        }
        _ => {}
    }
}

impl App {
    /// Begin editing the setting at `idx` (used by keyboard Enter and mouse click).
    pub fn start_edit(&mut self, idx: usize) {
        if idx < SettingField::ALL.len() {
            let field = SettingField::ALL[idx];
            self.edit_field = Some(idx);
            self.edit_buffer = field.value_string(&self.config);
            self.edit_caret = self.edit_buffer.len();
        }
    }
}
