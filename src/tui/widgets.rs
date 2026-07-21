//! Reusable presentation components shared across screens: a unified status
//! bar, modal/backdrop helpers, animated spinner, severity-tagged toasts and
//! consistent button styling.

use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::tui::theme;

/// Severity of a transient toast message; drives its color in the status bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ToastKind {
    #[default]
    Info,
    Success,
    Warn,
    Error,
}

impl ToastKind {
    /// Styling for the toast text.
    pub fn style(self) -> Style {
        let base = match self {
            ToastKind::Info => theme::status_style("SCANNING"),
            ToastKind::Success => theme::good_style(),
            ToastKind::Warn => theme::warn_style(),
            ToastKind::Error => theme::bad_style(),
        };
        base.add_modifier(Modifier::BOLD)
    }

    /// Leading glyph that reinforces severity without relying on color alone.
    pub fn glyph(self) -> &'static str {
        match self {
            ToastKind::Info => "•",
            ToastKind::Success => "✓",
            ToastKind::Warn => "!",
            ToastKind::Error => "✗",
        }
    }
}

/// Visual weight of an action button.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonKind {
    /// The recommended / default action (filled when active).
    Primary,
    /// Supporting actions.
    Secondary,
}

const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// A titled, rounded container block styled from the theme. `focused` panels use
/// the active border color; all others use the idle border color. Passing an
/// empty title renders a borderless-titled panel.
pub fn panel_block(title: &str, focused: bool) -> Block<'static> {
    let mut block = Block::default()
        .borders(Borders::ALL)
        .border_set(theme::BORDER_SET)
        .border_style(if focused {
            theme::border_active_style()
        } else {
            theme::border_style()
        });
    if !title.is_empty() {
        block = block.title(Span::styled(
            format!(" {}{} ", if focused { "› " } else { "" }, title.trim()),
            theme::panel_title_style(),
        ));
    }
    block
}

/// A low-weight section container for supporting information. Primary panels
/// retain the rounded treatment; secondary content uses a bottom rule so the
/// screen has hierarchy without making every region feel like a separate card.
pub fn subtle_panel_block(title: &str) -> Block<'static> {
    Block::default()
        .borders(Borders::BOTTOM)
        .border_style(theme::border_style())
        .title(Span::styled(
            format!(" {} ", title.trim()),
            theme::panel_title_style(),
        ))
}

/// A key/value segment rendered in the shared app header.
pub struct HeaderSegment {
    pub label: String,
    pub value: String,
    pub style: Style,
}

impl HeaderSegment {
    pub fn new(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
            style: theme::hint_style(),
        }
    }
}

/// Render the shared application header: a brand+version badge, an optional
/// status chip, then a series of `key: value` segments separated by dividers.
/// Unifies the top bar across every screen.
pub fn app_header(
    frame: &mut Frame,
    area: Rect,
    status: Option<(&str, Style)>,
    segments: &[HeaderSegment],
) {
    let mut spans = vec![Span::styled(
        format!(" CLEANSCAN v{} ", env!("CARGO_PKG_VERSION")),
        theme::header_style(),
    )];

    if let Some((text, style)) = status {
        spans.push(Span::styled("│", theme::hint_style()));
        spans.push(Span::styled(format!(" {text} "), style));
    }

    for seg in segments {
        spans.push(Span::styled("│", theme::hint_style()));
        if seg.label.is_empty() {
            spans.push(Span::styled(format!(" {} ", seg.value), seg.style));
        } else {
            spans.push(Span::styled(
                format!(" {}: ", seg.label),
                theme::hint_style(),
            ));
            spans.push(Span::styled(format!("{} ", seg.value), seg.style));
        }
    }

    let para = Paragraph::new(Line::from(spans)).block(panel_block("", false));
    frame.render_widget(para, area);
}

/// Current spinner glyph for an animation `tick` (advances once per frame).
pub fn spinner_frame(tick: u64) -> &'static str {
    SPINNER_FRAMES[(tick as usize) % SPINNER_FRAMES.len()]
}

/// Render the shared brand badge followed by a numbered step progress strip,
/// matching `app_header`'s look so the setup wizard is visually consistent with
/// every other screen. Completed steps are checked, the active step is
/// emphasized, and upcoming steps are dimmed.
pub fn stepper_header(frame: &mut Frame, area: Rect, steps: &[&str], current: usize) {
    let mut spans = vec![Span::styled(
        format!(" CLEANSCAN v{} ", env!("CARGO_PKG_VERSION")),
        theme::header_style(),
    )];
    for (i, label) in steps.iter().enumerate() {
        spans.push(Span::styled(" │", theme::hint_style()));
        let (marker, style) = if i < current {
            ("✓", theme::good_style())
        } else if i == current {
            ("▸", theme::highlight_style())
        } else {
            (" ", theme::hint_style())
        };
        spans.push(Span::styled(format!(" {marker} {}·{label} ", i + 1), style));
    }
    let para = Paragraph::new(Line::from(spans)).block(panel_block("", false));
    frame.render_widget(para, area);
}

/// Style for a button given its kind and whether it is active (focused/hovered).
pub fn button_style(kind: ButtonKind, active: bool) -> Style {
    let p = theme::palette();
    match (kind, active) {
        (ButtonKind::Primary, true) => Style::default()
            .bg(p.accent)
            .fg(p.row_alt)
            .add_modifier(Modifier::BOLD),
        (ButtonKind::Primary, false) => Style::default().fg(p.accent).add_modifier(Modifier::BOLD),
        (ButtonKind::Secondary, true) => Style::default()
            .fg(p.highlight)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        (ButtonKind::Secondary, false) => Style::default().fg(p.subtitle),
    }
}

/// A single key/action hint chip: the key(s) to press and the resulting action.
pub type KeyHint = (&'static str, &'static str);

/// Build a styled, single-line hint strip from key/action pairs. Each chip
/// renders the key emphasized followed by its action, chips separated by a
/// subtle divider. The strip is truncated to `max_width` columns (marked with
/// an ellipsis) so it never overflows on a narrow terminal.
pub fn hint_line(hints: &[KeyHint], max_width: u16) -> Line<'static> {
    const SEP: &str = "  ";
    let budget = max_width as usize;
    let sep_len = SEP.chars().count();
    let mut spans: Vec<Span> = Vec::new();
    let mut used = 0usize;
    let mut truncated = false;

    for (i, (keys, action)) in hints.iter().enumerate() {
        // ` key action` per chip; +1 for the space between key and action.
        let chip_len = keys.chars().count() + 1 + action.chars().count();
        let lead = if i == 0 { 0 } else { sep_len };
        // Reserve one column for a possible trailing ellipsis.
        if i > 0 && used + lead + chip_len > budget.saturating_sub(2) {
            truncated = true;
            break;
        }
        if i > 0 {
            spans.push(Span::styled(SEP, theme::hint_style()));
            used += lead;
        }
        spans.push(Span::styled(format!("{keys} "), theme::highlight_style()));
        spans.push(Span::styled(action.to_string(), theme::hint_style()));
        used += chip_len;
    }
    if truncated {
        spans.push(Span::styled(" …", theme::hint_style()));
    }
    Line::from(spans)
}

/// Render a single-line status bar: a severity-colored toast (when present)
/// followed by key/action hint chips that truncate to fit the width. Shared by
/// every screen for a consistent footer.
pub fn status_bar(
    frame: &mut Frame,
    area: Rect,
    hints: &[KeyHint],
    toast: Option<(&str, ToastKind)>,
) {
    let mut spans = Vec::new();
    let mut used = 0usize;
    if let Some((msg, kind)) = toast {
        let text = format!(" {} {} ", kind.glyph(), msg);
        used += text.chars().count() + 2;
        spans.push(Span::styled(text, kind.style()));
        spans.push(Span::styled("  ", theme::hint_style()));
    }
    let remaining = (area.width as usize).saturating_sub(used) as u16;
    let hint = hint_line(hints, remaining);
    spans.extend(hint.spans);
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

#[cfg(test)]
mod tests {
    use super::{hint_line, spinner_frame, ToastKind, SPINNER_FRAMES};

    fn line_text(line: &ratatui::text::Line) -> String {
        line.spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect::<String>()
    }

    #[test]
    fn hint_line_shows_all_chips_when_width_is_ample() {
        let hints = [("Tab", "focus"), ("Enter", "details"), ("q", "quit")];
        let text = line_text(&hint_line(&hints, 100));
        assert!(text.contains("focus"));
        assert!(text.contains("details"));
        assert!(text.contains("quit"));
        assert!(!text.contains('…'));
    }

    #[test]
    fn hint_line_truncates_with_ellipsis_when_narrow() {
        let hints = [("Tab", "focus"), ("Enter", "details"), ("q", "quit")];
        let text = line_text(&hint_line(&hints, 12));
        // The first chip is always kept; the rest are dropped with an ellipsis.
        assert!(text.contains("focus"));
        assert!(text.contains('…'));
        assert!(!text.contains("quit"));
    }

    #[test]
    fn spinner_cycles_through_all_frames() {
        assert_eq!(spinner_frame(0), SPINNER_FRAMES[0]);
        assert_eq!(spinner_frame(1), SPINNER_FRAMES[1]);
        // Wraps around after the last frame.
        let len = SPINNER_FRAMES.len() as u64;
        assert_eq!(spinner_frame(len), SPINNER_FRAMES[0]);
        assert_eq!(spinner_frame(len + 3), SPINNER_FRAMES[3]);
    }

    #[test]
    fn toast_kinds_have_distinct_glyphs() {
        let glyphs = [
            ToastKind::Info.glyph(),
            ToastKind::Success.glyph(),
            ToastKind::Warn.glyph(),
            ToastKind::Error.glyph(),
        ];
        for (i, a) in glyphs.iter().enumerate() {
            for b in glyphs.iter().skip(i + 1) {
                assert_ne!(a, b, "glyphs must be visually distinct");
            }
        }
    }

    #[test]
    fn default_toast_kind_is_info() {
        assert_eq!(ToastKind::default(), ToastKind::Info);
    }
}
