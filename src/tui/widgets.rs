//! Reusable presentation components shared across screens: a unified status
//! bar, modal/backdrop helpers, animated spinner, severity-tagged toasts and
//! consistent button styling.

use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
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
            format!(" {} ", title.trim()),
            theme::panel_title_style(),
        ));
    }
    block
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
            .add_modifier(Modifier::BOLD),
        (ButtonKind::Secondary, false) => Style::default().fg(p.subtitle),
    }
}

/// Render a single-line status bar: left-aligned key hints plus, when present,
/// a severity-colored toast. Shared by every screen for a consistent footer.
pub fn status_bar(frame: &mut Frame, area: Rect, hints: &str, toast: Option<(&str, ToastKind)>) {
    let mut spans = Vec::new();
    if let Some((msg, kind)) = toast {
        spans.push(Span::styled(
            format!(" {} {} ", kind.glyph(), msg),
            kind.style(),
        ));
        spans.push(Span::styled("  ", theme::hint_style()));
    }
    spans.push(Span::styled(hints.to_string(), theme::hint_style()));
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Dim every cell in `area` so a modal on top reads as the focused layer.
pub fn dim_backdrop(frame: &mut Frame, area: Rect) {
    let buf = frame.buffer_mut();
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            if let Some(cell) = buf.cell_mut((x, y)) {
                cell.set_style(
                    Style::default()
                        .add_modifier(Modifier::DIM)
                        .fg(theme::palette().muted),
                );
            }
        }
    }
}

/// Prepare a centered modal panel: dim the backdrop, clear the popup region and
/// draw a titled, accented block. Returns the inner content rect.
pub fn modal(frame: &mut Frame, area: Rect, popup: Rect, title: &str) -> Rect {
    dim_backdrop(frame, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(ratatui::symbols::border::ROUNDED)
        .border_style(theme::border_active_style())
        .title(Span::styled(title.to_string(), theme::header_style()));
    let inner = block.inner(popup);
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);
    inner
}

#[cfg(test)]
mod tests {
    use super::{spinner_frame, ToastKind, SPINNER_FRAMES};

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
