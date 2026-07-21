use std::sync::OnceLock;

use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::border;

/// Border glyph set used for every panel and control, app-wide.
pub const BORDER_SET: border::Set = border::ROUNDED;

/// Terminal color capability, detected once at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ColorMode {
    /// 24-bit RGB ("truecolor") terminals — the premium look.
    TrueColor,
    /// Classic 16-color ANSI terminals.
    Ansi16,
    /// `NO_COLOR` requested: rely on bold/dim modifiers only.
    None,
}

/// Semantic color tokens for the whole UI. All screens style through these,
/// so the entire app can be re-skinned from one place.
#[derive(Debug, Clone, Copy)]
pub struct Palette {
    /// Primary brand accent (headers, active borders, focus).
    pub accent: Color,
    /// Section / label emphasis.
    pub title: Color,
    /// Secondary emphasis.
    pub subtitle: Color,
    /// De-emphasized text (hints, inactive rows).
    pub muted: Color,
    /// Selection / interactive highlight.
    pub highlight: Color,
    /// Good / fast / success.
    pub success: Color,
    /// Caution / medium.
    pub warn: Color,
    /// Bad / slow / failure.
    pub danger: Color,
    /// Informational / live status.
    pub info: Color,
    /// Idle container borders.
    pub border: Color,
    /// Active / focused container borders.
    pub border_active: Color,
    /// Full-row selection fill.
    pub sel_bg: Color,
    /// Subtle alternating (zebra) row fill.
    pub row_alt: Color,
    /// The single fastest / "best" edge highlight (paired with a ★ glyph so it
    /// still reads under NO_COLOR).
    pub best: Color,
}

impl Palette {
    /// Curated dark, truecolor palette (slate surfaces + a vivid accent).
    const fn truecolor() -> Self {
        Self {
            accent: Color::Rgb(0x58, 0xa6, 0xff),
            title: Color::Rgb(0x79, 0xc0, 0xff),
            subtitle: Color::Rgb(0xa5, 0xd6, 0xff),
            muted: Color::Rgb(0x6e, 0x76, 0x81),
            highlight: Color::Rgb(0xd2, 0xa8, 0xff),
            success: Color::Rgb(0x3f, 0xb9, 0x50),
            warn: Color::Rgb(0xd2, 0x99, 0x22),
            danger: Color::Rgb(0xf8, 0x51, 0x49),
            info: Color::Rgb(0x56, 0xd4, 0xdd),
            border: Color::Rgb(0x30, 0x36, 0x3d),
            border_active: Color::Rgb(0x58, 0xa6, 0xff),
            sel_bg: Color::Rgb(0x1f, 0x2a, 0x3d),
            row_alt: Color::Rgb(0x16, 0x1b, 0x22),
            best: Color::Rgb(0x56, 0xd4, 0xdd),
        }
    }

    /// 16-color fallback that mirrors the original look.
    const fn ansi16() -> Self {
        Self {
            accent: Color::LightBlue,
            title: Color::Cyan,
            subtitle: Color::Blue,
            muted: Color::DarkGray,
            highlight: Color::Magenta,
            success: Color::Green,
            warn: Color::Yellow,
            danger: Color::Red,
            info: Color::LightCyan,
            border: Color::DarkGray,
            border_active: Color::LightBlue,
            sel_bg: Color::Blue,
            row_alt: Color::Reset,
            best: Color::LightCyan,
        }
    }

    /// Colorless palette: everything defaults; distinction comes from modifiers.
    const fn none() -> Self {
        Self {
            accent: Color::Reset,
            title: Color::Reset,
            subtitle: Color::Reset,
            muted: Color::Reset,
            highlight: Color::Reset,
            success: Color::Reset,
            warn: Color::Reset,
            danger: Color::Reset,
            info: Color::Reset,
            border: Color::Reset,
            border_active: Color::Reset,
            sel_bg: Color::Reset,
            row_alt: Color::Reset,
            best: Color::Reset,
        }
    }
}

fn detect_mode() -> ColorMode {
    // Honor the NO_COLOR convention (https://no-color.org/).
    if std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()) {
        return ColorMode::None;
    }
    // COLORTERM=truecolor|24bit is the de-facto truecolor signal.
    if let Ok(ct) = std::env::var("COLORTERM") {
        let ct = ct.to_ascii_lowercase();
        if ct.contains("truecolor") || ct.contains("24bit") {
            return ColorMode::TrueColor;
        }
    }
    // Some modern terminals advertise capability via TERM.
    if let Ok(term) = std::env::var("TERM") {
        if term.contains("truecolor") || term.contains("direct") {
            return ColorMode::TrueColor;
        }
    }
    ColorMode::Ansi16
}

/// The active palette, resolved once from the environment.
pub fn palette() -> &'static Palette {
    static PALETTE: OnceLock<Palette> = OnceLock::new();
    PALETTE.get_or_init(|| match detect_mode() {
        ColorMode::TrueColor => Palette::truecolor(),
        ColorMode::Ansi16 => Palette::ansi16(),
        ColorMode::None => Palette::none(),
    })
}

pub fn header_style() -> Style {
    Style::default()
        .fg(palette().accent)
        .add_modifier(Modifier::BOLD)
}

pub fn title_style() -> Style {
    Style::default()
        .fg(palette().title)
        .add_modifier(Modifier::BOLD)
}

pub fn subtitle_style() -> Style {
    Style::default().fg(palette().subtitle)
}

pub fn hint_style() -> Style {
    Style::default().fg(palette().muted)
}

pub fn highlight_style() -> Style {
    Style::default()
        .fg(palette().highlight)
        .add_modifier(Modifier::BOLD)
}

pub fn good_style() -> Style {
    Style::default().fg(palette().success)
}

pub fn warn_style() -> Style {
    Style::default().fg(palette().warn)
}

/// Highlight for the single fastest edge. Pairs a distinct color with BOLD so
/// the row still stands out on ANSI-16 terminals and under NO_COLOR (where the
/// accompanying ★ glyph carries the meaning).
pub fn best_style() -> Style {
    Style::default()
        .fg(palette().best)
        .add_modifier(Modifier::BOLD)
}

pub fn bad_style() -> Style {
    Style::default().fg(palette().danger)
}

pub fn status_style(code: &str) -> Style {
    match code {
        "DONE" => good_style().add_modifier(Modifier::BOLD),
        "PAUSED" => warn_style().add_modifier(Modifier::BOLD),
        "CANCELLING" | "CANCELLED" => warn_style().add_modifier(Modifier::BOLD),
        "FAILED" => bad_style().add_modifier(Modifier::BOLD),
        _ => Style::default()
            .fg(palette().info)
            .add_modifier(Modifier::BOLD),
    }
}

pub fn border_style() -> Style {
    Style::default().fg(palette().border)
}

pub fn border_active_style() -> Style {
    Style::default().fg(palette().border_active)
}

/// Styled title for a panel header (used with rounded panel blocks).
pub fn panel_title_style() -> Style {
    Style::default()
        .fg(palette().subtitle)
        .add_modifier(Modifier::BOLD)
}

/// Full-width background fill for the selected/active row in a list or table.
pub fn row_selected_style() -> Style {
    let mut style = Style::default()
        .bg(palette().sel_bg)
        .fg(palette().title)
        .add_modifier(Modifier::BOLD);
    if no_color() {
        style = style.add_modifier(Modifier::REVERSED);
    }
    style
}

/// Subtle alternating (zebra) row fill for even rows in dense tables.
pub fn row_alt_style() -> Style {
    Style::default().bg(palette().row_alt)
}

pub fn no_color() -> bool {
    std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty())
}

/// Color a latency value (in milliseconds) so good/ok/bad are visually distinct.
pub fn latency_style(ms: f64) -> Style {
    if ms < LATENCY_GOOD_MS {
        good_style()
    } else if ms < LATENCY_WARN_MS {
        warn_style()
    } else {
        bad_style()
    }
}

pub const LATENCY_GOOD_MS: f64 = 80.0;
pub const LATENCY_WARN_MS: f64 = 200.0;
