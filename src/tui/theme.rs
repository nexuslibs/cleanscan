use ratatui::style::{Color, Modifier, Style};

pub fn header_style() -> Style {
    Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD)
}

pub fn title_style() -> Style {
    Style::default().fg(Color::Cyan)
}

pub fn hint_style() -> Style {
    Style::default().fg(Color::DarkGray)
}

pub fn highlight_style() -> Style {
    Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD)
}

pub fn good_style() -> Style {
    Style::default().fg(Color::Green)
}

pub fn warn_style() -> Style {
    Style::default().fg(Color::Yellow)
}

pub fn bad_style() -> Style {
    Style::default().fg(Color::Red)
}

pub fn status_style(code: &str) -> Style {
    match code {
        "DONE" => good_style(),
        "PAUSED" => warn_style(),
        _ => Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
    }
}

/// Color a latency value (in milliseconds) so good/ok/bad are visually distinct.
pub fn latency_style(ms: f64) -> Style {
    if ms < 80.0 {
        good_style()
    } else if ms < 250.0 {
        warn_style()
    } else {
        bad_style()
    }
}
