use ratatui::style::{Color, Modifier, Style};

pub fn header_style() -> Style {
    Style::default()
        .fg(Color::LightBlue)
        .add_modifier(Modifier::BOLD)
}

pub fn title_style() -> Style {
    Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD)
}

pub fn subtitle_style() -> Style {
    Style::default().fg(Color::Blue)
}

pub fn hint_style() -> Style {
    Style::default().fg(Color::DarkGray)
}

pub fn highlight_style() -> Style {
    Style::default()
        .fg(Color::Magenta)
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
        "DONE" => good_style().add_modifier(Modifier::BOLD),
        "PAUSED" => warn_style().add_modifier(Modifier::BOLD),
        _ => Style::default()
            .fg(Color::LightCyan)
            .add_modifier(Modifier::BOLD),
    }
}

pub fn border_style() -> Style {
    Style::default().fg(Color::DarkGray)
}

pub fn border_active_style() -> Style {
    Style::default().fg(Color::LightBlue)
}

/// Color a latency value (in milliseconds) so good/ok/bad are visually distinct.
pub fn latency_style(ms: f64) -> Style {
    if ms < 80.0 {
        good_style()
    } else if ms < 200.0 {
        warn_style()
    } else {
        bad_style()
    }
}
