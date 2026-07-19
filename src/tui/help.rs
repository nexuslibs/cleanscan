use ratatui::{
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};
use std::time::Duration;

use crate::tui::{modal_overlay, theme, App, Screen, WizardStep};

/// Render a context-aware help overlay. Closed by any key (`?` toggles).
pub fn overlay(app: &mut App, frame: &mut Frame, area: Rect, elapsed: Duration) {
    let overlay = modal_overlay(" Help — ? / Esc / q to close ", 64, 70);
    if app.show_help {
        app.help_overlay.open();
    } else {
        app.help_overlay.close();
    }
    app.help_overlay.tick(elapsed);
    frame.render_stateful_widget(overlay, area, &mut app.help_overlay);
    let Some(inner) = app.help_overlay.inner_area() else {
        return;
    };

    let lines: Vec<Line> = match app.screen {
        Screen::Wizard => wizard_lines(app.wizard_step),
        Screen::Scanning => scanning_lines(app),
        Screen::SpeedSelect => speed_selection_lines(),
        Screen::SpeedTesting => speed_testing_lines(),
        Screen::SpeedResults => speed_results_lines(),
    };

    let para = Paragraph::new(lines).style(Style::default());
    frame.render_widget(para, inner);
}

fn key(keys: &str, desc: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("  {:<16}", keys), theme::highlight_style()),
        Span::raw(desc.to_string()),
    ])
}

fn wizard_lines(step: WizardStep) -> Vec<Line<'static>> {
    let mut v = vec![
        Line::from(Span::styled(" Wizard navigation", theme::header_style())),
        key("↑ / ↓  or  k / j", "Move cursor through the list"),
        key("Tab / Shift+Tab", "Move focus between controls"),
        key("Enter / Esc", "Activate or go back"),
        key("/", "Search the command palette"),
        key("?  Esc  q", "Close this help"),
        key("q", "Quit cleanscan"),
        Line::from(""),
    ];
    match step {
        WizardStep::Ranges => {
            v.push(Line::from(Span::styled(
                " Step 1 — CIDR ranges",
                theme::header_style(),
            )));
            v.push(key("Space", "Toggle the highlighted range"));
            v.push(key("a", "Add a custom CIDR range"));
            v.push(key("A", "Select all ranges"));
            v.push(key("N / n / d", "Deselect all ranges"));
            v.push(key("c", "Jump to scan parameters"));
            v.push(key("Enter", "Edit or activate the focused control"));
            v.push(key("↑ / ↓", "Move through ranges"));
            v.push(key("Esc", "Cancel custom CIDR entry"));
        }
        WizardStep::Settings => {
            v.push(Line::from(Span::styled(
                " Step 2 — Scan parameters",
                theme::header_style(),
            )));
            v.push(key("Enter", "Edit the highlighted parameter"));
            v.push(key("← / →", "Move the text cursor while editing"));
            v.push(key("↑ / ↓", "Move between parameters"));
            v.push(key("↑ / ↓ while editing", "Step a numeric value up / down"));
            v.push(key("Backspace / Del", "Delete a character"));
            v.push(key("Enter", "Confirm edit   Esc: cancel edit"));
        }
        WizardStep::Review => {
            v.push(Line::from(Span::styled(
                " Step 3 — Review & start",
                theme::header_style(),
            )));
            v.push(key("Enter", "Start the scan with the chosen settings"));
        }
    }
    v.push(Line::from(""));
    v.push(Line::from(Span::styled(
        " Mouse: click a row/button to activate; scroll to navigate",
        theme::hint_style(),
    )));
    v
}

fn scanning_lines(app: &App) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(Span::styled(" Scanning dashboard", theme::header_style())),
        key("↑ / ↓", "Select a result IP"),
        key("c", "Copy the selected IP"),
        key("PageUp / PageDn", "Scroll by a page"),
        key("Home / End", "Jump to top / bottom"),
        key("Tab", "Focus table and action buttons"),
        key("Enter", "Open full details for the selected IP"),
        key("1–5 / Tab", "Switch detail tabs in the selected-IP modal"),
    ];

    if app.scan_complete {
        lines.push(key("e", "Export results to a .tsv file"));
        lines.push(key("t", "Run speed tests on successful IPs"));
        lines.push(key("f", "Show failed targets for diagnosis"));
        lines.push(key("r", "Repeat the identical sampled target set"));
        lines.push(key("n", "Generate a new sample with the same settings"));
        lines.push(key("m", "Export runs for comparison"));
    } else {
        lines.push(key("p", "Pause / resume the scan"));
    }

    lines.extend([
        key("Click header", "Sort results by that column"),
        key("Mouse wheel", "Scroll the results table"),
        key("?  Esc  q", "Close this help"),
        key("q", "Quit (press twice while scanning)"),
        Line::from(""),
        Line::from(Span::styled(
            " Colors: green = fast, yellow = ok, red = slow/failing",
            theme::hint_style(),
        )),
    ]);

    lines
}

fn speed_selection_lines() -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled(
            " Speed-test target selection",
            theme::header_style(),
        )),
        key("↑ / ↓", "Move through successful IPs"),
        key("Space / click", "Toggle the highlighted IP"),
        key("a / x", "Select all / clear selection"),
        key("d / u / b", "Direction: download / upload / both"),
        key("Tab", "Focus list, options, and actions"),
        key("Enter", "Activate the focused control"),
        key("Esc", "Return to latency results"),
        key("q", "Quit cleanscan"),
    ]
}

fn speed_testing_lines() -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled(" Speed tests running", theme::header_style())),
        key("q", "Quit cleanscan"),
    ]
}

fn speed_results_lines() -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled(" Speed-test results", theme::header_style())),
        key("↑ / ↓", "Select a result IP"),
        key("c", "Copy the selected IP"),
        key("Esc / b", "Return to latency results"),
        key("q", "Quit cleanscan"),
    ]
}
