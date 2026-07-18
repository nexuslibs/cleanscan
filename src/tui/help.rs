use ratatui::{
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

use crate::tui::{centered, theme, widgets, App, Screen, WizardStep};

/// Render a context-aware help overlay. Closed by any key (`?` toggles).
pub fn overlay(app: &App, frame: &mut Frame, area: Rect) {
    let lines: Vec<Line> = match app.screen {
        Screen::Wizard => wizard_lines(app.wizard_step),
        Screen::Scanning => scanning_lines(),
        Screen::SpeedSelect => speed_selection_lines(),
        Screen::SpeedTesting => speed_testing_lines(),
        Screen::SpeedResults => speed_results_lines(),
    };

    let popup = centered(area, 64, 70);
    let inner = widgets::modal(frame, area, popup, " Help — press any key to close ");
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
        key("→  or  Enter", "Go to the next step"),
        key("←  or  Esc", "Go back to the previous step"),
        key("?  or  any key", "Toggle / close this help"),
        key("q", "Quit cleanscan"),
        Line::from(""),
    ];
    match step {
        WizardStep::Ranges => {
            v.push(Line::from(Span::styled(
                " Step 1 — CIDR ranges",
                theme::header_style(),
            )));
            v.push(key("space", "Toggle the highlighted range on/off"));
            v.push(key("A", "Select all ranges"));
            v.push(key("N", "Deselect all ranges"));
            v.push(key("a", "Add a custom CIDR (type + Enter)"));
            v.push(key("c", "Jump to the settings step"));
            v.push(key("Esc", "Cancel custom CIDR entry"));
        }
        WizardStep::Settings => {
            v.push(Line::from(Span::styled(
                " Step 2 — Scan parameters",
                theme::header_style(),
            )));
            v.push(key("Enter", "Edit the highlighted parameter"));
            v.push(key("← / →", "Move the text cursor while editing"));
            v.push(key("↑ / ↓", "Step a numeric value up / down"));
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

fn scanning_lines() -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled(" Scanning dashboard", theme::header_style())),
        key("↑ / ↓", "Select a result IP"),
        key("c", "Copy the selected IP"),
        key("PageUp / PageDn", "Scroll by a page"),
        key("Home / End", "Jump to top / bottom"),
        key("space  or  p", "Pause / resume the scan"),
        key("s", "Save results to a .tsv file (when done)"),
        key("v", "Select successful IPs for upload/download speed tests"),
        key("Click header", "Sort results by that column"),
        key("Mouse wheel", "Scroll the results table"),
        key("?  or  any key", "Toggle / close this help"),
        key("q", "Quit (press twice while scanning)"),
        Line::from(""),
        Line::from(Span::styled(
            " Colors: green = fast, yellow = ok, red = slow/failing",
            theme::hint_style(),
        )),
    ]
}

fn speed_selection_lines() -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled(
            " Speed-test target selection",
            theme::header_style(),
        )),
        key("↑ / ↓", "Move through successful IPs"),
        key("Space / click", "Toggle the highlighted IP"),
        key("a / N", "Select all / clear selection"),
        key("d / u / b", "Direction: download / upload / both"),
        key("Enter", "Start tests"),
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
