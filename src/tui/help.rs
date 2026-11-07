use ratatui::{
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
    Frame,
};
use std::time::Duration;

use crate::tui::{modal_overlay, theme, App, Screen, WizardStep};

/// Width of the "key" prefix (2 leading spaces + 28-column key column).
const KEY_PREFIX: usize = 30;

/// Render a context-aware help overlay. It remains open until `?`, `Esc`, or
/// `q`, so navigation keys can be read without accidentally dismissing help.
pub fn overlay(app: &mut App, frame: &mut Frame, area: Rect, elapsed: Duration) {
    let overlay = modal_overlay(" Help — ? / Esc / q to close ", 72, 70);
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
    let width = inner.width as usize;

    let lines: Vec<Line> = match app.screen {
        Screen::Wizard => wizard_lines(app.wizard_step, width),
        Screen::Scanning => scanning_lines(app, width),
        Screen::SpeedSelect => speed_selection_lines(width),
        Screen::SpeedTesting => speed_testing_lines(width),
        Screen::SpeedResults => speed_results_lines(width),
        Screen::FragmentSelect => fragment_selection_lines(width),
        Screen::FragmentTesting => fragment_testing_lines(width),
        Screen::FragmentResults => fragment_results_lines(width),
    };

    let para = Paragraph::new(lines)
        .style(Style::default())
        // Long free-form explainer lines fold here; `key()` already wraps its
        // own description with a hanging indent so it survives untouched.
        .wrap(Wrap { trim: false });
    let max_scroll = para
        .line_count(inner.width)
        .saturating_sub(inner.height as usize);
    let scroll = app.help_scroll.min(max_scroll).min(u16::MAX as usize) as u16;
    let para = para.scroll((scroll, 0));
    frame.render_widget(para, inner);
}

/// Build one `key → description` entry, word-wrapping the description to the
/// overlay width with a hanging indent so it never runs into the key column
/// or collides with the overlay edge.
fn key(keys: &str, desc: &str, width: usize) -> Vec<Line<'static>> {
    let budget = width.saturating_sub(KEY_PREFIX).max(8);
    // Greedy word wrap by display-ish width (char count; entries are ASCII).
    let mut chunks: Vec<String> = Vec::new();
    let mut current = String::new();
    for word in desc.split_whitespace() {
        let extra = word.chars().count() + usize::from(!current.is_empty());
        if !current.is_empty() && current.chars().count() + extra > budget {
            chunks.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        chunks.push(current);
    }

    let mut out = Vec::with_capacity(chunks.len());
    for (index, chunk) in chunks.into_iter().enumerate() {
        if index == 0 {
            out.push(Line::from(vec![
                Span::styled(format!("  {:<28}", keys), theme::highlight_style()),
                Span::raw(chunk),
            ]));
        } else {
            out.push(Line::from(format!("{}{chunk}", " ".repeat(KEY_PREFIX))));
        }
    }
    out
}

/// Help lines for the wizard, with the step-specific keys for the current
/// wizard step (ranges, settings, or review) after the shared navigation.
fn wizard_lines(step: WizardStep, width: usize) -> Vec<Line<'static>> {
    let mut v = Vec::new();
    v.push(Line::from(Span::styled(
        " Wizard navigation",
        theme::header_style(),
    )));
    v.extend(key(
        "↑ / ↓  or  k / j",
        "Move cursor through the list",
        width,
    ));
    v.extend(key("Tab / Shift+Tab", "Move focus between controls", width));
    v.extend(key("Enter / Esc", "Activate or go back", width));
    v.extend(key(
        "↑ / ↓ / PgUp / PgDn / Home",
        "Scroll this help on short terminals",
        width,
    ));
    v.extend(key("/", "Search the command palette", width));
    v.extend(key("?  Esc  q", "Close this help", width));
    v.extend(key("q", "Quit cleanscan", width));
    v.push(Line::from(""));
    match step {
        WizardStep::Ranges => {
            v.push(Line::from(Span::styled(
                " Step 1 — CIDR ranges",
                theme::header_style(),
            )));
            v.extend(key("Space", "Toggle the highlighted range", width));
            v.extend(key("a", "Add a custom CIDR range", width));
            v.extend(key("A", "Select all ranges", width));
            v.extend(key("N / n", "Deselect all ranges", width));
            v.extend(key("e", "Edit the highlighted custom range", width));
            v.extend(key(
                "x",
                "Remove the highlighted custom range (twice to confirm)",
                width,
            ));
            v.extend(key("s", "Toggle full-range sweep (every address)", width));
            v.extend(key("c", "Jump to scan parameters", width));
            v.extend(key("Enter", "Edit or activate the focused control", width));
            v.extend(key("↑ / ↓", "Move through ranges", width));
            v.extend(key("Esc", "Cancel custom CIDR entry", width));
        }
        WizardStep::Settings => {
            v.push(Line::from(Span::styled(
                " Step 2 — Scan parameters",
                theme::header_style(),
            )));
            v.push(Line::from(
                "  Only 5 core fields show: Host, Ports, Sample, Probes, Concurrency",
            ));
            v.extend(key("Enter", "Edit the highlighted parameter", width));
            v.extend(key("← / →", "Move the text cursor while editing", width));
            v.extend(key("↑ / ↓", "Move between parameters", width));
            v.extend(key(
                "↑ / ↓ while editing",
                "Step a numeric value up / down",
                width,
            ));
            v.extend(key("Backspace / Del", "Delete a character", width));
            v.extend(key("Enter", "Confirm edit   Esc: cancel edit", width));
            v.extend(key("x", "Toggle advanced settings (34 more fields)", width));
            v.extend(key(
                "C",
                "Show the equivalent CLI command (c to copy)",
                width,
            ));
        }
        WizardStep::Review => {
            v.push(Line::from(Span::styled(
                " Step 3 — Review & start",
                theme::header_style(),
            )));
            v.extend(key(
                "s",
                "Regenerate the sampled preview with a new seed",
                width,
            ));
            v.extend(key(
                "c",
                "Save the sampled targets to cleanscan_targets_<seed>.txt",
                width,
            ));
            v.extend(key(
                "Enter",
                "Start the scan with the chosen settings",
                width,
            ));
            v.extend(key(
                "Tab + Enter",
                "Focus the CLI panel's Copy button, then copy the command",
                width,
            ));
            v.extend(key(
                "C",
                "Show the equivalent CLI command (c to copy)",
                width,
            ));
        }
    }
    v.push(Line::from(""));
    v.push(Line::from(Span::styled(
        " Mouse: click a row/button to activate; scroll to navigate",
        theme::hint_style(),
    )));
    v
}

/// Help lines for the scanning dashboard: view cycling, result/live/log
/// selection, target marking, and the contextual sorting keys.
fn scanning_lines(app: &App, width: usize) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    lines.push(Line::from(Span::styled(
        " Scanning dashboard",
        theme::header_style(),
    )));
    lines.extend(key("o", "Cycle Results / Live Targets / Run Log", width));
    lines.extend(key(
        "↑ / ↓",
        "Select a result, live target, or run log",
        width,
    ));
    lines.extend(key("Space", "Mark or unmark a target", width));
    lines.extend(key(
        "F (Live Targets)",
        "Cycle all / active / problems / selected",
        width,
    ));
    lines.extend(key(
        "S (Live Targets)",
        "Cycle attention / age / stage / IP sorting",
        width,
    ));
    lines.extend(key(
        "target:<text>",
        "Search live targets from the command palette",
        width,
    ));
    lines.extend(key("c", "Copy the selected IP", width));
    lines.extend(key("PageUp / PageDn", "Move by 10 rows", width));
    lines.extend(key("Home / End", "Jump to top / bottom", width));
    lines.extend(key("Tab", "Focus table and action buttons", width));
    lines.extend(key("Enter", "Open full details for the selected IP", width));
    lines.extend(key(
        "1–5 / Tab",
        "Switch detail tabs in the selected-IP modal",
        width,
    ));

    if app.scan_complete {
        lines.extend(key("e", "Export results to a .tsv file", width));
        lines.extend(key("t", "Run speed tests on successful IPs", width));
        lines.extend(key(
            "g",
            "Auto-test every TLS fragment profile on the selected IP",
            width,
        ));
        lines.extend(key(
            "G",
            "Open manual fragment profiles (custom IP / subset)",
            width,
        ));
        lines.extend(key("d", "Retest degraded and failed targets", width));
        lines.extend(key("f", "Show failed targets for diagnosis", width));
        lines.extend(key("v", "Show or hide result columns", width));
        lines.extend(key("r", "Repeat the identical sampled target set", width));
        lines.extend(key(
            "n",
            "Generate a new sample with the same settings",
            width,
        ));
        lines.extend(key("m", "Export runs for comparison", width));
        lines.extend(key("w", "Customize scan parameters and ranges", width));
        lines.extend(key("R", "Rerun the selected targets", width));
        lines.extend(key(
            "i",
            "Run an isolated investigation for the selected target",
            width,
        ));
    } else {
        lines.extend(key(
            "p",
            "Pause scheduling / resume; active probes drain",
            width,
        ));
        lines.extend(key(
            "i",
            "Isolate the selected target after active work drains",
            width,
        ));
        lines.extend(key("x", "Stop the scan and keep completed results", width));
        lines.extend(key(", / .", "Decrease / increase live worker count", width));
        lines.extend(key("[ / ]", "Decrease / increase workers by 8", width));
        lines.extend(key("0", "Return worker count to automatic control", width));
        lines.extend(key("f", "Show failed targets while scanning", width));
    }

    lines.extend(key("Click header", "Sort results by that column", width));
    lines.extend(key("Mouse wheel", "Scroll the results table", width));
    lines.extend(key("?  Esc  q", "Close this help", width));
    lines.extend(key("Esc", "Open quit confirmation or quit results", width));
    lines.extend(key("q", "Quit (press twice while scanning)", width));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        " Colors: green = fast, yellow = ok, red = slow/failing",
        theme::hint_style(),
    )));

    lines
}

fn speed_selection_lines(width: usize) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    lines.push(Line::from(Span::styled(
        " Speed-test target selection",
        theme::header_style(),
    )));
    lines.extend(key("↑ / ↓", "Move through successful IPs", width));
    lines.extend(key("Space / click", "Toggle the highlighted IP", width));
    lines.extend(key("a / x", "Select all / clear selection", width));
    lines.extend(key(
        "d / u / b",
        "Direction: download / upload / both",
        width,
    ));
    lines.extend(key("< / >", "Choose the sort column", width));
    lines.extend(key("s", "Reverse sort direction", width));
    lines.extend(key("Tab", "Focus list, options, and actions", width));
    lines.extend(key("Enter", "Activate the focused control", width));
    lines.extend(key("Esc", "Return to latency results", width));
    lines.extend(key("q", "Quit cleanscan", width));
    lines
}

fn speed_testing_lines(width: usize) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    lines.push(Line::from(Span::styled(
        " Speed tests running",
        theme::header_style(),
    )));
    lines.extend(key("Esc", "Cancel speed tests", width));
    lines.extend(key("q", "Quit cleanscan", width));
    lines
}

fn speed_results_lines(width: usize) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    lines.push(Line::from(Span::styled(
        " Speed-test results",
        theme::header_style(),
    )));
    lines.extend(key("↑ / ↓", "Select a result IP", width));
    lines.extend(key("c", "Copy the selected IP", width));
    lines.extend(key("Esc / b", "Return to latency results", width));
    lines.extend(key("q", "Quit cleanscan", width));
    lines
}

fn fragment_selection_lines(width: usize) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    lines.push(Line::from(Span::styled(
        " TLS fragment tester — profiles",
        theme::header_style(),
    )));
    lines.extend(key(
        "↑ / ↓",
        "Move between the IP field and profiles",
        width,
    ));
    lines.extend(key("Enter on IP", "Edit the target IP address", width));
    lines.extend(key(
        "Space / Enter on profile",
        "Enable or disable a profile",
        width,
    ));
    lines.extend(key(
        "Enter on Custom",
        "Paste custom fragment JSON (freedom, finalmask, or aether)",
        width,
    ));
    lines.extend(key("Tab", "Focus the list, Start, or Back", width));
    lines.extend(key("Enter on Start", "Run the enabled profiles", width));
    lines.extend(key("Esc", "Return to scan results", width));
    lines.extend(key("q", "Quit cleanscan", width));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        " Each profile is an xray `fragment` config: tlshello splits the TLS ClientHello into random-length fragments re-wrapped as TLS records. Interval 0 sends them combined in a single packet. Each profile is probed three times; a profile works when a majority of attempts pass TCP + TLS + an HTTP 2xx response and the connection survives the idle hold (DPI often resets a connection shortly after the handshake).",
        theme::hint_style(),
    )));
    lines
}

fn fragment_testing_lines(width: usize) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    lines.push(Line::from(Span::styled(
        " TLS fragment tests running",
        theme::header_style(),
    )));
    lines.extend(key("Esc", "Cancel the remaining profiles", width));
    lines.extend(key("q", "Quit cleanscan", width));
    lines
}

fn fragment_results_lines(width: usize) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    lines.push(Line::from(Span::styled(
        " TLS fragment results",
        theme::header_style(),
    )));
    lines.extend(key("↑ / ↓", "Select a profile result", width));
    lines.extend(key(
        "c",
        "Copy the profile's xray JSON to the clipboard",
        width,
    ));
    lines.extend(key("Esc / b", "Return to the profile list", width));
    lines.extend(key("q", "Quit cleanscan", width));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        " Paste the copied fragment object into your xray freedom outbound (and into Settings → TLS fragment to reuse it in protocol checks).",
        theme::hint_style(),
    )));
    lines
}
