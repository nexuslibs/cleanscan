use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
    Frame,
};

use crate::config::AppConfig;
use crate::tui::theme;
use crate::tui::{widgets, App, ButtonAction, ButtonKind, WizardStep};

/// Identifies an editable scan parameter on the settings step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingField {
    Host,
    Path,
    DownloadPath,
    UploadPath,
    SpeedPayloadMb,
    SpeedRepetitions,
    SpeedTimeoutMs,
    SamplePerCidr,
    Probes,
    Concurrency,
    TimeoutMs,
    ConnectTimeoutMs,
    Top,
}

const MAX_SAMPLE_PER_CIDR: usize = 10_000;
const MAX_PROBES: usize = 1_000;
const MAX_CONCURRENCY: usize = 10_000;
const MAX_TIMEOUT_MS: u64 = 600_000;
const MAX_CONNECT_TIMEOUT_MS: u64 = 600_000;
const MAX_TOP: usize = 10_000;
const MAX_SPEED_PAYLOAD_MB: u64 = 1_024;
const MAX_SPEED_REPETITIONS: usize = 100;
const MAX_SPEED_TIMEOUT_MS: u64 = 3_600_000;

impl SettingField {
    /// All settings fields in display order, grouped by concern. Group
    /// boundaries are described by [`SettingField::GROUPS`].
    pub const ALL: [SettingField; 13] = [
        // Target
        SettingField::Host,
        SettingField::Path,
        // Latency scan
        SettingField::SamplePerCidr,
        SettingField::Probes,
        SettingField::Concurrency,
        SettingField::TimeoutMs,
        SettingField::ConnectTimeoutMs,
        SettingField::Top,
        // Speed test
        SettingField::DownloadPath,
        SettingField::UploadPath,
        SettingField::SpeedPayloadMb,
        SettingField::SpeedRepetitions,
        SettingField::SpeedTimeoutMs,
    ];

    /// Section headers and the number of consecutive fields in each, in the
    /// same order as [`SettingField::ALL`].
    pub const GROUPS: [(&'static str, usize); 3] =
        [("Target", 2), ("Latency scan", 6), ("Speed test", 5)];

    pub fn label(&self) -> &'static str {
        match self {
            SettingField::Host => "Host",
            SettingField::Path => "Path",
            SettingField::DownloadPath => "Download path",
            SettingField::UploadPath => "Upload path",
            SettingField::SpeedPayloadMb => "Speed payload (MB)",
            SettingField::SpeedRepetitions => "Speed repetitions",
            SettingField::SpeedTimeoutMs => "Speed timeout (ms)",
            SettingField::SamplePerCidr => "Sample per CIDR",
            SettingField::Probes => "Probes",
            SettingField::Concurrency => "Concurrency",
            SettingField::TimeoutMs => "Timeout (ms)",
            SettingField::ConnectTimeoutMs => "Connect timeout (ms)",
            SettingField::Top => "Top results",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            SettingField::Host => "The hostname used in SNI and the Host header for HTTP probes (e.g. app.iplat.ir). Cleanscan resolves this host to the tested edge IPs directly.",
            SettingField::Path => "The HTTP request path to probe (e.g. /cdn-cgi/trace). Typically points to a lightweight text file or endpoint to minimize bandwidth usage.",
            SettingField::DownloadPath => "Static file endpoint used for download speed tests.",
            SettingField::UploadPath => "POST endpoint used for upload speed tests; it should consume and discard the request body.",
            SettingField::SpeedPayloadMb => "Payload size used for each upload/download repetition. Larger payloads reduce short-test noise but use more bandwidth.",
            SettingField::SpeedRepetitions => "Number of upload/download repetitions per selected IP; reported speeds are averaged.",
            SettingField::SpeedTimeoutMs => "Maximum total time for one upload/download transfer, separate from the normal latency probe timeout.",
            SettingField::SamplePerCidr => "Number of random IPs sampled from each selected CIDR. Higher values increase coverage across the edge network, but increase total targets.",
            SettingField::Probes => "Number of requests sent to each IP to probe latency. More probes filter out transient noise and establish a highly accurate latency percentile.",
            SettingField::Concurrency => "Maximum number of simultaneous request workers. Higher concurrency speeds up scanning but may trigger rate limiting or CPU bottlenecks.",
            SettingField::TimeoutMs => "Max time (in ms) allowed for an HTTP request to finish. Probes exceeding this threshold are treated as errors/failures.",
            SettingField::ConnectTimeoutMs => "Max time (in ms) to establish a TCP socket connection. Lower values skip dead, blacklisted, or blocked IPs more rapidly.",
            SettingField::Top => "Number of fastest, zero-fail IP addresses to show in the final dashboard results table and export to files.",
        }
    }

    /// Current value of this field as an editable string.
    pub fn value_string(&self, args: &AppConfig) -> String {
        match self {
            SettingField::Host => args.host.clone(),
            SettingField::Path => args.path.clone(),
            SettingField::DownloadPath => args.download_path.clone(),
            SettingField::UploadPath => args.upload_path.clone(),
            SettingField::SpeedPayloadMb => (args.speed_payload_bytes / (1024 * 1024)).to_string(),
            SettingField::SpeedRepetitions => args.speed_repetitions.to_string(),
            SettingField::SpeedTimeoutMs => args.speed_timeout_ms.to_string(),
            SettingField::SamplePerCidr => args.sample_per_cidr.to_string(),
            SettingField::Probes => args.probes.to_string(),
            SettingField::Concurrency => args.concurrency.to_string(),
            SettingField::TimeoutMs => args.timeout_ms.to_string(),
            SettingField::ConnectTimeoutMs => args.connect_timeout_ms.to_string(),
            SettingField::Top => args.top.to_string(),
        }
    }

    fn is_numeric(&self) -> bool {
        !matches!(
            self,
            SettingField::Host
                | SettingField::Path
                | SettingField::DownloadPath
                | SettingField::UploadPath
        )
    }

    /// Step size used when nudging a numeric field with up/down arrows.
    fn step(&self) -> i64 {
        match self {
            SettingField::TimeoutMs | SettingField::ConnectTimeoutMs => 100,
            SettingField::SamplePerCidr => 10,
            SettingField::SpeedPayloadMb => 10,
            SettingField::SpeedTimeoutMs => 1_000,
            _ => 1,
        }
    }

    fn max_value(&self) -> i64 {
        match self {
            SettingField::SamplePerCidr => MAX_SAMPLE_PER_CIDR as i64,
            SettingField::Probes => MAX_PROBES as i64,
            SettingField::Concurrency => MAX_CONCURRENCY as i64,
            SettingField::TimeoutMs => MAX_TIMEOUT_MS as i64,
            SettingField::ConnectTimeoutMs => MAX_CONNECT_TIMEOUT_MS as i64,
            SettingField::Top => MAX_TOP as i64,
            SettingField::SpeedPayloadMb => MAX_SPEED_PAYLOAD_MB as i64,
            SettingField::SpeedRepetitions => MAX_SPEED_REPETITIONS as i64,
            SettingField::SpeedTimeoutMs => MAX_SPEED_TIMEOUT_MS as i64,
            SettingField::Host
            | SettingField::Path
            | SettingField::DownloadPath
            | SettingField::UploadPath => i64::MAX,
        }
    }

    /// Return the value after one up/down adjustment, clamped to the field's
    /// valid range.
    fn nudged_value(&self, value: i64, direction: i64) -> i64 {
        value
            .saturating_add(direction.saturating_mul(self.step()))
            .clamp(1, self.max_value())
    }

    /// Adjust this numeric field directly in the application config.
    fn nudge_config(&self, args: &mut AppConfig, direction: i64) {
        let value = self.value_string(args).parse::<i64>().unwrap_or(1);
        let value = self.nudged_value(value, direction);
        match self {
            SettingField::SamplePerCidr => args.sample_per_cidr = value as usize,
            SettingField::Probes => args.probes = value as usize,
            SettingField::Concurrency => args.concurrency = value as usize,
            SettingField::TimeoutMs => args.timeout_ms = value as u64,
            SettingField::ConnectTimeoutMs => args.connect_timeout_ms = value as u64,
            SettingField::Top => args.top = value as usize,
            SettingField::SpeedPayloadMb => args.speed_payload_bytes = value as u64 * 1024 * 1024,
            SettingField::SpeedRepetitions => args.speed_repetitions = value as usize,
            SettingField::SpeedTimeoutMs => args.speed_timeout_ms = value as u64,
            SettingField::Host
            | SettingField::Path
            | SettingField::DownloadPath
            | SettingField::UploadPath => {}
        }
    }

    /// Parse `raw` and apply it to `args`. Returns an error message on failure.
    pub fn apply(&self, raw: &str, args: &mut AppConfig) -> Result<(), String> {
        let raw = raw.trim();
        match self {
            SettingField::Host => {
                if raw.is_empty() || raw.contains("://") || raw.contains('/') || raw.contains('\\')
                {
                    return Err(
                        "host must be a non-empty authority without a scheme or path".to_string(),
                    );
                }
                args.host = raw.to_string();
            }
            SettingField::Path => {
                if raw.is_empty() || !raw.starts_with('/') {
                    return Err("path must be non-empty and begin with /".to_string());
                }
                args.path = raw.to_string();
            }
            SettingField::DownloadPath => {
                if raw.is_empty() || !raw.starts_with('/') {
                    return Err("download path must be non-empty and begin with /".to_string());
                }
                args.download_path = raw.to_string();
            }
            SettingField::UploadPath => {
                if raw.is_empty() || !raw.starts_with('/') {
                    return Err("upload path must be non-empty and begin with /".to_string());
                }
                args.upload_path = raw.to_string();
            }
            SettingField::SpeedPayloadMb => {
                let v = raw
                    .parse::<u64>()
                    .map_err(|_| "invalid number".to_string())?;
                if !(1..=MAX_SPEED_PAYLOAD_MB).contains(&v) {
                    return Err(format!("must be between 1 and {MAX_SPEED_PAYLOAD_MB}"));
                }
                args.speed_payload_bytes = v * 1024 * 1024;
            }
            SettingField::SpeedRepetitions => {
                let v = raw
                    .parse::<usize>()
                    .map_err(|_| "invalid number".to_string())?;
                if !(1..=MAX_SPEED_REPETITIONS).contains(&v) {
                    return Err(format!("must be between 1 and {MAX_SPEED_REPETITIONS}"));
                }
                args.speed_repetitions = v;
            }
            SettingField::SpeedTimeoutMs => {
                let v = raw
                    .parse::<u64>()
                    .map_err(|_| "invalid number".to_string())?;
                if !(1..=MAX_SPEED_TIMEOUT_MS).contains(&v) {
                    return Err(format!("must be between 1 and {MAX_SPEED_TIMEOUT_MS}"));
                }
                args.speed_timeout_ms = v;
            }
            SettingField::SamplePerCidr => {
                let v = raw
                    .parse::<usize>()
                    .map_err(|_| "invalid number".to_string())?;
                if !(1..=MAX_SAMPLE_PER_CIDR).contains(&v) {
                    return Err(format!("must be between 1 and {MAX_SAMPLE_PER_CIDR}"));
                }
                args.sample_per_cidr = v;
            }
            SettingField::Probes => {
                let v = raw
                    .parse::<usize>()
                    .map_err(|_| "invalid number".to_string())?;
                if !(1..=MAX_PROBES).contains(&v) {
                    return Err(format!("must be between 1 and {MAX_PROBES}"));
                }
                args.probes = v;
            }
            SettingField::Concurrency => {
                let v = raw
                    .parse::<usize>()
                    .map_err(|_| "invalid number".to_string())?;
                if !(1..=MAX_CONCURRENCY).contains(&v) {
                    return Err(format!("must be between 1 and {MAX_CONCURRENCY}"));
                }
                args.concurrency = v;
            }
            SettingField::TimeoutMs => {
                let v = raw
                    .parse::<u64>()
                    .map_err(|_| "invalid number".to_string())?;
                if !(1..=MAX_TIMEOUT_MS).contains(&v) {
                    return Err(format!("must be between 1 and {MAX_TIMEOUT_MS}"));
                }
                args.timeout_ms = v;
            }
            SettingField::ConnectTimeoutMs => {
                let v = raw
                    .parse::<u64>()
                    .map_err(|_| "invalid number".to_string())?;
                if !(1..=MAX_CONNECT_TIMEOUT_MS).contains(&v) {
                    return Err(format!("must be between 1 and {MAX_CONNECT_TIMEOUT_MS}"));
                }
                args.connect_timeout_ms = v;
            }
            SettingField::Top => {
                let v = raw
                    .parse::<usize>()
                    .map_err(|_| "invalid number".to_string())?;
                if !(1..=MAX_TOP).contains(&v) {
                    return Err(format!("must be between 1 and {MAX_TOP}"));
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
        spans.push(Span::styled(format!("  {s}  "), style));
        if i < steps.len() - 1 {
            spans.push(Span::styled("›", theme::hint_style()));
        }
    }
    let line = Line::from(spans);
    let para = Paragraph::new(line).block(widgets::panel_block("", false));
    frame.render_widget(para, area);
}

fn render_ranges(app: &mut App, frame: &mut Frame, area: Rect) {
    // On tall terminals, lead with a compact brand banner.
    let body = if area.height >= 16 {
        let split = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(1)])
            .split(area);
        let banner = Paragraph::new(vec![
            Line::from(Span::styled(
                "C L E A N S C A N",
                theme::header_style().add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                "Cloudflare edge latency & speed scanner",
                theme::hint_style(),
            )),
        ])
        .alignment(ratatui::layout::Alignment::Center);
        frame.render_widget(banner, split[0]);
        split[1]
    } else {
        area
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(3)])
        .split(body);

    let main_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(chunks[0]);

    let list_block =
        widgets::panel_block("Cloudflare CIDR ranges (space toggle, A all, N none)", true);
    let inner = list_block.inner(main_layout[0]);
    app.ranges_inner = Some(inner);

    let visible = inner.height as usize;
    let max_scroll = app.cidr_candidates.len().saturating_sub(visible);
    if app.cursor < app.ranges_scroll {
        app.ranges_scroll = app.cursor;
    } else if app.cursor >= app.ranges_scroll.saturating_add(visible) {
        app.ranges_scroll = app.cursor + 1 - visible;
    }
    app.ranges_scroll = app.ranges_scroll.min(max_scroll);
    let start = app.ranges_scroll;

    let lines: Vec<Line> = app
        .cidr_candidates
        .iter()
        .enumerate()
        .skip(start)
        .take(visible)
        .map(|(i, e)| {
            let mark = if e.selected { "☑" } else { "☐" };
            let cursor = if i == app.cursor { "› " } else { "  " };
            let style = if i == app.cursor {
                theme::row_selected_style()
            } else if e.selected {
                Style::default().fg(Color::LightCyan)
            } else {
                theme::hint_style()
            };
            Line::from(format!("{}{} {}", cursor, mark, e.cidr)).style(style)
        })
        .collect();

    let para = Paragraph::new(lines).block(list_block);
    frame.render_widget(para, main_layout[0]);

    // Right Side Info Panel
    let selected_count = app.cidr_candidates.iter().filter(|e| e.selected).count();
    let total_ips = selected_count.saturating_mul(app.config.sample_per_cidr);
    let total_requests = total_ips.saturating_mul(app.config.probes);

    let info_text = vec![
        Line::from(vec![Span::styled(" RANGE SUMMARY ", theme::header_style())]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Selected Ranges: ", theme::title_style()),
            Span::raw(format!(
                "{} / {}",
                selected_count,
                app.cidr_candidates.len()
            )),
        ]),
        Line::from(vec![
            Span::styled("Sample per CIDR: ", theme::title_style()),
            Span::raw(app.config.sample_per_cidr.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Total target IPs: ", theme::title_style()),
            Span::raw(total_ips.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Total HTTP Probes: ", theme::title_style()),
            Span::raw(total_requests.to_string()),
        ]),
        Line::from(""),
        Line::from(Span::styled(" Quick Actions: ", theme::subtitle_style())),
        Line::from(vec![
            Span::styled("  A  ", theme::highlight_style()),
            Span::raw("Select all CIDRs"),
        ]),
        Line::from(vec![
            Span::styled("  N  ", theme::highlight_style()),
            Span::raw("Deselect all CIDRs"),
        ]),
        Line::from(vec![
            Span::styled("  a  ", theme::highlight_style()),
            Span::raw("Add a custom CIDR range"),
        ]),
    ];

    let info_block = widgets::panel_block("Selected Metrics", false);
    let info_para = Paragraph::new(info_text).block(info_block);
    frame.render_widget(info_para, main_layout[1]);

    // Input line at bottom
    let input_line = if app.custom_input_mode {
        let (before, after) = app
            .input_buffer
            .split_at(app.edit_caret.min(app.input_buffer.len()));
        format!("> {}{}_{}", before, after, "")
    } else {
        "  press 'a' to add a custom CIDR range  ".to_string()
    };
    let title = " Add CIDR ";
    let input =
        Paragraph::new(input_line).block(widgets::panel_block(title, app.custom_input_mode));
    frame.render_widget(input, chunks[1]);
}

fn render_settings(app: &mut App, frame: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Preset bar
            Constraint::Min(1),    // Main parameters
        ])
        .split(area);

    // Preset Bar
    // Detect matching preset
    let mut current_preset = "Custom";
    if app.config.sample_per_cidr == 100
        && app.config.probes == 8
        && app.config.concurrency == 120
        && app.config.timeout_ms == 2500
        && app.config.connect_timeout_ms == 1000
        && app.config.top == 50
    {
        current_preset = "Default [1]";
    } else if app.config.sample_per_cidr == 50
        && app.config.probes == 4
        && app.config.concurrency == 200
        && app.config.timeout_ms == 1500
        && app.config.connect_timeout_ms == 500
        && app.config.top == 25
    {
        current_preset = "Fast Scan [2]";
    } else if app.config.sample_per_cidr == 200
        && app.config.probes == 15
        && app.config.concurrency == 80
        && app.config.timeout_ms == 3500
        && app.config.connect_timeout_ms == 1500
        && app.config.top == 100
    {
        current_preset = "Thorough Scan [3]";
    }

    let preset_spans = vec![
        Span::styled(" Quick Presets: ", theme::subtitle_style()),
        Span::styled(
            " [1] Default ",
            if current_preset.contains("Default") {
                theme::highlight_style()
            } else {
                theme::hint_style()
            },
        ),
        Span::styled(
            " [2] Fast Scan ",
            if current_preset.contains("Fast") {
                theme::highlight_style()
            } else {
                theme::hint_style()
            },
        ),
        Span::styled(
            " [3] Thorough Scan ",
            if current_preset.contains("Thorough") {
                theme::highlight_style()
            } else {
                theme::hint_style()
            },
        ),
        Span::styled("  Current: ", theme::hint_style()),
        Span::styled(current_preset, theme::title_style()),
    ];

    let preset_block = widgets::panel_block("Preset Configurations", false);
    let preset_para = Paragraph::new(Line::from(preset_spans)).block(preset_block);
    frame.render_widget(preset_para, chunks[0]);

    // Settings columns layout
    let main_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(chunks[1]);

    let block = widgets::panel_block("Scan parameters (Enter edit, ↑/↓ step numeric)", true);
    let inner = block.inner(main_layout[0]);
    app.settings_inner = Some(inner);

    // Build the field list with section subheaders, tracking which display row
    // maps to which field index (headers map to `None`) for mouse hit-testing.
    let mut lines: Vec<Line> = Vec::new();
    let mut row_map: Vec<Option<usize>> = Vec::new();
    let mut field_idx = 0usize;
    for (header, count) in SettingField::GROUPS {
        lines.push(Line::from(Span::styled(
            format!(" {} ", header.to_uppercase()),
            theme::subtitle_style().add_modifier(Modifier::BOLD),
        )));
        row_map.push(None);
        for _ in 0..count {
            let i = field_idx;
            let f = SettingField::ALL[i];
            let cursor = if i == app.cursor { "› " } else { "  " };
            let style = if i == app.cursor {
                theme::row_selected_style()
            } else {
                Style::default().fg(theme::palette().subtitle)
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
            lines.push(Line::from(format!("{}{} = {}", cursor, label, value)).style(style));
            row_map.push(Some(i));
            field_idx += 1;
        }
    }
    app.settings_row_map = row_map;

    let para = Paragraph::new(lines).block(block);
    frame.render_widget(para, main_layout[0]);

    // Right Side Description Panel
    let current_field = SettingField::ALL[app.cursor.min(SettingField::ALL.len() - 1)];
    let desc_text = vec![
        Line::from(vec![Span::styled(
            format!(" {} ", current_field.label().to_uppercase()),
            theme::header_style(),
        )]),
        Line::from(""),
        Line::from(Span::styled("Description:", theme::title_style())),
        Line::from(""),
    ];

    let mut desc_para_lines = desc_text;
    desc_para_lines.push(Line::from(current_field.description()));
    desc_para_lines.push(Line::from(""));
    desc_para_lines.push(Line::from(Span::styled(
        "Keyboard Shortcut:",
        theme::subtitle_style(),
    )));
    desc_para_lines.push(Line::from("  Press Enter to edit directly."));
    if current_field.is_numeric() {
        desc_para_lines.push(Line::from(
            "  Use ↑/↓ arrows to adjust this value immediately.",
        ));
        desc_para_lines.push(Line::from("  Use j/k to move between fields."));
    }

    let desc_block = widgets::panel_block("Field Context", false);
    let desc_widget = Paragraph::new(desc_para_lines)
        .block(desc_block)
        .wrap(Wrap { trim: true });
    frame.render_widget(desc_widget, main_layout[1]);
}

fn render_review(app: &App, frame: &mut Frame, area: Rect) {
    let selected: Vec<&str> = app
        .cidr_candidates
        .iter()
        .filter(|e| e.selected)
        .map(|e| e.cidr.as_str())
        .collect();

    let selected_count = selected.len();
    let total_ips = selected_count.saturating_mul(app.config.sample_per_cidr);
    let total_probes = total_ips.saturating_mul(app.config.probes);

    // Ideal scan duration estimate
    let ideal_seconds = (total_probes as f64 / app.config.concurrency as f64)
        * (app.config.timeout_ms as f64 / 2000.0);
    let est_duration_str = if ideal_seconds < 60.0 {
        format!("{:.1}s", ideal_seconds)
    } else {
        format!(
            "{:02}:{:02}",
            (ideal_seconds / 60.0) as u64,
            (ideal_seconds % 60.0) as u64
        )
    };

    let main_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let mut summary_left = vec![
        Line::from(vec![Span::styled(
            " TARGET SPECIFICATION ",
            theme::header_style(),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Hostname  : ", theme::title_style()),
            Span::raw(app.config.host.clone()),
        ]),
        Line::from(vec![
            Span::styled("Probe Path: ", theme::title_style()),
            Span::raw(app.config.path.clone()),
        ]),
        Line::from(vec![
            Span::styled("CIDR count: ", theme::title_style()),
            Span::raw(format!("{} selected", selected_count)),
        ]),
        Line::from(""),
    ];
    summary_left.extend(
        selected
            .iter()
            .take(8)
            .map(|c| Line::from(format!("  • {c}"))),
    );
    summary_left.push(Line::from(if selected_count > 8 {
        format!("  ... and {} more", selected_count - 8)
    } else {
        "".to_string()
    }));

    let summary_right = vec![
        Line::from(vec![Span::styled(
            " SCANNING PARAMETERS ",
            theme::header_style(),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Samples/CIDR: ", theme::title_style()),
            Span::raw(app.config.sample_per_cidr.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Probes/IP   : ", theme::title_style()),
            Span::raw(app.config.probes.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Concurrency : ", theme::title_style()),
            Span::raw(app.config.concurrency.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Timeout     : ", theme::title_style()),
            Span::raw(format!(
                "{}ms (connect: {}ms)",
                app.config.timeout_ms, app.config.connect_timeout_ms
            )),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "ESTIMATES & WORKLOAD",
            theme::subtitle_style(),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Total IPs   : ", theme::title_style()),
            Span::raw(total_ips.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Total Probes: ", theme::title_style()),
            Span::raw(total_probes.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Est Duration: ", theme::title_style()),
            Span::raw(format!("~{}", est_duration_str)),
        ]),
    ];

    let block_left = widgets::panel_block("Target configuration", false);
    let para_left = Paragraph::new(summary_left).block(block_left);
    frame.render_widget(para_left, main_layout[0]);

    let block_right = widgets::panel_block("Scope & Workload", false);
    let para_right = Paragraph::new(summary_right).block(block_right);
    frame.render_widget(para_right, main_layout[1]);
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
    let right_kind = if right_focused {
        ButtonKind::Primary
    } else {
        ButtonKind::Secondary
    };
    app.button_ex(
        frame,
        chunks[2],
        right_label,
        right_action,
        right_kind,
        right_focused,
    );
}

fn render_hint(app: &App, frame: &mut Frame, area: Rect) {
    let text = match app.wizard_step {
        WizardStep::Ranges => {
            if app.custom_input_mode {
                "type CIDR • Enter confirm • Esc cancel"
            } else {
                "↑/↓ move • space toggle • a add • A all • N none • → next • ? help"
            }
        }
        WizardStep::Settings => {
            if app.edit_field.is_some() {
                "type value • ←/→ move • ↑/↓ step • Enter confirm • Esc cancel"
            } else {
                "j/k move • ↑/↓ adjust numeric • Enter edit • 1/2/3 presets • → next • ? help"
            }
        }
        WizardStep::Review => "Enter start • ← back • ? help",
    };
    widgets::status_bar(frame, area, text, app.visible_message());
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
                        if let Some((idx, entry)) = app
                            .cidr_candidates
                            .iter_mut()
                            .enumerate()
                            .find(|(_, entry)| entry.cidr == s)
                        {
                            entry.selected = true;
                            app.cursor = idx;
                            app.toast_warn(format!("CIDR {s} already exists; selected it"));
                        } else {
                            app.cidr_candidates.push(crate::tui::CidrEntry {
                                cidr: s.clone(),
                                selected: true,
                            });
                            app.cursor = app.cidr_candidates.len() - 1;
                            app.toast_success(format!("Added {s}"));
                        }
                        app.input_buffer.clear();
                        app.edit_caret = 0;
                        app.custom_input_mode = false;
                        app.save_config();
                    }
                    Err(e) => app.toast_error(format!("Invalid CIDR '{s}': {e}")),
                }
            }
            KeyCode::Esc => {
                app.custom_input_mode = false;
                app.input_buffer.clear();
                app.edit_caret = 0;
            }
            KeyCode::Backspace if app.edit_caret > 0 => {
                let previous = previous_char_boundary(&app.input_buffer, app.edit_caret);
                app.input_buffer.drain(previous..app.edit_caret);
                app.edit_caret = previous;
            }
            KeyCode::Delete if app.edit_caret < app.input_buffer.len() => {
                let next = next_char_boundary(&app.input_buffer, app.edit_caret);
                app.input_buffer.drain(app.edit_caret..next);
            }
            KeyCode::Left if app.edit_caret > 0 => {
                app.edit_caret = previous_char_boundary(&app.input_buffer, app.edit_caret);
            }
            KeyCode::Right if app.edit_caret < app.input_buffer.len() => {
                app.edit_caret = next_char_boundary(&app.input_buffer, app.edit_caret);
            }
            KeyCode::Home => app.edit_caret = 0,
            KeyCode::End => app.edit_caret = app.input_buffer.len(),
            KeyCode::Char(c) => {
                app.input_buffer.insert(app.edit_caret, c);
                app.edit_caret += c.len_utf8();
            }
            _ => {}
        }
        return;
    }

    match code {
        KeyCode::Up | KeyCode::Char('k') if app.cursor > 0 => {
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
                app.save_config();
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
            app.save_config();
        }
        KeyCode::Char('N') | KeyCode::Char('n') | KeyCode::Char('d') | KeyCode::Char('D') => {
            for e in app.cidr_candidates.iter_mut() {
                e.selected = false;
            }
            app.save_config();
        }
        KeyCode::Char('c') => {
            app.wizard_step = WizardStep::Settings;
            app.cursor = 0;
        }
        KeyCode::Right | KeyCode::Enter if (app.wizard_step as usize) < 2 => {
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
            KeyCode::Enter => match field.apply(&app.edit_buffer, &mut app.config) {
                Ok(()) => {
                    app.edit_field = None;
                    app.edit_buffer.clear();
                    app.edit_caret = 0;
                    app.save_config();
                }
                Err(e) => app.toast_error(format!("Invalid {}: {}", field.label(), e)),
            },
            KeyCode::Esc => {
                app.edit_field = None;
                app.edit_buffer.clear();
                app.edit_caret = 0;
            }
            KeyCode::Backspace if app.edit_caret > 0 => {
                let previous = previous_char_boundary(&app.edit_buffer, app.edit_caret);
                app.edit_buffer.drain(previous..app.edit_caret);
                app.edit_caret = previous;
            }
            KeyCode::Delete if app.edit_caret < app.edit_buffer.len() => {
                let next = next_char_boundary(&app.edit_buffer, app.edit_caret);
                app.edit_buffer.drain(app.edit_caret..next);
            }
            KeyCode::Left if app.edit_caret > 0 => {
                app.edit_caret = previous_char_boundary(&app.edit_buffer, app.edit_caret);
            }
            KeyCode::Right if app.edit_caret < app.edit_buffer.len() => {
                app.edit_caret = next_char_boundary(&app.edit_buffer, app.edit_caret);
            }
            KeyCode::Home => app.edit_caret = 0,
            KeyCode::End => app.edit_caret = app.edit_buffer.len(),
            KeyCode::Up | KeyCode::Down if field.is_numeric() => {
                let delta = if code == KeyCode::Up { 1 } else { -1 };
                if let Ok(v) = app.edit_buffer.parse::<i64>() {
                    let nv = field.nudged_value(v, delta);
                    app.edit_buffer = nv.to_string();
                    app.edit_caret = app.edit_buffer.len();
                }
            }
            KeyCode::Char(c) => {
                app.edit_buffer.insert(app.edit_caret, c);
                app.edit_caret += c.len_utf8();
            }
            _ => {}
        }
        return;
    }

    let field = SettingField::ALL[app.cursor.min(SettingField::ALL.len() - 1)];
    match code {
        KeyCode::Up | KeyCode::Down if field.is_numeric() => {
            let direction = if code == KeyCode::Up { 1 } else { -1 };
            field.nudge_config(&mut app.config, direction);
            app.save_config();
        }
        KeyCode::Char('k') if app.cursor > 0 => {
            app.cursor -= 1;
        }
        KeyCode::Char('j') => {
            let last = SettingField::ALL.len().saturating_sub(1);
            if app.cursor < last {
                app.cursor += 1;
            }
        }
        KeyCode::Up if app.cursor > 0 => {
            app.cursor -= 1;
        }
        KeyCode::Down => {
            let last = SettingField::ALL.len().saturating_sub(1);
            if app.cursor < last {
                app.cursor += 1;
            }
        }
        KeyCode::Right if (app.wizard_step as usize) < 2 => {
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
        KeyCode::Char('1') => {
            app.config.sample_per_cidr = 100;
            app.config.probes = 8;
            app.config.concurrency = 120;
            app.config.timeout_ms = 2500;
            app.config.connect_timeout_ms = 1000;
            app.config.top = 50;
            app.toast_success("Preset Applied: Default");
            app.save_config();
        }
        KeyCode::Char('2') => {
            app.config.sample_per_cidr = 50;
            app.config.probes = 4;
            app.config.concurrency = 200;
            app.config.timeout_ms = 1500;
            app.config.connect_timeout_ms = 500;
            app.config.top = 25;
            app.toast_success("Preset Applied: Fast Scan");
            app.save_config();
        }
        KeyCode::Char('3') => {
            app.config.sample_per_cidr = 200;
            app.config.probes = 15;
            app.config.concurrency = 80;
            app.config.timeout_ms = 3500;
            app.config.connect_timeout_ms = 1500;
            app.config.top = 100;
            app.toast_success("Preset Applied: Thorough Scan");
            app.save_config();
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

fn previous_char_boundary(s: &str, index: usize) -> usize {
    s[..index]
        .char_indices()
        .next_back()
        .map(|(position, _)| position)
        .unwrap_or(0)
}

fn next_char_boundary(s: &str, index: usize) -> usize {
    s[index..]
        .chars()
        .next()
        .map(|c| index + c.len_utf8())
        .unwrap_or(index)
}

#[cfg(test)]
mod tests {
    use super::{next_char_boundary, previous_char_boundary, SettingField};
    use crate::config::AppConfig;

    #[test]
    fn host_and_path_validation_match_url_construction() {
        let mut config = AppConfig::default();
        assert!(SettingField::Host
            .apply("example.test:443", &mut config)
            .is_ok());
        assert!(SettingField::Host
            .apply("https://example.test", &mut config)
            .is_err());
        assert!(SettingField::Host
            .apply("example.test/path", &mut config)
            .is_err());
        assert!(SettingField::Path.apply("/trace", &mut config).is_ok());
        assert!(SettingField::Path.apply("trace", &mut config).is_err());
    }

    #[test]
    fn editor_boundaries_are_utf8_safe() {
        let value = "a🙂b";
        assert_eq!(previous_char_boundary(value, value.len()), 5);
        assert_eq!(previous_char_boundary(value, 5), 1);
        assert_eq!(next_char_boundary(value, 1), 5);
        assert_eq!(next_char_boundary(value, 5), value.len());
    }

    #[test]
    fn numeric_nudge_uses_field_specific_steps() {
        assert_eq!(SettingField::Probes.nudged_value(8, 1), 9);
        assert_eq!(SettingField::SamplePerCidr.nudged_value(100, 1), 110);
        assert_eq!(SettingField::TimeoutMs.nudged_value(2500, -1), 2400);
    }

    #[test]
    fn numeric_nudge_clamps_to_valid_bounds() {
        assert_eq!(SettingField::Probes.nudged_value(1, -1), 1);
        assert_eq!(SettingField::Probes.nudged_value(1000, 1), 1000);
        assert_eq!(SettingField::Top.nudged_value(10_000, 1), 10_000);
    }

    #[test]
    fn numeric_nudge_updates_config() {
        let mut config = AppConfig::default();
        SettingField::TimeoutMs.nudge_config(&mut config, 1);
        SettingField::SamplePerCidr.nudge_config(&mut config, -1);
        assert_eq!(config.timeout_ms, 2600);
        assert_eq!(config.sample_per_cidr, 90);
    }
}
