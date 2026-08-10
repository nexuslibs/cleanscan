//! Shared state types for the TUI: screens, scan lifecycle, target activity,
//! run history, the action registry, and the results sort cache.

use std::{
    collections::VecDeque,
    sync::atomic::AtomicBool,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::scanner::{ProbeFailureCounts, ProbeResult, ScanEvent, ScanEventKind, ScanPhase};

/// Which top-level screen the TUI is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Guided setup wizard (steps 1-3).
    Wizard,
    /// Live scanning dashboard.
    Scanning,
    SpeedSelect,
    SpeedTesting,
    SpeedResults,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanLifecycle {
    Running,
    Paused,
    Cancelling,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanDashboardView {
    Results,
    LiveTargets,
    RunLog,
}

impl ScanDashboardView {
    pub const ALL: [Self; 3] = [Self::Results, Self::LiveTargets, Self::RunLog];

    pub fn label(self) -> &'static str {
        match self {
            Self::Results => "Results",
            Self::LiveTargets => "Live Targets",
            Self::RunLog => "Run Log",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetStage {
    Queued,
    WarmingUp,
    Probing,
    Finalized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetFilter {
    All,
    Active,
    Problems,
    Selected,
}

impl TargetFilter {
    pub const ALL: [Self; 4] = [Self::All, Self::Active, Self::Problems, Self::Selected];

    pub fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Active => "active",
            Self::Problems => "problems",
            Self::Selected => "selected",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetSort {
    Attention,
    ActivityAge,
    Stage,
    Ip,
}

impl TargetSort {
    pub const ALL: [Self; 4] = [Self::Attention, Self::ActivityAge, Self::Stage, Self::Ip];

    pub fn label(self) -> &'static str {
        match self {
            Self::Attention => "attention",
            Self::ActivityAge => "age",
            Self::Stage => "stage",
            Self::Ip => "IP",
        }
    }
}

impl TargetStage {
    pub fn label(self) -> &'static str {
        match self {
            Self::Queued => "QUEUED",
            Self::WarmingUp => "WARMUP",
            Self::Probing => "PROBING",
            Self::Finalized => "DONE",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TargetActivity {
    pub ip: String,
    pub stage: TargetStage,
    pub probes_started: usize,
    pub probes_completed: usize,
    pub failures: usize,
    pub first_activity: Option<Instant>,
    pub last_activity: Option<Instant>,
    pub last_outcome: String,
}

impl TargetActivity {
    pub(super) fn queued(ip: String) -> Self {
        Self {
            ip,
            stage: TargetStage::Queued,
            probes_started: 0,
            probes_completed: 0,
            failures: 0,
            first_activity: None,
            last_activity: None,
            last_outcome: "waiting for scheduler".to_string(),
        }
    }
}

pub(super) fn apply_event_to_activity(
    activity: &mut TargetActivity,
    event: &ScanEvent,
    now: Instant,
) -> bool {
    activity.first_activity.get_or_insert(now);
    activity.last_activity = Some(now);
    activity.last_outcome = event.message.clone();
    match event.kind {
        ScanEventKind::TargetQueued => activity.stage = TargetStage::Queued,
        ScanEventKind::WarmupStarted => {
            activity.stage = TargetStage::WarmingUp;
            activity.probes_started = activity.probes_started.saturating_add(1);
        }
        ScanEventKind::ProbeStarted => {
            activity.stage = TargetStage::Probing;
            activity.probes_started = activity.probes_started.saturating_add(1);
        }
        ScanEventKind::ProbeCompleted => {
            activity.stage = TargetStage::Probing;
            activity.probes_completed = activity.probes_completed.saturating_add(1);
            // Telemetry is deliberately bounded and may shed an earlier start
            // event under extreme pressure. A completion proves that start
            // happened, so preserve the factual invariant instead of showing
            // impossible counts such as 6 completed / 4 started.
            activity.probes_started = activity.probes_started.max(activity.probes_completed);
            if event.probe_succeeded == Some(false) {
                activity.failures = activity.failures.saturating_add(1);
            }
            return true;
        }
        ScanEventKind::TargetFinalized => {
            activity.stage = TargetStage::Finalized;
            return true;
        }
        ScanEventKind::WorkerChanged | ScanEventKind::ScanFinalizing | ScanEventKind::Warning => {}
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunKind {
    Full,
    Targeted,
    Investigation,
}

impl RunKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Full => "FULL",
            Self::Targeted => "TARGETED",
            Self::Investigation => "ISOLATED",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RunRecord {
    pub id: u64,
    pub source_run_id: Option<u64>,
    pub kind: RunKind,
    pub targets: Vec<String>,
    pub results: Vec<ProbeResult>,
    pub elapsed: Duration,
    pub lifecycle: ScanLifecycle,
}

#[derive(Debug, Clone)]
pub struct InvestigationState {
    pub id: u64,
    pub target: String,
    pub source_run_id: u64,
    pub started_at: Instant,
    pub cancel: Arc<AtomicBool>,
    pub activity: TargetActivity,
    pub events: VecDeque<TimedScanEvent>,
    pub results: Vec<ProbeResult>,
}

impl InvestigationState {
    pub(super) fn new(id: u64, target: String, source_run_id: u64) -> Self {
        Self {
            id,
            activity: TargetActivity::queued(target.clone()),
            target,
            source_run_id,
            started_at: Instant::now(),
            cancel: Arc::new(AtomicBool::new(false)),
            events: VecDeque::new(),
            results: Vec::new(),
        }
    }

    pub(super) fn apply_event(&mut self, event: ScanEvent) {
        apply_event_to_activity(&mut self.activity, &event, Instant::now());
        self.events.push_front(TimedScanEvent {
            elapsed: self.started_at.elapsed(),
            event,
        });
        self.events.truncate(1_000);
    }
}

#[derive(Debug, Clone)]
pub struct TimedScanEvent {
    pub elapsed: Duration,
    pub event: ScanEvent,
}

#[derive(Debug, Clone)]
pub struct ScanProgressState {
    pub phase: ScanPhase,
    pub probes_started: usize,
    pub probes_completed: usize,
    pub active_probes: usize,
    pub targets_completed: usize,
    pub latest_target: Option<String>,
    pub current_workers: Option<usize>,
    pub adaptive_reason: Option<String>,
    pub targets_total: Option<usize>,
    pub failure_counts: ProbeFailureCounts,
}

impl Default for ScanProgressState {
    fn default() -> Self {
        Self {
            phase: ScanPhase::Starting,
            probes_started: 0,
            probes_completed: 0,
            active_probes: 0,
            targets_completed: 0,
            latest_target: None,
            current_workers: None,
            adaptive_reason: None,
            targets_total: None,
            failure_counts: ProbeFailureCounts::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PendingScanAction {
    RepeatTargets,
    NewSample,
}

/// Step within the guided wizard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardStep {
    Ranges = 0,
    Settings = 1,
    Review = 2,
}

/// Semantic focus target shared by every screen. The concrete index is kept in
/// `focus_index`, while this enum gives the UI a stable vocabulary for focus
/// styling, help, and future screen-specific focus maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusTarget {
    Panel,
    List,
    Table,
    Button,
    Field,
    Dialog,
}

/// User-facing commands. The command palette, contextual help, keyboard
/// aliases, and visible buttons all resolve to this same registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Back,
    Next,
    Start,
    Quit,
    Export,
    PauseResume,
    SpeedTest,
    CopyIp,
    OpenDetails,
    CloseDetails,
    OpenHelp,
    OpenCommandPalette,
    Confirm,
    Cancel,
    SelectAll,
    ClearSelection,
    Download,
    Upload,
    Both,
    ConfigureColumns,
    ToggleFailures,
    RepeatTargets,
    NewSample,
    ExportComparison,
    CustomizeScan,
    CycleScanView,
    IsolateTarget,
    RerunSelected,
    StopKeepResults,
}

impl Action {
    pub const ALL: [Action; 29] = [
        Action::Back,
        Action::Next,
        Action::Start,
        Action::Quit,
        Action::Export,
        Action::PauseResume,
        Action::SpeedTest,
        Action::CopyIp,
        Action::OpenDetails,
        Action::CloseDetails,
        Action::OpenHelp,
        Action::OpenCommandPalette,
        Action::Confirm,
        Action::Cancel,
        Action::SelectAll,
        Action::ClearSelection,
        Action::Download,
        Action::Upload,
        Action::Both,
        Action::ConfigureColumns,
        Action::ToggleFailures,
        Action::RepeatTargets,
        Action::NewSample,
        Action::ExportComparison,
        Action::CustomizeScan,
        Action::CycleScanView,
        Action::IsolateTarget,
        Action::RerunSelected,
        Action::StopKeepResults,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Action::Back => "Back",
            Action::Next => "Next",
            Action::Start => "Start scan",
            Action::Quit => "Quit",
            Action::Export => "Export results",
            Action::PauseResume => "Pause / resume",
            Action::SpeedTest => "Run speed test",
            Action::CopyIp => "Copy selected IP",
            Action::OpenDetails => "Open selected details",
            Action::CloseDetails => "Close details",
            Action::OpenHelp => "Open help",
            Action::OpenCommandPalette => "Open command palette",
            Action::Confirm => "Confirm",
            Action::Cancel => "Cancel",
            Action::SelectAll => "Select all",
            Action::ClearSelection => "Clear selection",
            Action::Download => "Download only",
            Action::Upload => "Upload only",
            Action::Both => "Download + upload",
            Action::ConfigureColumns => "Configure result columns",
            Action::ToggleFailures => "Show failures",
            Action::RepeatTargets => "Repeat current targets",
            Action::NewSample => "Generate new sample",
            Action::ExportComparison => "Export comparison",
            Action::CustomizeScan => "Customize scan",
            Action::CycleScanView => "Cycle scan dashboard view",
            Action::IsolateTarget => "Isolate selected target",
            Action::RerunSelected => "Rerun selected targets",
            Action::StopKeepResults => "Stop and keep results",
        }
    }

    pub fn shortcut(self) -> &'static str {
        match self {
            Action::Quit => "q",
            Action::Export => "e",
            Action::PauseResume => "p",
            Action::SpeedTest => "t",
            Action::CopyIp => "c",
            Action::OpenHelp => "?",
            Action::OpenCommandPalette => "/",
            Action::Confirm => "Enter",
            Action::Cancel => "Esc",
            Action::ConfigureColumns => "v",
            Action::ToggleFailures => "f",
            Action::RepeatTargets => "r",
            Action::NewSample => "n",
            Action::ExportComparison => "m",
            Action::CustomizeScan => "w",
            Action::CycleScanView => "o",
            Action::IsolateTarget => "i",
            Action::RerunSelected => "R",
            Action::StopKeepResults => "x",
            _ => "",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Action::OpenDetails => "Show complete latency statistics for the selected result",
            Action::Export => "Write the ranked results to a TSV file",
            Action::SpeedTest => "Choose successful IPs for bandwidth testing",
            Action::PauseResume => "Pause or resume the active scan",
            Action::CopyIp => "Copy the selected IP address to the clipboard",
            Action::ConfigureColumns => "Show or hide columns in the results table",
            Action::ToggleFailures => "Toggle between successful targets and all targets",
            Action::RepeatTargets => "Run the identical sampled target set again",
            Action::NewSample => "Generate a new target sample with the same settings",
            Action::ExportComparison => "Export the current run for comparison",
            Action::CustomizeScan => "Return to scan parameters without discarding results",
            Action::CycleScanView => "Switch between results, live targets, and run log",
            Action::IsolateTarget => "Pause main scheduling and investigate one target alone",
            Action::RerunSelected => "Start a focused scan using the selected targets",
            Action::StopKeepResults => "Stop active work and preserve completed results",
            _ => self.label(),
        }
    }
}

/// Identifies an action button drawn on screen, used for mouse hit-testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonAction {
    Back,
    Next,
    Start,
    Quit,
    Save,
    PauseResume,
    SpeedTest,
    ConfirmQuit,
    CancelQuit,
    SpeedAll,
    SpeedClear,
    SpeedDirDownload,
    SpeedDirUpload,
    SpeedDirBoth,
    SpeedStart,
    SpeedBack,
    CustomizeScan,
    WorkerDown,
    WorkerUp,
    WorkerAuto,
    StopKeepResults,
}

/// A selectable CIDR candidate in the wizard's ranges step.
pub struct CidrEntry {
    pub cidr: String,
    pub selected: bool,
}

#[derive(Clone)]
pub(super) struct SortedCache {
    pub(super) key: (u64, usize, bool, bool, Option<String>, Option<String>),
    pub(super) indices: Vec<usize>,
}
