use crate::config::{AppConfig, DiscoveryDriver};

/// Render a single value as a safe shell word. Values made only of letters,
/// digits, and `./-:@,_=` pass through; everything else is single-quoted.
pub fn shell_quote(value: &str) -> String {
    let safe = !value.is_empty()
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '/' | '-' | ':' | '@' | ',' | '_' | '=')
        });
    if safe {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn push(parts: &mut Vec<String>, flag: &str) {
    parts.push(flag.to_string());
}

fn kv(parts: &mut Vec<String>, flag: &str, value: impl std::fmt::Display) {
    parts.push(flag.to_string());
    parts.push(value.to_string());
}

/// Build the equivalent `cleanscan` CLI invocation for the given scan
/// configuration. Flags that match the CLI defaults are omitted so the
/// command stays readable; the resulting invocation behaves identically.
pub fn command_string(
    config: &AppConfig,
    cidrs: &[String],
    seed: u64,
    ips: Option<&str>,
) -> String {
    let mut parts: Vec<String> = vec!["cleanscan".to_string(), "--cli".to_string()];

    kv(&mut parts, "--host", shell_quote(&config.host));
    if config.health_checks.is_empty() {
        kv(&mut parts, "--path", shell_quote(&config.path));
    } else {
        for check in &config.health_checks {
            kv(
                &mut parts,
                "--check",
                shell_quote(&format!("{}={}", check.name, check.path)),
            );
        }
    }
    for port in &config.ports {
        kv(&mut parts, "--port", port);
    }
    for status in &config.expected_statuses {
        kv(&mut parts, "--expect-status", status);
    }
    for marker in &config.required_body_markers {
        kv(&mut parts, "--require-body", shell_quote(marker));
    }
    for header in &config.required_headers {
        kv(&mut parts, "--require-header", shell_quote(header));
    }
    if config.follow_redirects {
        push(&mut parts, "--follow-redirects");
    }
    for cidr in cidrs {
        kv(&mut parts, "--cidr", shell_quote(cidr));
    }
    if let Some(ips) = ips {
        kv(&mut parts, "--ips", shell_quote(ips));
    }
    kv(&mut parts, "--sample-per-cidr", config.sample_per_cidr);
    let driver = match config.discovery_driver {
        DiscoveryDriver::Sampling => None,
        DiscoveryDriver::Connect => Some("connect"),
        DiscoveryDriver::Syn => Some("syn"),
    };
    if let Some(driver) = driver {
        kv(&mut parts, "--discover", driver);
        if config.discovery_driver == DiscoveryDriver::Syn {
            if config.syn_rate != 5_000 {
                kv(&mut parts, "--rate", config.syn_rate);
            }
            if config.syn_retransmits != 1 {
                kv(&mut parts, "--syn-retrans", config.syn_retransmits);
            }
        }
    }
    if let Some(interface) = &config.interface {
        kv(&mut parts, "--interface", shell_quote(interface));
    }
    if let Some(fragment) = &config.tls_fragment {
        kv(
            &mut parts,
            "--tls-fragment",
            shell_quote(&fragment.xray_json()),
        );
    }
    kv(&mut parts, "--probes", config.probes);
    kv(&mut parts, "--concurrency", config.concurrency);
    kv(&mut parts, "--timeout-ms", config.timeout_ms);
    kv(
        &mut parts,
        "--connect-timeout-ms",
        config.connect_timeout_ms,
    );
    kv(&mut parts, "--top", config.top);
    if seed != 0 {
        kv(&mut parts, "--seed", seed);
    }
    if !config.warmup {
        push(&mut parts, "--no-warmup");
    }
    if config.stability_weight != 1.0 {
        kv(&mut parts, "--stability-weight", config.stability_weight);
    }
    if config.loss_weight != 1.0 {
        kv(&mut parts, "--loss-weight", config.loss_weight);
    }
    if !config.early_stop {
        push(&mut parts, "--no-early-stop");
    }
    if config.early_stop_loss_streak != 5 {
        kv(
            &mut parts,
            "--early-stop-loss-streak",
            config.early_stop_loss_streak,
        );
    }
    if config.early_stop_min_samples != 3 {
        kv(
            &mut parts,
            "--early-stop-min-samples",
            config.early_stop_min_samples,
        );
    }
    if config.early_stop_success_floor != 0.5 {
        kv(
            &mut parts,
            "--early-stop-success-floor",
            config.early_stop_success_floor,
        );
    }
    if !config.early_stop_prune {
        push(&mut parts, "--no-early-stop-prune");
    }
    if config.early_stop_prune_margin != 0.2 {
        kv(
            &mut parts,
            "--early-stop-prune-margin",
            config.early_stop_prune_margin,
        );
    }
    if config.two_phase {
        push(&mut parts, "--two-phase");
        if config.discover_fraction != 0.25 {
            kv(&mut parts, "--discover-fraction", config.discover_fraction);
        }
    }
    if config.adaptive_probing {
        push(&mut parts, "--adaptive-probing");
        if config.min_probes != 3 {
            kv(&mut parts, "--min-probes", config.min_probes);
        }
        if config.max_probes != 40 {
            kv(&mut parts, "--max-probes", config.max_probes);
        }
    }
    if config.adaptive_concurrency {
        push(&mut parts, "--adaptive-concurrency");
        if config.min_concurrency != 1 {
            kv(&mut parts, "--min-concurrency", config.min_concurrency);
        }
        if config.max_concurrency != 240 {
            kv(&mut parts, "--max-concurrency", config.max_concurrency);
        }
    }
    if config.confidence != 0.95 {
        kv(
            &mut parts,
            "--confidence",
            format!("{:.2}", config.confidence),
        );
    }

    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> AppConfig {
        AppConfig {
            host: "www.cloudflare.com".to_string(),
            ..AppConfig::default()
        }
    }

    #[test]
    fn renders_core_flags_for_default_config() {
        let command = command_string(&base_config(), &["173.245.48.0/20".to_string()], 0, None);
        assert_eq!(
            command,
            "cleanscan --cli --host www.cloudflare.com --path /cdn-cgi/trace --port 443 \
             --cidr 173.245.48.0/20 --sample-per-cidr 100 --probes 8 --concurrency 120 \
             --timeout-ms 2500 --connect-timeout-ms 1000 --top 50"
        );
    }

    #[test]
    fn seed_is_emitted_when_concrete() {
        let command = command_string(&base_config(), &[], 12345, None);
        assert!(command.ends_with("--seed 12345"));
        let random = command_string(&base_config(), &[], 0, None);
        assert!(!random.contains("--seed"));
    }

    #[test]
    fn health_checks_replace_path() {
        let mut config = base_config();
        config.health_checks.push(crate::config::HealthCheck {
            name: "home".to_string(),
            path: "/index".to_string(),
            required: true,
            weight: 1.0,
        });
        let command = command_string(&config, &[], 0, None);
        assert!(
            !command.contains("--path"),
            "no --path when --check is present"
        );
        assert!(command.contains("--check home=/index"));
        assert!(!command.contains("/cdn-cgi/trace"));
    }

    #[test]
    fn quotes_values_with_special_characters() {
        assert_eq!(shell_quote("plain"), "plain");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(
            shell_quote("{\"packets\":\"tlshello\",\"length\":\"100-200\"}"),
            "'{\"packets\":\"tlshello\",\"length\":\"100-200\"}'"
        );
    }

    #[test]
    fn tls_fragment_and_interface_are_emitted() {
        let mut config = base_config();
        config.interface = Some("en0".to_string());
        config.tls_fragment = Some(
            crate::proxy::FragmentSpec::parse_json(
                "{\"packets\":\"tlshello\",\"length\":\"100-200\",\"interval\":\"10-20\"}",
            )
            .unwrap(),
        );
        let command = command_string(&config, &[], 0, None);
        assert!(command.contains("--interface en0"));
        assert!(command.contains("--tls-fragment '"));
    }

    #[test]
    fn syn_driver_emits_sweep_flags() {
        let mut config = base_config();
        config.discovery_driver = DiscoveryDriver::Syn;
        config.syn_rate = 10_000;
        let command = command_string(&config, &[], 0, None);
        assert!(command.contains("--discover syn"));
        assert!(command.contains("--rate 10000"));
        assert!(
            !command.contains("--syn-retrans"),
            "default retransmits omitted"
        );

        config.syn_retransmits = 3;
        let command = command_string(&config, &[], 0, None);
        assert!(command.contains("--syn-retrans 3"));
    }

    #[test]
    fn disabled_early_stop_and_warmup_flags() {
        let mut config = base_config();
        config.warmup = false;
        config.early_stop = false;
        config.early_stop_prune = false;
        config.early_stop_loss_streak = 8;
        let command = command_string(&config, &[], 0, None);
        assert!(command.contains("--no-warmup"));
        assert!(command.contains("--no-early-stop"));
        assert!(command.contains("--no-early-stop-prune"));
        assert!(command.contains("--early-stop-loss-streak 8"));
    }

    #[test]
    fn two_phase_and_adaptive_families() {
        let mut config = base_config();
        config.two_phase = true;
        config.discover_fraction = 0.4;
        config.adaptive_probing = true;
        config.max_probes = 60;
        config.adaptive_concurrency = true;
        config.max_concurrency = 300;
        let command = command_string(&config, &[], 0, None);
        assert!(command.contains("--two-phase"));
        assert!(command.contains("--discover-fraction 0.4"));
        assert!(command.contains("--adaptive-probing"));
        assert!(command.contains("--max-probes 60"));
        assert!(!command.contains("--min-probes"), "default min omitted");
        assert!(command.contains("--adaptive-concurrency"));
        assert!(command.contains("--max-concurrency 300"));
        assert!(
            !command.contains("--min-concurrency"),
            "default min omitted"
        );
    }

    #[test]
    fn confidence_and_validation_flags() {
        let mut config = base_config();
        config.confidence = 0.90;
        config.expected_statuses = vec![200, 301];
        config.required_body_markers = vec!["cloudflare".to_string()];
        config.required_headers = vec!["x-test=ok".to_string()];
        config.follow_redirects = true;
        let command = command_string(&config, &[], 0, None);
        assert!(command.contains("--confidence 0.90"));
        assert!(command.contains("--expect-status 200 --expect-status 301"));
        assert!(command.contains("--require-body cloudflare"));
        assert!(command.contains("--require-header x-test=ok"));
        assert!(command.contains("--follow-redirects"));
    }

    #[test]
    fn explicit_ips_file_is_emitted() {
        let command = command_string(&base_config(), &[], 0, Some("/tmp/targets.txt"));
        assert!(command.contains("--ips /tmp/targets.txt"));
    }
}
