use std::{
    env,
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use openmls::{
    group::{
        MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
    },
    prelude::{Capabilities, Ciphersuite},
    test_utils::OpenMlsLibcrux,
};
use uq_openmls::{
    ciphersuite::requires_external_ratchet_tree,
    core::{
        add_members, create_group, encrypt_message, export_ratchet_tree, generate_key_package,
        generate_signature_key, group_signer, process_application_message,
        process_operation_message, process_welcome, process_welcome_with_ratchet_tree,
    },
};

const GROUP_SIZES: [usize; 4] = [2, 10, 100, 200];
const CIPHERSUITES: [Ciphersuite; 3] = [
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
    Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
];
const APPLICATION_MESSAGE_BYTES: usize = 1024;
const DEFAULT_SAMPLES: usize = 5;

#[derive(Clone, Copy)]
struct ReportConfig {
    samples: usize,
}

impl ReportConfig {
    fn from_environment() -> Self {
        let samples = env::var("PQ_PERFORMANCE_SAMPLES")
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|samples: &usize| *samples > 0)
            .unwrap_or(DEFAULT_SAMPLES);
        Self { samples }
    }

    #[cfg(test)]
    fn for_test() -> Self {
        Self { samples: 0 }
    }
}

#[derive(Clone, Copy, Default)]
struct LatencySummary {
    median_ns: u128,
    p95_ns: u128,
}

struct SizeRow {
    key_package_bytes: usize,
    commit_bytes: usize,
    welcome_bytes: usize,
    group_info_bytes: usize,
    serialized_tree_bytes: usize,
    external_tree_bytes: usize,
    onboarding_payload_bytes: usize,
}

#[derive(Default)]
struct LatencyRow {
    key_package: Option<LatencySummary>,
    create_group: Option<LatencySummary>,
    add_one_member: Option<LatencySummary>,
    merge_commit: Option<LatencySummary>,
    export_tree: Option<LatencySummary>,
    process_commit: Option<LatencySummary>,
    process_welcome: Option<LatencySummary>,
    encrypt: Option<LatencySummary>,
    decrypt: Option<LatencySummary>,
}

struct FinalAddFixture {
    creator_provider: OpenMlsLibcrux,
    creator_group: MlsGroup,
    existing_member: Option<(OpenMlsLibcrux, MlsGroup)>,
    joiner_provider: OpenMlsLibcrux,
    joiner_key_package: Vec<u8>,
}

fn main() {
    print!("{}", render_report(&ReportConfig::from_environment()));
}

fn render_report(config: &ReportConfig) -> String {
    let mut report = String::new();
    report.push_str("# Post-Quantum MLS Performance Report\n\n");
    report.push_str("## Reproducibility\n\n");
    report.push_str(&format!(
        "- Command: `cargo run -p uq-openmls --release --example pq_performance_report > docs/pq-performance-report.md`\n- Samples per latency row: {}\n- Application message: {} B\n- Timing: wall-clock latency from `std::time::Instant`; not CPU time.\n- Environment: {} {} ({})\n- Rust: {}\n- Generated: UNIX epoch {}\n\n",
        config.samples,
        APPLICATION_MESSAGE_BYTES,
        env::consts::OS,
        env::consts::ARCH,
        env::consts::FAMILY,
        rust_version(),
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |value| value.as_secs()),
    ));

    report.push_str("## Artifact sizes\n\n");
    report.push_str("| Suite | Members | KeyPackage | Commit | Welcome | GroupInfo | Serialized tree | External tree | Onboarding payload |\n");
    report.push_str("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");

    let mut rows = Vec::new();
    for ciphersuite in CIPHERSUITES {
        for group_size in GROUP_SIZES {
            if config.samples == 0 {
                report.push_str(&format!(
                    "| {} | {} | N/A | N/A | N/A | N/A | N/A | N/A | N/A |\n",
                    ciphersuite_name(ciphersuite),
                    group_size
                ));
                continue;
            }
            let sizes = measure_size_row(ciphersuite, group_size);
            report.push_str(&format!(
                "| {} | {} | {} B | {} B | {} B | {} B | {} B | {} B | {} B |\n",
                ciphersuite_name(ciphersuite),
                group_size,
                sizes.key_package_bytes,
                sizes.commit_bytes,
                sizes.welcome_bytes,
                sizes.group_info_bytes,
                sizes.serialized_tree_bytes,
                sizes.external_tree_bytes,
                sizes.onboarding_payload_bytes,
            ));
            rows.push((
                ciphersuite,
                group_size,
                sizes,
                measure_latency_row(ciphersuite, group_size, config.samples),
            ));
        }
    }

    report.push_str("\n## Runtime latency\n\n");
    report.push_str("Each cell is `median / p95` in milliseconds. `N/A` means the operation does not apply: external-tree export for embedded-tree suites, or Commit processing with no existing member at size 2.\n\n");
    report.push_str("| Suite | Members | KeyPackage | Create group | Add one member | Merge Commit | Export tree | Process Commit | Process Welcome | Encrypt 1 KiB | Decrypt 1 KiB |\n");
    report.push_str(
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n",
    );
    for (ciphersuite, group_size, _, latency) in &rows {
        report.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            ciphersuite_name(*ciphersuite),
            group_size,
            format_latency(latency.key_package),
            format_latency(latency.create_group),
            format_latency(latency.add_one_member),
            format_latency(latency.merge_commit),
            format_latency(latency.export_tree),
            format_latency(latency.process_commit),
            format_latency(latency.process_welcome),
            format_latency(latency.encrypt),
            format_latency(latency.decrypt),
        ));
    }

    report.push_str("\n## Trade-off summary\n\n");
    report.push_str("At 100 members, relative to classic at the same row:\n\n");
    report.push_str("| Suite | Onboarding payload ratio | Add-one-member median ratio |\n| --- | ---: | ---: |\n");
    if config.samples > 0 {
        let classic = rows
            .iter()
            .find(|(suite, size, _, _)| *suite == CIPHERSUITES[0] && *size == 100);
        for suite in CIPHERSUITES {
            let row = rows
                .iter()
                .find(|(row_suite, size, _, _)| *row_suite == suite && *size == 100);
            if let (Some((_, _, classic_sizes, classic_latency)), Some((_, _, sizes, latency))) =
                (classic, row)
            {
                report.push_str(&format!(
                    "| {} | {:.2}x | {:.2}x |\n",
                    ciphersuite_name(suite),
                    sizes.onboarding_payload_bytes as f64
                        / classic_sizes.onboarding_payload_bytes as f64,
                    ratio(latency.add_one_member, classic_latency.add_one_member),
                ));
            }
        }
    }

    report
}

fn measure_size_row(ciphersuite: Ciphersuite, group_size: usize) -> SizeRow {
    let mut fixture = bootstrap_fixture(ciphersuite, group_size - 1);
    let key_package_bytes = fixture.joiner_key_package.len();
    let signer =
        group_signer(&fixture.creator_group, &fixture.creator_provider).expect("creator signer");
    let add = add_members(
        &mut fixture.creator_group,
        &fixture.creator_provider,
        &signer,
        std::slice::from_ref(&fixture.joiner_key_package),
    )
    .expect("final add");
    fixture
        .creator_group
        .merge_pending_commit(&fixture.creator_provider)
        .expect("merge final add");
    let serialized_tree = export_ratchet_tree(&fixture.creator_group).expect("serialize tree");
    let external_tree_bytes = if requires_external_ratchet_tree(ciphersuite) {
        serialized_tree.len()
    } else {
        0
    };
    let group_info_bytes = add.group_info.as_ref().map_or(0, Vec::len);

    SizeRow {
        key_package_bytes,
        commit_bytes: add.commit.len(),
        welcome_bytes: add.welcome.len(),
        group_info_bytes,
        serialized_tree_bytes: serialized_tree.len(),
        external_tree_bytes,
        onboarding_payload_bytes: add.welcome.len()
            + add.commit.len()
            + group_info_bytes
            + external_tree_bytes,
    }
}

fn measure_latency_row(ciphersuite: Ciphersuite, group_size: usize, samples: usize) -> LatencyRow {
    let mut row = LatencyRow {
        key_package: Some(measure_key_package(samples, ciphersuite)),
        create_group: Some(measure_create_group(samples, ciphersuite)),
        add_one_member: Some(measure_add_one_member(samples, ciphersuite, group_size)),
        merge_commit: Some(measure_merge_commit(samples, ciphersuite, group_size)),
        process_welcome: Some(measure_process_welcome(samples, ciphersuite, group_size)),
        encrypt: Some(measure_encrypt(samples, ciphersuite, group_size)),
        decrypt: Some(measure_decrypt(samples, ciphersuite, group_size)),
        ..Default::default()
    };
    if requires_external_ratchet_tree(ciphersuite) {
        row.export_tree = Some(measure_export_tree(samples, ciphersuite, group_size));
    }
    if group_size > 2 {
        row.process_commit = Some(measure_process_commit(samples, ciphersuite, group_size));
    }
    row
}

fn bootstrap_fixture(ciphersuite: Ciphersuite, member_count: usize) -> FinalAddFixture {
    let creator_provider = OpenMlsLibcrux::default();
    let group_id = format!("pq-performance-{ciphersuite:?}-{member_count}");
    let mut creator_group = create_group(
        &creator_provider,
        "creator",
        &group_id,
        ciphersuite,
        &create_config(ciphersuite),
        None,
    )
    .expect("create group");
    let joiner_provider = OpenMlsLibcrux::default();
    let joiner_key_package =
        generate_key_package_for("final-joiner", &joiner_provider, ciphersuite);
    let initial_members = member_count.saturating_sub(1);
    let mut initial = Vec::with_capacity(initial_members);
    let mut key_packages = Vec::with_capacity(initial_members);
    for index in 0..initial_members {
        let provider = OpenMlsLibcrux::default();
        key_packages.push(generate_key_package_for(
            &format!("member-{index}"),
            &provider,
            ciphersuite,
        ));
        initial.push(provider);
    }
    let mut existing_member = None;
    if !key_packages.is_empty() {
        let signer = group_signer(&creator_group, &creator_provider).expect("creator signer");
        let add = add_members(
            &mut creator_group,
            &creator_provider,
            &signer,
            &key_packages,
        )
        .expect("bootstrap add");
        creator_group
            .merge_pending_commit(&creator_provider)
            .expect("bootstrap merge");
        let provider = initial.remove(0);
        let tree = requires_external_ratchet_tree(ciphersuite)
            .then(|| export_ratchet_tree(&creator_group).expect("bootstrap tree"));
        let group = join_group(&provider, ciphersuite, &add.welcome, tree.as_deref());
        existing_member = Some((provider, group));
    }
    FinalAddFixture {
        creator_provider,
        creator_group,
        existing_member,
        joiner_provider,
        joiner_key_package,
    }
}

fn generate_key_package_for(
    identity: &str,
    provider: &OpenMlsLibcrux,
    ciphersuite: Ciphersuite,
) -> Vec<u8> {
    let signer = generate_signature_key(provider, ciphersuite).expect("signature key");
    generate_key_package(
        identity,
        provider,
        ciphersuite,
        false,
        Some(signer.public().to_vec()),
    )
    .expect("key package")
}

fn final_add(fixture: &mut FinalAddFixture) -> uq_openmls::core::AddMembersResult {
    let signer =
        group_signer(&fixture.creator_group, &fixture.creator_provider).expect("creator signer");
    add_members(
        &mut fixture.creator_group,
        &fixture.creator_provider,
        &signer,
        std::slice::from_ref(&fixture.joiner_key_package),
    )
    .expect("final add")
}

fn join_group(
    provider: &OpenMlsLibcrux,
    ciphersuite: Ciphersuite,
    welcome: &[u8],
    tree: Option<&[u8]>,
) -> MlsGroup {
    if let Some(tree) = tree {
        process_welcome_with_ratchet_tree(provider, welcome, &join_config(ciphersuite), tree)
            .expect("process external-tree welcome")
    } else {
        process_welcome(provider, welcome, &join_config(ciphersuite))
            .expect("process embedded-tree welcome")
    }
}

fn measure_prepared<Input, Output>(
    samples: usize,
    mut setup: impl FnMut() -> Input,
    mut operation: impl FnMut(Input) -> Output,
) -> LatencySummary {
    let mut durations = Vec::with_capacity(samples);
    for _ in 0..samples {
        let input = setup();
        let start = Instant::now();
        std::hint::black_box(operation(input));
        durations.push(start.elapsed());
    }
    summarize(&mut durations)
}

fn measure_key_package(samples: usize, ciphersuite: Ciphersuite) -> LatencySummary {
    measure_prepared(
        samples,
        || {
            let provider = OpenMlsLibcrux::default();
            let signer = generate_signature_key(&provider, ciphersuite).expect("signature key");
            (provider, signer)
        },
        |(provider, signer)| {
            generate_key_package(
                "sample",
                &provider,
                ciphersuite,
                false,
                Some(signer.public().to_vec()),
            )
            .expect("key package")
        },
    )
}

fn measure_create_group(samples: usize, ciphersuite: Ciphersuite) -> LatencySummary {
    measure_prepared(samples, OpenMlsLibcrux::default, |provider| {
        create_group(
            &provider,
            "sample",
            "sample-group",
            ciphersuite,
            &create_config(ciphersuite),
            None,
        )
        .expect("create group")
    })
}

fn measure_add_one_member(
    samples: usize,
    ciphersuite: Ciphersuite,
    group_size: usize,
) -> LatencySummary {
    measure_prepared(
        samples,
        || bootstrap_fixture(ciphersuite, group_size - 1),
        |mut fixture| final_add(&mut fixture),
    )
}

fn measure_merge_commit(
    samples: usize,
    ciphersuite: Ciphersuite,
    group_size: usize,
) -> LatencySummary {
    measure_prepared(
        samples,
        || {
            let mut fixture = bootstrap_fixture(ciphersuite, group_size - 1);
            let _ = final_add(&mut fixture);
            fixture
        },
        |mut fixture| {
            fixture
                .creator_group
                .merge_pending_commit(&fixture.creator_provider)
                .expect("merge final add")
        },
    )
}

fn measure_export_tree(
    samples: usize,
    ciphersuite: Ciphersuite,
    group_size: usize,
) -> LatencySummary {
    measure_prepared(
        samples,
        || {
            let mut fixture = bootstrap_fixture(ciphersuite, group_size - 1);
            let _ = final_add(&mut fixture);
            fixture
                .creator_group
                .merge_pending_commit(&fixture.creator_provider)
                .expect("merge final add");
            fixture
        },
        |fixture| export_ratchet_tree(&fixture.creator_group).expect("export tree"),
    )
}

fn measure_process_commit(
    samples: usize,
    ciphersuite: Ciphersuite,
    group_size: usize,
) -> LatencySummary {
    measure_prepared(
        samples,
        || {
            let mut fixture = bootstrap_fixture(ciphersuite, group_size - 1);
            let add = final_add(&mut fixture);
            fixture
                .creator_group
                .merge_pending_commit(&fixture.creator_provider)
                .expect("merge final add");
            let (provider, group) = fixture.existing_member.take().expect("existing member");
            (provider, group, add.commit)
        },
        |(provider, mut group, commit)| {
            process_operation_message(&mut group, &provider, &commit).expect("process commit")
        },
    )
}

fn measure_process_welcome(
    samples: usize,
    ciphersuite: Ciphersuite,
    group_size: usize,
) -> LatencySummary {
    measure_prepared(
        samples,
        || {
            let mut fixture = bootstrap_fixture(ciphersuite, group_size - 1);
            let add = final_add(&mut fixture);
            fixture
                .creator_group
                .merge_pending_commit(&fixture.creator_provider)
                .expect("merge final add");
            let tree = requires_external_ratchet_tree(ciphersuite)
                .then(|| export_ratchet_tree(&fixture.creator_group).expect("export tree"));
            (fixture.joiner_provider, add.welcome, tree)
        },
        |(provider, welcome, tree)| join_group(&provider, ciphersuite, &welcome, tree.as_deref()),
    )
}

fn measure_encrypt(samples: usize, ciphersuite: Ciphersuite, group_size: usize) -> LatencySummary {
    measure_prepared(
        samples,
        || {
            let mut fixture = bootstrap_fixture(ciphersuite, group_size - 1);
            let _ = final_add(&mut fixture);
            fixture
                .creator_group
                .merge_pending_commit(&fixture.creator_provider)
                .expect("merge final add");
            let signer = group_signer(&fixture.creator_group, &fixture.creator_provider)
                .expect("creator signer");
            (fixture.creator_provider, fixture.creator_group, signer)
        },
        |(provider, mut group, signer)| {
            encrypt_message(
                &mut group,
                &provider,
                &signer,
                &[0xA5; APPLICATION_MESSAGE_BYTES],
            )
            .expect("encrypt")
        },
    )
}

fn measure_decrypt(samples: usize, ciphersuite: Ciphersuite, group_size: usize) -> LatencySummary {
    measure_prepared(
        samples,
        || {
            let mut fixture = bootstrap_fixture(ciphersuite, group_size - 1);
            let add = final_add(&mut fixture);
            fixture
                .creator_group
                .merge_pending_commit(&fixture.creator_provider)
                .expect("merge final add");
            let tree = requires_external_ratchet_tree(ciphersuite)
                .then(|| export_ratchet_tree(&fixture.creator_group).expect("export tree"));
            let joiner = join_group(
                &fixture.joiner_provider,
                ciphersuite,
                &add.welcome,
                tree.as_deref(),
            );
            let signer = group_signer(&fixture.creator_group, &fixture.creator_provider)
                .expect("creator signer");
            let ciphertext = encrypt_message(
                &mut fixture.creator_group,
                &fixture.creator_provider,
                &signer,
                &[0xA5; APPLICATION_MESSAGE_BYTES],
            )
            .expect("encrypt");
            (fixture.joiner_provider, joiner, ciphertext)
        },
        |(provider, mut group, ciphertext)| {
            process_application_message(&mut group, &provider, &ciphertext).expect("decrypt")
        },
    )
}

fn summarize(samples: &mut [Duration]) -> LatencySummary {
    samples.sort_unstable();
    let median_ns = samples[samples.len() / 2].as_nanos();
    let p95_index = (samples.len() * 95).div_ceil(100).saturating_sub(1);
    LatencySummary {
        median_ns,
        p95_ns: samples[p95_index].as_nanos(),
    }
}

fn create_config(ciphersuite: Ciphersuite) -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .capabilities(Capabilities::new(
            None,
            Some(&[ciphersuite]),
            None,
            None,
            None,
        ))
        .use_ratchet_tree_extension(!requires_external_ratchet_tree(ciphersuite))
        .build()
}
fn join_config(ciphersuite: Ciphersuite) -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(!requires_external_ratchet_tree(ciphersuite))
        .build()
}
fn ciphersuite_name(ciphersuite: Ciphersuite) -> &'static str {
    match ciphersuite {
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
            "classic_x25519_chacha_ed25519"
        }
        Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => "xwing_chacha_ed25519",
        Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87 => {
            "mlkem1024_aes256_sha384_mldsa87"
        }
        _ => "out_of_scope",
    }
}
fn format_latency(latency: Option<LatencySummary>) -> String {
    latency.map_or_else(
        || "N/A".to_owned(),
        |value| {
            format!(
                "{:.3} / {:.3}",
                value.median_ns as f64 / 1_000_000.0,
                value.p95_ns as f64 / 1_000_000.0
            )
        },
    )
}
fn ratio(value: Option<LatencySummary>, baseline: Option<LatencySummary>) -> f64 {
    match (value, baseline) {
        (Some(value), Some(baseline)) if baseline.median_ns > 0 => {
            value.median_ns as f64 / baseline.median_ns as f64
        }
        _ => f64::NAN,
    }
}
fn rust_version() -> String {
    Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|| "unknown".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_includes_every_suite_and_group_size() {
        let report = render_report(&ReportConfig::for_test());
        assert!(report.contains("classic_x25519_chacha_ed25519"));
        assert!(report.contains("xwing_chacha_ed25519"));
        assert!(report.contains("mlkem1024_aes256_sha384_mldsa87"));
        assert!(report.contains("| 200 |"));
    }

    #[test]
    fn summary_uses_nearest_rank_p95() {
        let mut samples = vec![
            Duration::from_millis(1),
            Duration::from_millis(2),
            Duration::from_millis(3),
            Duration::from_millis(4),
            Duration::from_millis(5),
        ];
        let summary = summarize(&mut samples);
        assert_eq!(summary.median_ns, 3_000_000);
        assert_eq!(summary.p95_ns, 5_000_000);
    }

    #[test]
    fn full_pq_join_uses_tree_exported_after_merging_the_final_commit() {
        let ciphersuite = Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87;
        let mut fixture = bootstrap_fixture(ciphersuite, 1);
        let add = final_add(&mut fixture);
        fixture
            .creator_group
            .merge_pending_commit(&fixture.creator_provider)
            .expect("merge final add");
        let tree = export_ratchet_tree(&fixture.creator_group).expect("export tree");

        let joiner = join_group(
            &fixture.joiner_provider,
            ciphersuite,
            &add.welcome,
            Some(&tree),
        );
        assert_eq!(joiner.members().count(), 2);
    }
}
