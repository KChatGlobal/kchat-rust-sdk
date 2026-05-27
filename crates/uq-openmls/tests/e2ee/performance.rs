use std::{
    env, fs,
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use openmls::group::MlsGroupCreateConfig;
use uq_openmls::{
    core::{
        DEFAULT_CIPHERSUITE, add_members, create_group, encrypt_message, generate_key_package,
        group, group_signer, merge_pending_commit,
    },
    provider::SqliteProvider,
};

const GROUP_ID: &str = "perf_group_encrypt";
const CREATOR_ID: &str = "perf_creator";

fn parse_env_usize(name: &str, default_value: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default_value)
}

fn unique_temp_storage_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    env::temp_dir().join(format!("{prefix}_{pid}_{nanos}.db"))
}

fn cleanup_sqlite_files(storage_path: &PathBuf) {
    let _ = fs::remove_file(storage_path);
    let _ = fs::remove_file(storage_path.with_extension("db-shm"));
    let _ = fs::remove_file(storage_path.with_extension("db-wal"));
}

fn setup_large_group(
    provider: &SqliteProvider,
    member_count: usize,
    max_past_epochs: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(DEFAULT_CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .max_past_epochs(max_past_epochs)
        .build();

    create_group(
        provider,
        CREATOR_ID,
        GROUP_ID,
        DEFAULT_CIPHERSUITE,
        &config,
        None,
    )?;

    let mut key_packages = Vec::with_capacity(member_count);
    for idx in 0..member_count {
        let member_id = format!("perf_member_{idx}");
        let key_package =
            generate_key_package(&member_id, provider, DEFAULT_CIPHERSUITE, false, None)?;
        key_packages.push(key_package);
    }

    let mut mls_group = group(provider, GROUP_ID, [])?;
    let signer = group_signer(&mls_group, provider)?;
    let _ = add_members(&mut mls_group, provider, &signer, &key_packages)?;
    merge_pending_commit(&mut mls_group, provider)?;

    Ok(())
}

fn measure_encrypt_no_cache(
    provider: &SqliteProvider,
    iterations: usize,
) -> Result<Duration, Box<dyn std::error::Error>> {
    let start = Instant::now();
    for idx in 0..iterations {
        let mut mls_group = group(provider, GROUP_ID, [])?;
        let signer = group_signer(&mls_group, provider)?;
        let payload = format!("perf_no_cache_{idx}").into_bytes();
        let _ = encrypt_message(&mut mls_group, provider, &signer, &payload)?;
    }
    Ok(start.elapsed())
}

fn measure_encrypt_cache(
    provider: &SqliteProvider,
    iterations: usize,
) -> Result<Duration, Box<dyn std::error::Error>> {
    let mut mls_group = group(provider, GROUP_ID, [])?;
    let signer = group_signer(&mls_group, provider)?;

    let start = Instant::now();
    for idx in 0..iterations {
        let payload = format!("perf_cache_{idx}").into_bytes();
        let _ = encrypt_message(&mut mls_group, provider, &signer, &payload)?;
    }
    Ok(start.elapsed())
}

#[test]
#[ignore = "Performance test, run manually: cargo test -p uq-openmls --test e2ee compare_encrypt_message_no_cache_vs_cache -- --ignored --nocapture"]
fn compare_encrypt_message_no_cache_vs_cache() -> Result<(), Box<dyn std::error::Error>> {
    let member_count = parse_env_usize("PERF_MEMBER_COUNT", 1200);
    let iterations = parse_env_usize("PERF_ENCRYPT_ITERATIONS", 100);
    let max_past_epochs = parse_env_usize("PERF_MAX_PAST_EPOCHS", 1200);

    let no_cache_storage_path = unique_temp_storage_path("mls_perf_no_cache");
    let cache_storage_path = unique_temp_storage_path("mls_perf_cache");

    let no_cache_provider =
        SqliteProvider::new(no_cache_storage_path.to_string_lossy().as_ref(), &None)?;
    setup_large_group(&no_cache_provider, member_count, max_past_epochs)?;

    let cache_provider = SqliteProvider::new(cache_storage_path.to_string_lossy().as_ref(), &None)?;
    setup_large_group(&cache_provider, member_count, max_past_epochs)?;

    let no_cache_duration = measure_encrypt_no_cache(&no_cache_provider, iterations)?;
    let cache_duration = measure_encrypt_cache(&cache_provider, iterations)?;

    let speedup = no_cache_duration.as_secs_f64() / cache_duration.as_secs_f64();
    println!(
        "encrypt_message perf compare: members={member_count}, iterations={iterations}, max_past_epochs={max_past_epochs}, no_cache={:?}, cache={:?}, speedup={:.2}x",
        no_cache_duration, cache_duration, speedup
    );

    cleanup_sqlite_files(&no_cache_storage_path);
    cleanup_sqlite_files(&cache_storage_path);

    assert!(
        cache_duration < no_cache_duration,
        "expected cache path faster than no-cache path, got no_cache={:?}, cache={:?}",
        no_cache_duration,
        cache_duration
    );

    Ok(())
}
