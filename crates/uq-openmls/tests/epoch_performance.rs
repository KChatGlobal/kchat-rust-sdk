use std::{
    env, fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use openmls::group::{GroupId, MlsGroupCreateConfig, MlsGroupJoinConfig};
use openmls_traits::OpenMlsProvider;
use rusqlite::params;
use uq_openmls::{
    core::{self, DEFAULT_CIPHERSUITE},
    provider::SqliteProvider,
};

static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeMode {
    Legacy,
    Current,
}

#[derive(Debug)]
struct Timing {
    legacy: Duration,
    current: Duration,
}

impl Timing {
    fn speedup(&self) -> f64 {
        self.legacy.as_secs_f64() / self.current.as_secs_f64()
    }
}

struct ProviderFixture {
    provider: SqliteProvider,
    db_path: PathBuf,
}

impl ProviderFixture {
    fn new(name: &str) -> Self {
        let db_path = temp_db_path(name);
        let db_path_str = db_path.to_string_lossy().into_owned();
        let provider = SqliteProvider::new(&db_path_str, &None).expect("should create provider");
        Self { provider, db_path }
    }
}

impl Drop for ProviderFixture {
    fn drop(&mut self) {
        cleanup_sqlite_files(&self.db_path);
    }
}

struct Pair {
    alice: ProviderFixture,
    bob: ProviderFixture,
    group_id: String,
}

struct SingleGroup {
    fixture: ProviderFixture,
    group_id: String,
}

struct WelcomeFixture {
    bob: ProviderFixture,
    welcome: Vec<u8>,
}

struct JoinExternalFixture {
    joiner: ProviderFixture,
    group_info: Vec<u8>,
}

struct ReaddFixture {
    alice: ProviderFixture,
    _bob: ProviderFixture,
    _charlie: ProviderFixture,
    group_id: String,
    bob_id: String,
    bob_key_package: Vec<u8>,
}

fn temp_db_path(name: &str) -> PathBuf {
    let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    env::temp_dir().join(format!(
        "uq-openmls-epoch-performance-{name}-{}-{counter}-{nanos}.sqlite",
        std::process::id()
    ))
}

fn cleanup_sqlite_files(path: &PathBuf) {
    let path = path.to_string_lossy();
    let _ = fs::remove_file(path.as_ref());
    let _ = fs::remove_file(format!("{path}-wal"));
    let _ = fs::remove_file(format!("{path}-shm"));
}

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn create_config(max_past_epochs: usize) -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(DEFAULT_CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .max_past_epochs(max_past_epochs)
        .build()
}

fn join_config(max_past_epochs: usize) -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .max_past_epochs(max_past_epochs)
        .build()
}

fn to_group_id(group_id: &str) -> GroupId {
    GroupId::from_slice(group_id.as_bytes())
}

fn has_legacy_message_secrets(provider: &SqliteProvider, group_id: &str) -> bool {
    let connection = provider
        .storage()
        .connection_pool()
        .checkout()
        .expect("should get sqlite connection");
    let group_id_blob =
        serde_json::to_vec(&to_group_id(group_id)).expect("should serialize group id");
    connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1
                FROM openmls_group_data
                WHERE provider_version = ?1
                    AND group_id = ?2
                    AND data_type = 'message_secrets'
            )",
            params![
                kchat_storage_provider::STORAGE_PROVIDER_VERSION,
                group_id_blob
            ],
            |row| row.get::<_, i64>(0),
        )
        .expect("should check legacy message secrets")
        != 0
}

fn force_legacy_load(provider: &SqliteProvider, group_id: &str) {
    if !has_legacy_message_secrets(provider, group_id) {
        return;
    }
    provider
        .storage()
        .mark_group_epoch_message_secrets_migrated(&to_group_id(group_id), false)
        .expect("should force legacy group load");
}

fn after_mutation(provider: &SqliteProvider, mode: RuntimeMode, group_id: &str) {
    if matches!(mode, RuntimeMode::Legacy) {
        force_legacy_load(provider, group_id);
    }
}

fn load_group(
    provider: &SqliteProvider,
    mode: RuntimeMode,
    group_id: &str,
) -> openmls::prelude::MlsGroup {
    load_group_with_messages(provider, mode, group_id, std::iter::empty())
}

fn load_group_with_messages<'a, Messages>(
    provider: &SqliteProvider,
    mode: RuntimeMode,
    group_id: &str,
    messages: Messages,
) -> openmls::prelude::MlsGroup
where
    Messages: IntoIterator<Item = &'a [u8]>,
{
    if matches!(mode, RuntimeMode::Legacy) {
        force_legacy_load(provider, group_id);
        return openmls::group::MlsGroup::load(provider.storage(), &to_group_id(group_id))
            .expect("should load full-window group")
            .expect("group should exist");
    }
    core::group(provider, group_id, messages).expect("should load group")
}

fn create_group(
    provider: &SqliteProvider,
    mode: RuntimeMode,
    user_id: &str,
    group_id: &str,
    max_past_epochs: usize,
) {
    core::create_group(
        provider,
        user_id,
        group_id,
        DEFAULT_CIPHERSUITE,
        &create_config(max_past_epochs),
        None,
    )
    .expect("should create group");
    after_mutation(provider, mode, group_id);
}

fn process_welcome(
    provider: &SqliteProvider,
    mode: RuntimeMode,
    welcome: &[u8],
    group_id: &str,
    max_past_epochs: usize,
) {
    core::process_welcome(provider, welcome, &join_config(max_past_epochs))
        .expect("should process welcome");
    after_mutation(provider, mode, group_id);
}

fn generate_key_package(user_id: &str, provider: &SqliteProvider) -> Vec<u8> {
    core::generate_key_package(user_id, provider, DEFAULT_CIPHERSUITE, true, None)
        .expect("should generate key package")
}

fn add_member(
    provider: &SqliteProvider,
    mode: RuntimeMode,
    group_id: &str,
    key_package: Vec<u8>,
) -> core::AddMembersResult {
    let mut group = load_group(provider, mode, group_id);
    let signer = core::group_signer(&group, provider).expect("should load signer");
    let result = core::add_members(&mut group, provider, &signer, &[key_package])
        .expect("should add member");
    after_mutation(provider, mode, group_id);
    result
}

fn merge_pending_commit(provider: &SqliteProvider, mode: RuntimeMode, group_id: &str) {
    let mut group = load_group(provider, mode, group_id);
    core::merge_pending_commit(&mut group, provider).expect("should merge pending commit");
    after_mutation(provider, mode, group_id);
}

fn update_leaf_node(
    provider: &SqliteProvider,
    mode: RuntimeMode,
    group_id: &str,
) -> core::UpdateLeafNodeResult {
    let mut group = load_group(provider, mode, group_id);
    let signer = core::group_signer(&group, provider).expect("should load signer");
    let result =
        core::update_leaf_node(&mut group, provider, &signer).expect("should update leaf node");
    after_mutation(provider, mode, group_id);
    result
}

fn process_operation_message(
    provider: &SqliteProvider,
    mode: RuntimeMode,
    group_id: &str,
    message: &[u8],
) {
    let mut group = load_group_with_messages(provider, mode, group_id, [message]);
    core::process_operation_message(&mut group, provider, message)
        .expect("should process operation message");
    after_mutation(provider, mode, group_id);
}

fn process_many_operation_messages(
    provider: &SqliteProvider,
    mode: RuntimeMode,
    group_id: &str,
    messages: &[Vec<u8>],
) {
    let mut group =
        load_group_with_messages(provider, mode, group_id, messages.iter().map(Vec::as_slice));
    core::process_many_operation_messages(&mut group, provider, messages, None)
        .expect("should process operation batch");
    after_mutation(provider, mode, group_id);
}

fn process_proposal_message(
    provider: &SqliteProvider,
    mode: RuntimeMode,
    group_id: &str,
    message: &[u8],
) {
    let mut group = load_group_with_messages(provider, mode, group_id, [message]);
    core::process_proposal_message(&mut group, provider, message)
        .expect("should process proposal message");
    after_mutation(provider, mode, group_id);
}

fn encrypt_message(
    provider: &SqliteProvider,
    mode: RuntimeMode,
    group_id: &str,
    message: &[u8],
) -> Vec<u8> {
    let mut group = load_group(provider, mode, group_id);
    let signer = core::group_signer(&group, provider).expect("should load signer");
    let ciphertext =
        core::encrypt_message(&mut group, provider, &signer, message).expect("should encrypt");
    after_mutation(provider, mode, group_id);
    ciphertext
}

fn process_application_message(
    provider: &SqliteProvider,
    mode: RuntimeMode,
    group_id: &str,
    message: &[u8],
) {
    let mut group = load_group_with_messages(provider, mode, group_id, [message]);
    let result = core::process_application_message(&mut group, provider, message)
        .expect("should process app message");
    assert!(result.message.starts_with(b"message-"));
    after_mutation(provider, mode, group_id);
}

fn leave_group(provider: &SqliteProvider, mode: RuntimeMode, group_id: &str) -> Vec<u8> {
    let mut group = load_group(provider, mode, group_id);
    let signer = core::group_signer(&group, provider).expect("should load signer");
    let result = core::leave_group(&mut group, provider, &signer).expect("should leave group");
    after_mutation(provider, mode, group_id);
    result.proposal
}

fn remove_members(
    provider: &SqliteProvider,
    mode: RuntimeMode,
    group_id: &str,
    member_ids: &[&str],
) {
    let mut group = load_group(provider, mode, group_id);
    let signer = core::group_signer(&group, provider).expect("should load signer");
    core::remove_members(&mut group, provider, &signer, member_ids).expect("should remove member");
    after_mutation(provider, mode, group_id);
}

fn readd(
    provider: &SqliteProvider,
    mode: RuntimeMode,
    group_id: &str,
    member_ids: &[&str],
    key_packages: &[Vec<u8>],
) {
    let mut group = load_group(provider, mode, group_id);
    let signer = core::group_signer(&group, provider).expect("should load signer");
    core::readd(&mut group, provider, &signer, member_ids, key_packages).expect("should readd");
    after_mutation(provider, mode, group_id);
}

fn export_group_info(provider: &SqliteProvider, mode: RuntimeMode, group_id: &str) -> Vec<u8> {
    let group = load_group(provider, mode, group_id);
    let signer = core::group_signer(&group, provider).expect("should load signer");
    core::export_group_info(&group, provider, &signer).expect("should export group info")
}

fn join_by_external_commit(
    provider: &SqliteProvider,
    mode: RuntimeMode,
    client_id: &str,
    group_info: &[u8],
    max_past_epochs: usize,
) {
    core::join_by_external_commit(
        provider,
        client_id,
        group_info,
        DEFAULT_CIPHERSUITE,
        &join_config(max_past_epochs),
        None,
    )
    .expect("should join by external commit");
    let _ = mode;
}

fn advance_epoch(pair: &Pair, mode: RuntimeMode) {
    let update = update_leaf_node(&pair.alice.provider, mode, &pair.group_id);
    merge_pending_commit(&pair.alice.provider, mode, &pair.group_id);
    process_operation_message(&pair.bob.provider, mode, &pair.group_id, &update.commit);
}

fn setup_pair(
    mode: RuntimeMode,
    name: &str,
    max_past_epochs: usize,
    history_epochs: usize,
) -> Pair {
    let alice = ProviderFixture::new(&format!("{name}-alice"));
    let bob = ProviderFixture::new(&format!("{name}-bob"));
    let group_id = format!("{name}-group");

    create_group(&alice.provider, mode, "alice", &group_id, max_past_epochs);
    let bob_key_package = generate_key_package("bob", &bob.provider);
    let core::AddMembersResult { welcome, .. } =
        add_member(&alice.provider, mode, &group_id, bob_key_package);
    merge_pending_commit(&alice.provider, mode, &group_id);
    process_welcome(&bob.provider, mode, &welcome, &group_id, max_past_epochs);

    let pair = Pair {
        alice,
        bob,
        group_id,
    };

    for _ in 0..history_epochs {
        advance_epoch(&pair, mode);
    }
    pair
}

fn setup_single_group(
    mode: RuntimeMode,
    name: &str,
    max_past_epochs: usize,
    history_epochs: usize,
) -> SingleGroup {
    let fixture = ProviderFixture::new(name);
    let group_id = format!("{name}-group");
    create_group(&fixture.provider, mode, "alice", &group_id, max_past_epochs);
    let group = SingleGroup { fixture, group_id };
    for _ in 0..history_epochs {
        update_leaf_node(&group.fixture.provider, mode, &group.group_id);
        merge_pending_commit(&group.fixture.provider, mode, &group.group_id);
    }
    group
}

fn encrypt_messages(pair: &Pair, mode: RuntimeMode, count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|index| {
            encrypt_message(
                &pair.alice.provider,
                mode,
                &pair.group_id,
                format!("message-{index}").as_bytes(),
            )
        })
        .collect()
}

fn measure_encrypt(pair: &Pair, mode: RuntimeMode, iterations: usize) -> Duration {
    let start = Instant::now();
    for index in 0..iterations {
        encrypt_message(
            &pair.alice.provider,
            mode,
            &pair.group_id,
            format!("encrypt-benchmark-{index}").as_bytes(),
        );
    }
    start.elapsed()
}

fn measure_process_current(pair: &Pair, mode: RuntimeMode, iterations: usize) -> Duration {
    let messages = encrypt_messages(pair, mode, iterations);
    let start = Instant::now();
    for message in messages {
        process_application_message(&pair.bob.provider, mode, &pair.group_id, &message);
    }
    start.elapsed()
}

fn measure_process_past(pair: &Pair, mode: RuntimeMode, iterations: usize) -> Duration {
    let messages = encrypt_messages(pair, mode, iterations);
    advance_epoch(pair, mode);
    let start = Instant::now();
    for message in messages {
        process_application_message(&pair.bob.provider, mode, &pair.group_id, &message);
    }
    start.elapsed()
}

fn measure_epoch_advance_roundtrip(pair: &Pair, mode: RuntimeMode, iterations: usize) -> Duration {
    let start = Instant::now();
    for _ in 0..iterations {
        advance_epoch(pair, mode);
    }
    start.elapsed()
}

fn measure_process_operation_message(
    pair: &Pair,
    mode: RuntimeMode,
    iterations: usize,
) -> Duration {
    let mut elapsed = Duration::ZERO;
    for _ in 0..iterations {
        let update = update_leaf_node(&pair.alice.provider, mode, &pair.group_id);
        merge_pending_commit(&pair.alice.provider, mode, &pair.group_id);
        let start = Instant::now();
        process_operation_message(&pair.bob.provider, mode, &pair.group_id, &update.commit);
        elapsed += start.elapsed();
    }
    elapsed
}

fn measure_process_many_operation_messages(
    pair: &Pair,
    mode: RuntimeMode,
    iterations: usize,
) -> Duration {
    let batch_size = env_usize("EPOCH_PERF_OPERATION_BATCH_SIZE", 5);
    let mut elapsed = Duration::ZERO;
    for _ in 0..iterations {
        let mut messages = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            let update = update_leaf_node(&pair.alice.provider, mode, &pair.group_id);
            merge_pending_commit(&pair.alice.provider, mode, &pair.group_id);
            messages.push(update.commit);
        }
        let start = Instant::now();
        process_many_operation_messages(&pair.bob.provider, mode, &pair.group_id, &messages);
        elapsed += start.elapsed();
    }
    elapsed
}

fn measure_process_proposal_message(pair: &Pair, mode: RuntimeMode, iterations: usize) -> Duration {
    let mut elapsed = Duration::ZERO;
    for _ in 0..iterations {
        let proposal = leave_group(&pair.bob.provider, mode, &pair.group_id);
        let start = Instant::now();
        process_proposal_message(&pair.alice.provider, mode, &pair.group_id, &proposal);
        elapsed += start.elapsed();
    }
    elapsed
}

fn measure_leave_group(pair: &Pair, mode: RuntimeMode, iterations: usize) -> Duration {
    let start = Instant::now();
    for _ in 0..iterations {
        leave_group(&pair.bob.provider, mode, &pair.group_id);
    }
    start.elapsed()
}

fn measure_add_members(group: &SingleGroup, mode: RuntimeMode, iterations: usize) -> Duration {
    let members: Vec<_> = (0..iterations)
        .map(|index| {
            let fixture = ProviderFixture::new(&format!("add-member-{mode:?}-{index}"));
            let key_package =
                generate_key_package(&format!("add-member-{index}"), &fixture.provider);
            (fixture, key_package)
        })
        .collect();

    let mut elapsed = Duration::ZERO;
    for (_, key_package) in &members {
        let start = Instant::now();
        add_member(
            &group.fixture.provider,
            mode,
            &group.group_id,
            key_package.clone(),
        );
        elapsed += start.elapsed();
        merge_pending_commit(&group.fixture.provider, mode, &group.group_id);
    }
    elapsed
}

fn measure_remove_members(group: &SingleGroup, mode: RuntimeMode, iterations: usize) -> Duration {
    let members: Vec<_> = (0..iterations)
        .map(|index| {
            let fixture = ProviderFixture::new(&format!("remove-member-{mode:?}-{index}"));
            let user_id = format!("remove-member-{index}");
            let key_package = generate_key_package(&user_id, &fixture.provider);
            (fixture, user_id, key_package)
        })
        .collect();

    let mut elapsed = Duration::ZERO;
    for (_, user_id, key_package) in &members {
        add_member(
            &group.fixture.provider,
            mode,
            &group.group_id,
            key_package.clone(),
        );
        merge_pending_commit(&group.fixture.provider, mode, &group.group_id);
        let start = Instant::now();
        remove_members(
            &group.fixture.provider,
            mode,
            &group.group_id,
            &[user_id.as_str()],
        );
        elapsed += start.elapsed();
        merge_pending_commit(&group.fixture.provider, mode, &group.group_id);
    }
    elapsed
}

fn measure_update_leaf_node(group: &SingleGroup, mode: RuntimeMode, iterations: usize) -> Duration {
    let mut elapsed = Duration::ZERO;
    for _ in 0..iterations {
        let start = Instant::now();
        update_leaf_node(&group.fixture.provider, mode, &group.group_id);
        elapsed += start.elapsed();
        merge_pending_commit(&group.fixture.provider, mode, &group.group_id);
    }
    elapsed
}

fn measure_merge_pending_commit(
    group: &SingleGroup,
    mode: RuntimeMode,
    iterations: usize,
) -> Duration {
    let mut elapsed = Duration::ZERO;
    for _ in 0..iterations {
        update_leaf_node(&group.fixture.provider, mode, &group.group_id);
        let start = Instant::now();
        merge_pending_commit(&group.fixture.provider, mode, &group.group_id);
        elapsed += start.elapsed();
    }
    elapsed
}

fn measure_create_group(
    mode: RuntimeMode,
    name: &str,
    iterations: usize,
    max_past_epochs: usize,
) -> Duration {
    let providers: Vec<_> = (0..iterations)
        .map(|index| ProviderFixture::new(&format!("{name}-{index}")))
        .collect();
    let start = Instant::now();
    for (index, fixture) in providers.iter().enumerate() {
        create_group(
            &fixture.provider,
            mode,
            "alice",
            &format!("{name}-group-{index}"),
            max_past_epochs,
        );
    }
    start.elapsed()
}

fn prepare_welcome_fixture(
    mode: RuntimeMode,
    name: &str,
    index: usize,
    max_past_epochs: usize,
) -> WelcomeFixture {
    let alice = ProviderFixture::new(&format!("{name}-alice-{index}"));
    let bob = ProviderFixture::new(&format!("{name}-bob-{index}"));
    let group_id = format!("{name}-group-{index}");
    create_group(&alice.provider, mode, "alice", &group_id, max_past_epochs);
    let bob_key_package = generate_key_package(&format!("bob-{index}"), &bob.provider);
    let core::AddMembersResult { welcome, .. } =
        add_member(&alice.provider, mode, &group_id, bob_key_package);
    merge_pending_commit(&alice.provider, mode, &group_id);
    WelcomeFixture { bob, welcome }
}

fn measure_process_welcome(
    mode: RuntimeMode,
    name: &str,
    iterations: usize,
    max_past_epochs: usize,
) -> Duration {
    let fixtures: Vec<_> = (0..iterations)
        .map(|index| prepare_welcome_fixture(mode, name, index, max_past_epochs))
        .collect();
    let start = Instant::now();
    for (index, fixture) in fixtures.iter().enumerate() {
        process_welcome(
            &fixture.bob.provider,
            mode,
            &fixture.welcome,
            &format!("{name}-group-{index}"),
            max_past_epochs,
        );
    }
    start.elapsed()
}

fn prepare_join_external_fixture(
    mode: RuntimeMode,
    name: &str,
    index: usize,
    max_past_epochs: usize,
) -> JoinExternalFixture {
    let alice = ProviderFixture::new(&format!("{name}-alice-{index}"));
    let joiner = ProviderFixture::new(&format!("{name}-joiner-{index}"));
    let group_id = format!("{name}-group-{index}");
    create_group(&alice.provider, mode, "alice", &group_id, max_past_epochs);
    let group_info = export_group_info(&alice.provider, mode, &group_id);
    JoinExternalFixture { joiner, group_info }
}

fn measure_join_by_external_commit(
    mode: RuntimeMode,
    name: &str,
    iterations: usize,
    max_past_epochs: usize,
) -> Duration {
    let fixtures: Vec<_> = (0..iterations)
        .map(|index| prepare_join_external_fixture(mode, name, index, max_past_epochs))
        .collect();
    let start = Instant::now();
    for (index, fixture) in fixtures.iter().enumerate() {
        join_by_external_commit(
            &fixture.joiner.provider,
            mode,
            &format!("external-joiner-{index}"),
            &fixture.group_info,
            max_past_epochs,
        );
    }
    start.elapsed()
}

fn prepare_readd_fixture(
    mode: RuntimeMode,
    name: &str,
    index: usize,
    max_past_epochs: usize,
) -> ReaddFixture {
    let alice = ProviderFixture::new(&format!("{name}-alice-{index}"));
    let bob = ProviderFixture::new(&format!("{name}-bob-{index}"));
    let charlie = ProviderFixture::new(&format!("{name}-charlie-{index}"));
    let group_id = format!("{name}-group-{index}");
    let bob_id = format!("bob-{index}");
    let charlie_id = format!("charlie-{index}");

    let bob_key_package = generate_key_package(&bob_id, &bob.provider);
    create_group(&alice.provider, mode, "alice", &group_id, max_past_epochs);
    let core::AddMembersResult { welcome, .. } =
        add_member(&alice.provider, mode, &group_id, bob_key_package.clone());
    merge_pending_commit(&alice.provider, mode, &group_id);
    process_welcome(&bob.provider, mode, &welcome, &group_id, max_past_epochs);

    let charlie_key_package = generate_key_package(&charlie_id, &charlie.provider);
    add_member(
        &alice.provider,
        mode,
        &group_id,
        charlie_key_package.clone(),
    );
    merge_pending_commit(&alice.provider, mode, &group_id);
    add_member(&bob.provider, mode, &group_id, charlie_key_package);
    merge_pending_commit(&bob.provider, mode, &group_id);

    ReaddFixture {
        alice,
        _bob: bob,
        _charlie: charlie,
        group_id,
        bob_id,
        bob_key_package,
    }
}

fn measure_readd(
    mode: RuntimeMode,
    name: &str,
    iterations: usize,
    max_past_epochs: usize,
) -> Duration {
    let fixtures: Vec<_> = (0..iterations)
        .map(|index| prepare_readd_fixture(mode, name, index, max_past_epochs))
        .collect();
    let start = Instant::now();
    for fixture in &fixtures {
        readd(
            &fixture.alice.provider,
            mode,
            &fixture.group_id,
            &[fixture.bob_id.as_str()],
            std::slice::from_ref(&fixture.bob_key_package),
        );
    }
    start.elapsed()
}

fn compare_pair(
    name: &str,
    iterations: usize,
    max_past_epochs: usize,
    history_epochs: usize,
    measure: fn(&Pair, RuntimeMode, usize) -> Duration,
) -> Timing {
    let legacy_pair = setup_pair(
        RuntimeMode::Legacy,
        &format!("{name}-legacy"),
        max_past_epochs,
        history_epochs,
    );
    let current_pair = setup_pair(
        RuntimeMode::Current,
        &format!("{name}-current"),
        max_past_epochs,
        history_epochs,
    );
    let timing = Timing {
        legacy: measure(&legacy_pair, RuntimeMode::Legacy, iterations),
        current: measure(&current_pair, RuntimeMode::Current, iterations),
    };
    print_timing(name, &timing);
    timing
}

fn compare_single(
    name: &str,
    iterations: usize,
    max_past_epochs: usize,
    history_epochs: usize,
    measure: fn(&SingleGroup, RuntimeMode, usize) -> Duration,
) -> Timing {
    let legacy_group = setup_single_group(
        RuntimeMode::Legacy,
        &format!("{name}-legacy"),
        max_past_epochs,
        history_epochs,
    );
    let current_group = setup_single_group(
        RuntimeMode::Current,
        &format!("{name}-current"),
        max_past_epochs,
        history_epochs,
    );
    let timing = Timing {
        legacy: measure(&legacy_group, RuntimeMode::Legacy, iterations),
        current: measure(&current_group, RuntimeMode::Current, iterations),
    };
    print_timing(name, &timing);
    timing
}

fn compare_constructor(
    name: &str,
    iterations: usize,
    max_past_epochs: usize,
    measure: fn(RuntimeMode, &str, usize, usize) -> Duration,
) -> Timing {
    let timing = Timing {
        legacy: measure(
            RuntimeMode::Legacy,
            &format!("{name}-legacy"),
            iterations,
            max_past_epochs,
        ),
        current: measure(
            RuntimeMode::Current,
            &format!("{name}-current"),
            iterations,
            max_past_epochs,
        ),
    };
    print_timing(name, &timing);
    timing
}

fn print_timing(name: &str, timing: &Timing) {
    println!(
        "PERF {name}: legacy={:?}, current={:?}, speedup={:.2}x",
        timing.legacy,
        timing.current,
        timing.speedup()
    );
}

#[test]
#[ignore = "performance comparison; run explicitly with --ignored --nocapture"]
fn compare_legacy_vs_current_epoch_message_secrets() {
    let iterations = env_usize("EPOCH_PERF_ITERATIONS", 20);
    let max_past_epochs = env_usize("EPOCH_PERF_MAX_PAST_EPOCHS", 80);
    let history_epochs = env_usize("EPOCH_PERF_HISTORY_EPOCHS", max_past_epochs);

    println!(
        "epoch message secrets benchmark config: iterations={iterations}, max_past_epochs={max_past_epochs}, history_epochs={history_epochs}"
    );

    let encrypt = compare_pair(
        "encrypt_message",
        iterations,
        max_past_epochs,
        history_epochs,
        measure_encrypt,
    );
    let current = compare_pair(
        "process_application_message_current",
        iterations,
        max_past_epochs,
        history_epochs,
        measure_process_current,
    );
    let past = compare_pair(
        "process_application_message_past",
        iterations,
        max_past_epochs,
        history_epochs,
        measure_process_past,
    );
    let state_change = compare_pair(
        "state_changing_epoch_advance_roundtrip",
        iterations,
        max_past_epochs,
        history_epochs,
        measure_epoch_advance_roundtrip,
    );
    let process_operation = compare_pair(
        "process_operation_message",
        iterations,
        max_past_epochs,
        history_epochs,
        measure_process_operation_message,
    );
    let process_many_operation = compare_pair(
        "process_many_operation_messages",
        iterations,
        max_past_epochs,
        history_epochs,
        measure_process_many_operation_messages,
    );
    let process_proposal = compare_pair(
        "process_proposal_message",
        iterations,
        max_past_epochs,
        history_epochs,
        measure_process_proposal_message,
    );
    let leave = compare_pair(
        "leave_group",
        iterations,
        max_past_epochs,
        history_epochs,
        measure_leave_group,
    );
    let add_members = compare_single(
        "add_members",
        iterations,
        max_past_epochs,
        history_epochs,
        measure_add_members,
    );
    let remove_members = compare_single(
        "remove_members",
        iterations,
        max_past_epochs,
        history_epochs,
        measure_remove_members,
    );
    let update_leaf = compare_single(
        "update_leaf_node",
        iterations,
        max_past_epochs,
        history_epochs,
        measure_update_leaf_node,
    );
    let merge_pending = compare_single(
        "merge_pending_commit",
        iterations,
        max_past_epochs,
        history_epochs,
        measure_merge_pending_commit,
    );
    let readd = compare_constructor("readd", iterations, max_past_epochs, measure_readd);
    let create_group = compare_constructor(
        "create_group",
        iterations,
        max_past_epochs,
        measure_create_group,
    );
    let process_welcome = compare_constructor(
        "process_welcome",
        iterations,
        max_past_epochs,
        measure_process_welcome,
    );
    let join_external = compare_constructor(
        "join_by_external_commit",
        iterations,
        max_past_epochs,
        measure_join_by_external_commit,
    );

    println!(
        "SUMMARY hot_path encrypt={:.2}x current_app={:.2}x past_app={:.2}x",
        encrypt.speedup(),
        current.speedup(),
        past.speedup()
    );
    println!(
        "SUMMARY state_change epoch_roundtrip={:.2}x process_operation={:.2}x process_many={:.2}x process_proposal={:.2}x leave={:.2}x add={:.2}x remove={:.2}x update_leaf={:.2}x merge_pending={:.2}x readd={:.2}x",
        state_change.speedup(),
        process_operation.speedup(),
        process_many_operation.speedup(),
        process_proposal.speedup(),
        leave.speedup(),
        add_members.speedup(),
        remove_members.speedup(),
        update_leaf.speedup(),
        merge_pending.speedup(),
        readd.speedup()
    );
    println!(
        "SUMMARY constructors create_group={:.2}x process_welcome={:.2}x join_external={:.2}x",
        create_group.speedup(),
        process_welcome.speedup(),
        join_external.speedup()
    );
}
