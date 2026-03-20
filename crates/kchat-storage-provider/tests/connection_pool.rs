use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use kchat_storage_provider::SqliteConnectionPool;
use rusqlite::Connection;

fn temp_db_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "kchat-storage-provider-connection-pool-{}-{}.sqlite",
        std::process::id(),
        nanos
    ))
}

#[test]
fn shared_connection_allows_parallel_leases() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let db_path = temp_db_path();
    let opener_path = db_path.clone();
    let shared = SqliteConnectionPool::new(4, move || {
        let connection = Connection::open(&opener_path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.busy_timeout(Duration::from_secs(5))?;
        Ok(connection)
    });

    {
        let connection = shared.checkout()?;
        connection.execute(
            "CREATE TABLE IF NOT EXISTS contention_test (id INTEGER)",
            [],
        )?;
    }

    let inflight = Arc::new(AtomicUsize::new(0));
    let max_inflight = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();

    for _ in 0..4 {
        let shared = shared.clone();
        let inflight = Arc::clone(&inflight);
        let max_inflight = Arc::clone(&max_inflight);
        handles.push(thread::spawn(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                let connection = shared.checkout()?;
                let current = inflight.fetch_add(1, Ordering::SeqCst) + 1;
                max_inflight.fetch_max(current, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(100));
                connection.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))?;
                inflight.fetch_sub(1, Ordering::SeqCst);
                Ok(())
            },
        ));
    }

    for handle in handles {
        handle.join().expect("worker thread panicked")?;
    }

    assert!(
        max_inflight.load(Ordering::SeqCst) > 1,
        "expected multiple concurrent connection leases"
    );

    let _ = fs::remove_file(db_path);
    Ok(())
}

#[test]
fn shared_connection_respects_max_size() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let db_path = temp_db_path();
    let opener_path = db_path.clone();
    let opened = Arc::new(AtomicUsize::new(0));
    let opened_for_pool = Arc::clone(&opened);
    let shared = SqliteConnectionPool::new(1, move || {
        opened_for_pool.fetch_add(1, Ordering::SeqCst);
        let connection = Connection::open(&opener_path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.busy_timeout(Duration::from_secs(5))?;
        Ok(connection)
    });
    let (tx, rx) = mpsc::channel();

    let worker_shared = shared.clone();
    let handle = thread::spawn(
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let connection = worker_shared.checkout()?;
            tx.send(()).expect("failed to signal leased connection");
            thread::sleep(Duration::from_millis(150));
            connection.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))?;
            Ok(())
        },
    );

    rx.recv().expect("failed to wait for leased connection");
    let started = Instant::now();
    let connection = shared.checkout()?;
    let waited = started.elapsed();
    connection.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))?;

    handle.join().expect("worker thread panicked")?;

    assert_eq!(
        opened.load(Ordering::SeqCst),
        1,
        "expected the pool to reuse the only configured connection"
    );
    assert!(
        waited >= Duration::from_millis(100),
        "expected checkout to wait for the leased connection to return, only waited {waited:?}"
    );

    let _ = fs::remove_file(db_path);
    Ok(())
}
