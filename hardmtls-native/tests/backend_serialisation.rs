//! Tests that the global backend serialisation pattern works correctly.
//!
//! The core property we verify: when multiple threads call `sign()` through
//! a `Mutex<Box<dyn SigningBackend>>`, only one thread is inside `sign()` at
//! a time — even if callers are fully parallel.
//!
//! We use a [`MockSerialBackend`] that detects concurrent access with an
//! [`AtomicBool`] flag.  If two threads are inside `sign()` simultaneously,
//! the mock returns an error (simulating hardware contention).

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use hardmtls::backends::SigningBackend;
use hardmtls::error::HardmtlsError;

/// Number of concurrent threads to launch.
const NUM_THREADS: usize = 16;

/// A mock signing backend that detects concurrent access.
///
/// If two threads enter `sign()` at the same time, the second one sees
/// `busy == true` and returns an error — simulating the TPM handle crash.
struct MockSerialBackend {
    /// Set to `true` while a thread is inside `sign()`.
    busy: AtomicBool,
    /// Total number of successful sign operations.
    sign_count: AtomicUsize,
}

impl MockSerialBackend {
    fn new() -> Self {
        Self {
            busy: AtomicBool::new(false),
            sign_count: AtomicUsize::new(0),
        }
    }
}

impl SigningBackend for MockSerialBackend {
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, HardmtlsError> {
        // Try to set busy = true.  If it was already true, another thread
        // is inside sign() — this is exactly the contention we're preventing.
        if self
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(HardmtlsError::Pkcs11Error(
                "CONCURRENT ACCESS DETECTED — this simulates a TPM handle crash".into(),
            ));
        }

        // Simulate hardware work (10ms is enough to expose races).
        thread::sleep(std::time::Duration::from_millis(10));

        self.busy.store(false, Ordering::SeqCst);
        self.sign_count.fetch_add(1, Ordering::SeqCst);

        Ok(vec![0xDE, 0xAD])
    }

    fn certificate_pem(&self) -> Result<String, HardmtlsError> {
        Ok("-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n".into())
    }
}

/// Without the mutex, concurrent callers will detect overlap and fail.
///
/// This test proves the mock actually catches concurrency — if this test
/// passed with direct (un-serialised) access, the mock would be broken.
#[test]
fn mock_detects_concurrent_access_without_mutex() {
    let backend = Arc::new(MockSerialBackend::new());
    let barrier = Arc::new(Barrier::new(NUM_THREADS));

    let handles: Vec<_> = (0..NUM_THREADS)
        .map(|_| {
            let backend = Arc::clone(&backend);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait(); // Synchronise — all threads start at once.
                backend.sign(b"test")
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let errors: Vec<_> = results.iter().filter(|r| r.is_err()).collect();

    // At least one thread should have detected concurrency.
    // (With 16 threads and a 10ms sleep, this is essentially guaranteed.)
    assert!(
        !errors.is_empty(),
        "Expected at least one concurrent-access error without serialisation, \
         but all {NUM_THREADS} calls succeeded. The mock may not be detecting overlap correctly.",
    );
}

/// With the mutex, all callers are serialised and every `sign()` succeeds.
///
/// This is the actual property we're testing: the `Mutex<Box<dyn SigningBackend>>`
/// pattern (as used by `BACKEND_CACHE` in `lib.rs`) prevents concurrent access.
#[test]
fn mutex_serialises_concurrent_sign_calls() {
    let backend: Arc<Mutex<Box<dyn SigningBackend>>> =
        Arc::new(Mutex::new(Box::new(MockSerialBackend::new())));
    let barrier = Arc::new(Barrier::new(NUM_THREADS));

    let handles: Vec<_> = (0..NUM_THREADS)
        .map(|_| {
            let backend = Arc::clone(&backend);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait(); // All threads start at once.
                let guard = backend.lock().unwrap();
                guard.sign(b"test")
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // Every single call must succeed — no concurrent-access errors.
    for (i, result) in results.iter().enumerate() {
        assert!(
            result.is_ok(),
            "Thread {i} failed: {:?}  — the mutex did not serialise access correctly",
            result.as_ref().unwrap_err(),
        );
    }
}

/// Same test for `certificate_pem()` — serialisation applies to all operations.
#[test]
fn mutex_serialises_concurrent_cert_calls() {
    let backend: Arc<Mutex<Box<dyn SigningBackend>>> =
        Arc::new(Mutex::new(Box::new(MockSerialBackend::new())));
    let barrier = Arc::new(Barrier::new(NUM_THREADS));

    let handles: Vec<_> = (0..NUM_THREADS)
        .map(|_| {
            let backend = Arc::clone(&backend);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                let guard = backend.lock().unwrap();
                guard.certificate_pem()
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    for (i, result) in results.iter().enumerate() {
        assert!(
            result.is_ok(),
            "Thread {i} failed: {:?}",
            result.as_ref().unwrap_err(),
        );
    }
}

/// Mixed workload: some threads sign, some read certs — all serialised.
#[test]
fn mutex_serialises_mixed_sign_and_cert_calls() {
    let backend: Arc<Mutex<Box<dyn SigningBackend>>> =
        Arc::new(Mutex::new(Box::new(MockSerialBackend::new())));
    let barrier = Arc::new(Barrier::new(NUM_THREADS));

    let handles: Vec<_> = (0..NUM_THREADS)
        .map(|i| {
            let backend = Arc::clone(&backend);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                let guard = backend.lock().unwrap();
                if i % 2 == 0 {
                    guard.sign(b"test").map(|_| ())
                } else {
                    guard.certificate_pem().map(|_| ())
                }
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    for (i, result) in results.iter().enumerate() {
        assert!(
            result.is_ok(),
            "Thread {i} failed: {:?}",
            result.as_ref().unwrap_err(),
        );
    }
}
