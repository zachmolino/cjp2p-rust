//! Lamport clocks, matching git-bug's `util/lamport` semantics exactly.
//!
//! git-bug uses Lamport clocks to order operations. Two details differ from a
//! textbook Lamport clock and MUST be replicated or pack acceptance will fail:
//!
//! 1. Clocks start at 1; the value 0 is reserved as "unset/invalid".
//! 2. `Witness` sets `counter = max(counter, t)` — NOT `max(counter, t) + 1`.
//!    git-bug's rationale: events happen when data is *written*, not when read,
//!    so witnessing another clock only raises ours to (at most) that value.

use anyhow::{Context, Result};
use std::path::PathBuf;

/// A point in Lamport time. `0` means unset/invalid; valid clocks start at 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LamportTime(pub u64);

/// In-memory Lamport clock. Mirrors git-bug's `MemClock`.
#[derive(Clone, Debug)]
pub struct MemClock {
    counter: u64,
}

impl Default for MemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MemClock {
    /// A fresh clock with counter = 1 (0 is invalid), matching
    /// git-bug's `NewMemClock`.
    pub fn new() -> MemClock {
        MemClock {
            counter: 1,
        }
    }

    /// Construct from an existing counter value (used when loading from disk).
    fn with_counter(counter: u64) -> MemClock {
        MemClock {
            counter,
        }
    }

    /// Current clock value, matching git-bug's `Time()`.
    pub fn time(&self) -> LamportTime {
        LamportTime(self.counter)
    }

    /// Advance the clock and return the NEW value.
    ///
    /// Matches git-bug's `Increment()`, which is
    /// `Time(atomic.AddUint64(&counter, 1))` — i.e. it increments FIRST and
    /// returns the post-increment value. (From counter 1, a single
    /// `increment()` advances to 2 and returns `LamportTime(2)`.)
    pub fn increment(&mut self) -> LamportTime {
        self.counter += 1;
        LamportTime(self.counter)
    }

    /// Raise this clock after seeing another process's clock value.
    ///
    /// Sets `counter = max(counter, t)` — git-bug uses plain max, NOT max+1.
    pub fn witness(&mut self, t: LamportTime) {
        if t.0 > self.counter {
            self.counter = t.0;
        }
    }
}

/// On-disk Lamport clock, mirroring git-bug's `PersistedClock`.
///
/// The file holds a BARE DECIMAL ASCII integer with NO trailing newline.
/// git-bug stores these under `.git/git-bug/clocks/{bugs-create,bugs-edit}`.
#[derive(Clone, Debug)]
pub struct PersistedClock {
    path: PathBuf,
}

impl PersistedClock {
    /// Bind a persisted clock to a file path. Does not touch the file.
    pub fn new(path: impl Into<PathBuf>) -> PersistedClock {
        PersistedClock {
            path: path.into(),
        }
    }

    /// Read the clock value from disk.
    ///
    /// A missing file reads as a fresh clock: `LamportTime(1)`. This matches
    /// git-bug, whose `NewPersistedClock` initializes a `MemClock` (counter 1)
    /// and writes it; we treat absence as that same fresh value rather than
    /// failing, so callers can lazily create the file on first `write`.
    pub fn read(&self) -> Result<LamportTime> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                let s = std::str::from_utf8(&bytes)
                    .with_context(|| format!("clock file {:?} is not valid UTF-8", self.path))?;
                let n: u64 = s.trim().parse().with_context(|| {
                    format!("clock file {:?} is not a decimal integer: {s:?}", self.path)
                })?;
                Ok(LamportTime(n))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(LamportTime(1)),
            Err(e) => Err(e).with_context(|| format!("reading clock file {:?}", self.path)),
        }
    }

    /// Write the clock value to disk as a bare decimal integer, NO newline.
    pub fn write(&self, t: LamportTime) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating clock dir {parent:?}"))?;
        }
        std::fs::write(&self.path, t.0.to_string().as_bytes())
            .with_context(|| format!("writing clock file {:?}", self.path))?;
        Ok(())
    }

    /// Read, advance, write, and return the new value.
    ///
    /// Mirrors git-bug's `PersistedClock.Increment` (in-memory increment then
    /// persist). The advance uses [`MemClock::increment`], so the returned
    /// value is the post-increment time.
    pub fn increment(&mut self) -> Result<LamportTime> {
        let current = self.read()?;
        let mut mem = MemClock::with_counter(current.0);
        let next = mem.increment();
        self.write(next)?;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_clock_starts_at_one() {
        let c = MemClock::new();
        assert_eq!(c.time(), LamportTime(1));
    }

    #[test]
    fn increment_advances_then_returns_new_value() {
        // git-bug: Increment() returns the POST-increment value.
        let mut c = MemClock::new();
        assert_eq!(c.increment(), LamportTime(2));
        assert_eq!(c.time(), LamportTime(2));
        assert_eq!(c.increment(), LamportTime(3));
        assert_eq!(c.time(), LamportTime(3));
    }

    #[test]
    fn witness_uses_max_not_max_plus_one() {
        let mut c = MemClock::new(); // counter = 1
        c.witness(LamportTime(5));
        // max(1, 5) = 5, NOT 6.
        assert_eq!(c.time(), LamportTime(5));

        // Witnessing a smaller value does not lower the clock.
        c.witness(LamportTime(3));
        assert_eq!(c.time(), LamportTime(5));

        // Witnessing an equal value is a no-op (still max, not +1).
        c.witness(LamportTime(5));
        assert_eq!(c.time(), LamportTime(5));
    }

    #[test]
    fn persisted_round_trip_writes_no_newline() {
        let dir = std::env::temp_dir().join(format!("cjp2p-clock-{}", std::process::id()));
        let path = dir.join("bugs-create");
        let _ = std::fs::remove_file(&path);

        let pc = PersistedClock::new(&path);
        pc.write(LamportTime(42)).unwrap();

        // Assert the EXACT bytes on disk: bare decimal, no trailing newline.
        let raw = std::fs::read(&path).unwrap();
        assert_eq!(raw, b"42");
        assert!(!raw.ends_with(b"\n"));

        assert_eq!(pc.read().unwrap(), LamportTime(42));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn missing_file_reads_as_one() {
        let path = std::env::temp_dir().join(format!("cjp2p-clock-missing-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let pc = PersistedClock::new(&path);
        assert_eq!(pc.read().unwrap(), LamportTime(1));
    }

    #[test]
    fn persisted_increment_is_monotonic() {
        let dir = std::env::temp_dir().join(format!("cjp2p-clock-mono-{}", std::process::id()));
        let path = dir.join("bugs-edit");
        let _ = std::fs::remove_file(&path);

        let mut pc = PersistedClock::new(&path);
        // Fresh (missing) file reads as 1; first increment -> 2.
        assert_eq!(pc.increment().unwrap(), LamportTime(2));
        assert_eq!(pc.increment().unwrap(), LamportTime(3));
        assert_eq!(pc.increment().unwrap(), LamportTime(4));
        assert_eq!(pc.read().unwrap(), LamportTime(4));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}
