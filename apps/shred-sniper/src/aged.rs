//! A map whose entries age out on the wall clock.
//!
//! Every key in this crate that could drive eviction — slot numbers, erasure
//! batch indices — comes off the wire unauthenticated, so nothing key-derived
//! (like the highest slot seen) can be trusted to: one spoofed shred would
//! freeze eviction for good. Entries therefore age out on when they were last
//! touched, and a cap bounds what spoofed keys can pin in memory until they do.

use {
    std::{
        collections::HashMap,
        hash::Hash,
        time::{Duration, Instant},
    },
    tracing::debug,
};

/// Sweeping every entry on every insert would dominate the packet path.
const SWEEP_INTERVAL: Duration = Duration::from_millis(200);

pub struct AgedMap<K, V> {
    entries: HashMap<K, Aged<V>>,
    retention: Duration,
    cap: usize,
    /// What the entries are, for the log line when the cap forces drops.
    label: &'static str,
    last_swept: Instant,
}

struct Aged<V> {
    /// When this entry last saw an insert, which is what it ages out on.
    updated: Instant,
    value: V,
}

impl<K: Eq + Hash, V> AgedMap<K, V> {
    pub fn new(retention: Duration, cap: usize, label: &'static str) -> Self {
        Self {
            entries: HashMap::new(),
            retention,
            cap,
            label,
            last_swept: Instant::now(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key).map(|aged| &aged.value)
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.entries.get_mut(key).map(|aged| &mut aged.value)
    }

    /// The entry under `key`, created if absent, stamped as touched either way.
    pub fn upsert(&mut self, key: K, now: Instant, create: impl FnOnce() -> V) -> &mut V {
        let aged = self.entries.entry(key).or_insert_with(|| Aged {
            updated: now,
            value: create(),
        });
        aged.updated = now;
        &mut aged.value
    }

    /// Ages out entries past retention, handing each to `expired` on its way
    /// out, then enforces the cap. Gated on an interval so callers can run it
    /// on every insert; says whether it actually ran, so anything that only
    /// needs refreshing per sweep (a gauge, say) can key off it.
    pub fn sweep(&mut self, now: Instant, mut expired: impl FnMut(&K, &mut V)) -> bool {
        if now.duration_since(self.last_swept) < SWEEP_INTERVAL && self.entries.len() <= self.cap {
            return false;
        }
        self.last_swept = now;

        let retention = self.retention;
        self.entries.retain(|key, aged| {
            let keep = now.duration_since(aged.updated) < retention;
            if !keep {
                expired(key, &mut aged.value);
            }
            keep
        });

        // Nothing legitimate reaches the cap, so when it is hit the entries to
        // give up are the ones that have gone quiet.
        if self.entries.len() > self.cap {
            let mut updated: Vec<Instant> =
                self.entries.values().map(|aged| aged.updated).collect();
            updated.sort_unstable();
            let cutoff = updated[updated.len() - self.cap];
            let before = self.entries.len();
            self.entries.retain(|_, aged| aged.updated >= cutoff);
            debug!(
                dropped = before - self.entries.len(),
                held = self.entries.len(),
                "{} over the cap",
                self.label
            );
        }
        true
    }
}
