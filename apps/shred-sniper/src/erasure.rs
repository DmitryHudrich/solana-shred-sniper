//! Reed-Solomon recovery of data shreds lost in turbine.
//!
//! The leader groups shreds into erasure batches, typically 32 data shreds and
//! 32 coding shreds, and any `num_data` of the 64 reconstruct the batch. We
//! already receive the coding shreds, so gaps can be filled locally without
//! asking anyone for a repair.

use {
    crate::{
        metrics::Metrics,
        shred::{CodingShred, DataShred},
    },
    reed_solomon_erasure::galois_8::ReedSolomon,
    std::{
        collections::{HashMap, hash_map::Entry},
        sync::Arc,
        time::{Duration, Instant},
    },
    tracing::debug,
};

/// Sanity bound on a batch, well above the 32:32 the shredder produces.
const MAX_SHARDS: usize = 128;

/// Turbine delivers a batch within its slot, so one still short of shreds
/// after this long is never completing. Recovered shreds have to land in a
/// slot the assembler still holds, which is far longer than this.
const BATCH_LIFETIME: Duration = Duration::from_secs(2);

/// A slot holds a few dozen batches, so this leaves room for the batches in
/// flight while capping what spoofed slot numbers can pin in memory.
const MAX_FEC_SETS: usize = 1024;

/// Sweeping every batch on every shred would dominate the packet path.
const EVICT_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Clone, Copy)]
struct Layout {
    num_data: usize,
    num_coding: usize,
    shard_len: usize,
}

/// One erasure batch. Shards are dropped as soon as the batch resolves, so the
/// steady-state footprint is only the few batches still in flight.
struct FecSet {
    data: HashMap<usize, Vec<u8>>,
    coding: HashMap<usize, Vec<u8>>,
    /// Known once any coding shred of the batch arrives.
    layout: Option<Layout>,
    resolved: bool,
    /// When this batch last saw a shred, which is what it ages out on.
    updated: Instant,
}

impl FecSet {
    fn new(now: Instant) -> Self {
        Self {
            data: HashMap::new(),
            coding: HashMap::new(),
            layout: None,
            resolved: false,
            updated: now,
        }
    }

    fn resolve(&mut self) {
        self.data = HashMap::new();
        self.coding = HashMap::new();
        self.resolved = true;
    }
}

pub struct Recovery {
    sets: HashMap<(u64, u32), FecSet>,
    codecs: HashMap<(usize, usize), Arc<ReedSolomon>>,
    retention: Duration,
    last_evicted: Instant,
    metrics: Arc<Metrics>,
}

impl Recovery {
    pub fn new(retention: Duration, metrics: Arc<Metrics>) -> Self {
        Self {
            sets: HashMap::new(),
            codecs: HashMap::new(),
            retention: retention.min(BATCH_LIFETIME),
            last_evicted: Instant::now(),
            metrics,
        }
    }

    /// Returns the bodies of any data shreds this insert made recoverable.
    pub fn insert_data(&mut self, shred: &DataShred<'_>) -> Vec<Vec<u8>> {
        let Some(offset) = shred
            .index
            .checked_sub(shred.fec_set_index)
            .map(usize::try_from)
            .and_then(Result::ok)
            .filter(|offset| *offset < MAX_SHARDS)
        else {
            return Vec::new();
        };

        let now = Instant::now();
        self.evict(now);
        let key = (shred.slot, shred.fec_set_index);
        let set = self.sets.entry(key).or_insert_with(|| FecSet::new(now));
        set.updated = now;
        if set.resolved {
            return Vec::new();
        }
        set.data
            .entry(offset)
            .or_insert_with(|| shred.shard.to_vec());
        self.recover(key)
    }

    /// Returns the bodies of any data shreds this insert made recoverable.
    pub fn insert_coding(&mut self, shred: &CodingShred<'_>) -> Vec<Vec<u8>> {
        let CodingShred {
            num_data,
            num_coding,
            position,
            ..
        } = *shred;
        if num_data == 0
            || num_coding == 0
            || num_data + num_coding > MAX_SHARDS
            || position >= num_coding
        {
            return Vec::new();
        }

        let now = Instant::now();
        self.evict(now);
        let key = (shred.slot, shred.fec_set_index);
        let set = self.sets.entry(key).or_insert_with(|| FecSet::new(now));
        set.updated = now;
        if set.resolved {
            return Vec::new();
        }
        set.layout = Some(Layout {
            num_data,
            num_coding,
            shard_len: shred.shard.len(),
        });
        set.coding
            .entry(position)
            .or_insert_with(|| shred.shard.to_vec());
        self.recover(key)
    }

    fn recover(&mut self, key: (u64, u32)) -> Vec<Vec<u8>> {
        let Some(set) = self.sets.get_mut(&key) else {
            return Vec::new();
        };
        let Some(Layout {
            num_data,
            num_coding,
            shard_len,
        }) = set.layout
        else {
            return Vec::new();
        };

        let usable = |shards: &HashMap<usize, Vec<u8>>, limit: usize| {
            shards
                .iter()
                .filter(|(index, shard)| **index < limit && shard.len() == shard_len)
                .count()
        };
        let have_data = usable(&set.data, num_data);
        if have_data == num_data {
            // Nothing was lost, so the coding shreds are no longer of interest.
            set.resolve();
            return Vec::new();
        }
        if have_data + usable(&set.coding, num_coding) < num_data {
            return Vec::new();
        }

        let mut shards: Vec<Option<Vec<u8>>> = vec![None; num_data + num_coding];
        for (index, shard) in set.data.drain().chain(
            set.coding
                .drain()
                .map(|(position, shard)| (num_data + position, shard)),
        ) {
            if index < shards.len() && shard.len() == shard_len {
                shards[index] = Some(shard);
            }
        }
        // One attempt per batch: a failure here means the input was malformed,
        // and retrying it on every later shred would only burn cycles.
        set.resolve();
        let missing: Vec<usize> = (0..num_data)
            .filter(|index| shards[*index].is_none())
            .collect();

        let codec = match self.codecs.entry((num_data, num_coding)) {
            Entry::Occupied(entry) => entry.get().clone(),
            Entry::Vacant(entry) => match ReedSolomon::new(num_data, num_coding) {
                Ok(codec) => entry.insert(Arc::new(codec)).clone(),
                Err(err) => {
                    debug!(num_data, num_coding, %err, "unusable erasure batch layout");
                    self.metrics.fec_set_incomplete();
                    return Vec::new();
                }
            },
        };

        if let Err(err) = codec.reconstruct_data(&mut shards) {
            let (slot, fec_set_index) = key;
            debug!(slot, fec_set_index, %err, "erasure recovery failed");
            self.metrics.fec_set_incomplete();
            return Vec::new();
        }

        let recovered: Vec<Vec<u8>> = missing
            .into_iter()
            .filter_map(|index| shards[index].take())
            .collect();
        self.metrics.shreds_recovered(recovered.len() as u64);
        recovered
    }

    /// Batches age out on the same clock as the slots they belong to, so a
    /// recovered shred always lands in a slot the assembler still holds. Slot
    /// numbers cannot drive this: they arrive unauthenticated, and anchoring
    /// on the highest one seen let a single spoofed shred freeze eviction.
    fn evict(&mut self, now: Instant) {
        if now.duration_since(self.last_evicted) < EVICT_INTERVAL && self.sets.len() <= MAX_FEC_SETS
        {
            return;
        }
        self.last_evicted = now;

        let retention = self.retention;
        let metrics = &self.metrics;
        self.sets.retain(|_, set| {
            let keep = now.duration_since(set.updated) < retention;
            if !keep && !set.resolved && set.layout.is_some() {
                metrics.fec_set_incomplete();
            }
            keep
        });

        // Nothing legitimate reaches the cap, so when it is hit the batches to
        // give up are the ones that have gone quiet.
        if self.sets.len() > MAX_FEC_SETS {
            let mut updated: Vec<Instant> = self.sets.values().map(|set| set.updated).collect();
            updated.sort_unstable();
            let cutoff = updated[updated.len() - MAX_FEC_SETS];
            let before = self.sets.len();
            self.sets.retain(|_, set| set.updated >= cutoff);
            debug!(
                dropped = before - self.sets.len(),
                held = self.sets.len(),
                "erasure batches over the cap"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::shred::{self, Shred},
        opentelemetry::global,
        solana_hash::Hash,
        solana_keypair::Keypair,
        solana_ledger::shred::{
            ProcessShredsStats, ReedSolomonCache, Shred as AgaveShred, Shredder,
        },
    };

    const SLOT: u64 = 42;
    const RETENTION: Duration = Duration::from_secs(30);
    /// Whatever a cluster would hash out; the point is that it is not zero.
    const SHRED_VERSION: u16 = 4242;

    /// Shreds a payload the way a leader would, so the tests run against the
    /// real wire format rather than our own idea of it.
    fn shred(payload_len: usize) -> (Vec<u8>, Vec<AgaveShred>, Vec<AgaveShred>) {
        let payload: Vec<u8> = (0..payload_len).map(|byte| (byte % 251) as u8).collect();
        let (data, coding) = Shredder::new(SLOT, SLOT - 1, 0, SHRED_VERSION)
            .unwrap()
            .make_shreds_from_data_slice(
                &Keypair::new(),
                &payload,
                true,
                Hash::default(),
                0,
                0,
                &ReedSolomonCache::default(),
                &mut ProcessShredsStats::default(),
            )
            .unwrap()
            .partition(AgaveShred::is_data);
        (payload, data, coding)
    }

    /// Data shreds of a slot carry the payload split in index order.
    fn reassemble<'a>(shreds: impl IntoIterator<Item = shred::DataShred<'a>>) -> Vec<u8> {
        let mut shreds: Vec<_> = shreds.into_iter().collect();
        shreds.sort_by_key(|shred| shred.index);
        shreds
            .iter()
            .flat_map(|shred| shred.data)
            .copied()
            .collect()
    }

    fn recovery() -> Recovery {
        Recovery::new(
            RETENTION,
            Arc::new(crate::metrics::Metrics::new(&global::meter("test"))),
        )
    }

    #[test]
    fn parses_data_shreds_like_agave() {
        let (payload, data, coding) = shred(40 * 1024);
        assert!(data.len() > 32 && !coding.is_empty());

        let mut parsed_data = Vec::new();
        for shred in &data {
            let Some(Shred::Data(parsed)) = shred::parse(shred.payload(), SHRED_VERSION) else {
                panic!("data shred did not parse");
            };
            assert_eq!(parsed.slot, shred.slot());
            assert_eq!(parsed.index, shred.index());
            assert_eq!(parsed.fec_set_index, shred.fec_set_index());
            parsed_data.push(parsed);
        }
        assert_eq!(reassemble(parsed_data), payload);

        for shred in &coding {
            let Some(Shred::Coding(parsed)) = shred::parse(shred.payload(), SHRED_VERSION) else {
                panic!("coding shred did not parse");
            };
            assert_eq!(parsed.slot, shred.slot());
            assert_eq!(parsed.fec_set_index, shred.fec_set_index());
            assert!(parsed.position < parsed.num_coding);
        }
    }

    #[test]
    fn recovers_data_shreds_dropped_by_turbine() {
        let (payload, data, coding) = shred(40 * 1024);
        let dropped = &data[..2];

        let mut recovery = recovery();
        let mut recovered = Vec::new();
        for shred in data.iter().skip(dropped.len()).chain(coding.iter()) {
            recovered.extend(match shred::parse(shred.payload(), SHRED_VERSION) {
                Some(Shred::Data(shred)) => recovery.insert_data(&shred),
                Some(Shred::Coding(shred)) => recovery.insert_coding(&shred),
                None => panic!("shred did not parse"),
            });
        }

        assert_eq!(recovered.len(), dropped.len());
        for shred in dropped {
            let Some(Shred::Data(expected)) = shred::parse(shred.payload(), SHRED_VERSION) else {
                panic!("data shred did not parse");
            };
            let actual = recovered
                .iter()
                .filter_map(|body| shred::parse_data(body, SHRED_VERSION))
                .find(|actual| actual.index == expected.index)
                .expect("shred was not recovered");

            assert_eq!(actual.slot, expected.slot);
            assert_eq!(actual.fec_set_index, expected.fec_set_index);
            assert_eq!(actual.data_complete, expected.data_complete);
            assert_eq!(actual.shard, expected.shard);
            assert_eq!(actual.data, expected.data);
        }

        // What the assembler would end up with: the kept shreds plus the
        // recovered ones have to add back up to the leader's payload.
        let kept = data.iter().skip(dropped.len()).filter_map(|shred| {
            match shred::parse(shred.payload(), SHRED_VERSION) {
                Some(Shred::Data(shred)) => Some(shred),
                _ => None,
            }
        });
        let filled = recovered
            .iter()
            .filter_map(|body| shred::parse_data(body, SHRED_VERSION));
        assert_eq!(reassemble(kept.chain(filled)), payload);
    }

    #[test]
    fn keeps_quiet_when_nothing_was_lost() {
        let (_, data, coding) = shred(40 * 1024);

        let mut recovery = recovery();
        for shred in data.iter().chain(coding.iter()) {
            let recovered = match shred::parse(shred.payload(), SHRED_VERSION) {
                Some(Shred::Data(shred)) => recovery.insert_data(&shred),
                Some(Shred::Coding(shred)) => recovery.insert_coding(&shred),
                None => panic!("shred did not parse"),
            };
            assert!(recovered.is_empty());
        }
    }

    /// Eviction used to be anchored to the highest slot number seen, so one
    /// spoofed shred froze it and the cache grew without bound from there.
    #[test]
    fn a_spoofed_slot_does_not_stop_eviction() {
        let mut recovery = recovery();
        let spoofed = DataShred {
            slot: u64::MAX,
            index: 0,
            fec_set_index: 0,
            data_complete: false,
            data: &[],
            shard: &[1, 2, 3],
        };
        recovery.insert_data(&spoofed);

        for slot in 0..8 * MAX_FEC_SETS as u64 {
            recovery.insert_data(&DataShred { slot, ..spoofed });
        }
        assert!(
            recovery.sets.len() <= MAX_FEC_SETS + 1,
            "{} batches held",
            recovery.sets.len()
        );
    }

    #[test]
    fn gives_up_when_the_batch_is_beyond_repair() {
        let (_, data, coding) = shred(40 * 1024);
        let Some(Shred::Coding(first)) = shred::parse(coding[0].payload(), SHRED_VERSION) else {
            panic!("coding shred did not parse");
        };
        // One short of what Reed-Solomon needs for the first batch.
        let keep = first.num_data - 1;

        let mut recovery = recovery();
        let mut recovered = Vec::new();
        for shred in data
            .iter()
            .filter(|shred| shred.fec_set_index() == first.fec_set_index)
            .take(keep.saturating_sub(1))
            .chain(coding.iter().take(1))
        {
            recovered.extend(match shred::parse(shred.payload(), SHRED_VERSION) {
                Some(Shred::Data(shred)) => recovery.insert_data(&shred),
                Some(Shred::Coding(shred)) => recovery.insert_coding(&shred),
                None => panic!("shred did not parse"),
            });
        }

        assert!(recovered.is_empty());
    }
}
