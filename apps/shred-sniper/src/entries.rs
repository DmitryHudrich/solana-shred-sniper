use {
    crate::metrics::{BatchOutcome, Metrics},
    serde::Deserialize,
    solana_hash::Hash,
    solana_transaction::versioned::VersionedTransaction,
    std::{
        collections::{BTreeMap, HashMap, HashSet},
        sync::Arc,
        time::{Duration, Instant},
    },
    tracing::debug,
};

/// Retention is anchored to the clock, so spoofed slot numbers cost memory
/// until they age out rather than evicting the slots we care about. This caps
/// that cost; steady state needs one buffer per slot inside the window.
const MAX_BUFFERED_SLOTS: usize = 128;

/// Sweeping every buffer on every shred would dominate the packet path.
const EVICT_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Debug, Deserialize)]
pub struct Entry {
    #[allow(dead_code)]
    pub num_hashes: u64,
    #[allow(dead_code)]
    pub hash: Hash,
    pub transactions: Vec<VersionedTransaction>,
}

struct Shred {
    data: Vec<u8>,
    data_complete: bool,
    received: Instant,
}

struct SlotBuffer {
    shreds: BTreeMap<u32, Shred>,
    emitted: HashSet<u32>,
    /// When this slot last saw a shred, which is what it ages out on.
    updated: Instant,
}

impl SlotBuffer {
    fn new(now: Instant) -> Self {
        Self {
            shreds: BTreeMap::new(),
            emitted: HashSet::new(),
            updated: now,
        }
    }

    fn take_complete_batches(&mut self) -> Vec<(Vec<u8>, Instant)> {
        let starts: Vec<u32> = std::iter::once(0)
            .chain(
                self.shreds
                    .iter()
                    .filter(|(_, shred)| shred.data_complete)
                    .map(|(index, _)| index + 1),
            )
            .filter(|start| !self.emitted.contains(start))
            .collect();

        let mut batches = Vec::new();
        for start in starts {
            let mut payload = Vec::new();
            let mut index = start;
            let mut complete = false;
            let mut first_received = None;

            while let Some(shred) = self.shreds.get(&index) {
                payload.extend_from_slice(&shred.data);
                first_received = Some(match first_received {
                    Some(earliest) if earliest <= shred.received => earliest,
                    _ => shred.received,
                });
                index += 1;
                if shred.data_complete {
                    complete = true;
                    break;
                }
            }

            if let (true, Some(first_received)) = (complete, first_received) {
                self.emitted.insert(start);
                batches.push((payload, first_received));
            }
        }

        batches
    }

    fn missing(&self) -> Vec<u32> {
        let Some(last) = self.shreds.keys().next_back().copied() else {
            return Vec::new();
        };
        (0..=last)
            .filter(|index| !self.shreds.contains_key(index))
            .collect()
    }
}

pub struct Assembler {
    slots: HashMap<u64, SlotBuffer>,
    retention: Duration,
    last_evicted: Instant,
    metrics: Arc<Metrics>,
}

impl Assembler {
    pub fn new(retention: Duration, metrics: Arc<Metrics>) -> Self {
        Self {
            slots: HashMap::new(),
            retention,
            last_evicted: Instant::now(),
            metrics,
        }
    }

    pub fn insert(&mut self, shred: &crate::shred::DataShred<'_>) -> Vec<Entry> {
        let now = Instant::now();
        self.evict(now);

        let buffer = self
            .slots
            .entry(shred.slot)
            .or_insert_with(|| SlotBuffer::new(now));
        buffer.updated = now;
        let replaced = buffer.shreds.insert(
            shred.index,
            Shred {
                data: shred.data.to_vec(),
                data_complete: shred.data_complete,
                received: now,
            },
        );
        if replaced.is_some() {
            self.metrics.shred_duplicate();
        }

        let batches = buffer.take_complete_batches();
        let mut entries = Vec::new();
        for (batch, first_received) in batches {
            let latency = first_received.elapsed();
            match decode_batch(&batch) {
                Batch::Entries(decoded) => {
                    self.metrics.batch(BatchOutcome::Decoded, latency);
                    self.metrics.entries(decoded.len() as u64);
                    entries.extend(decoded);
                }
                Batch::Marker => self.metrics.batch(BatchOutcome::Marker, latency),
                Batch::Invalid => self.metrics.batch(BatchOutcome::Failed, latency),
            }
        }
        entries
    }

    /// Slot numbers arrive unauthenticated, so a slot ages out on the wall
    /// clock rather than on how far ahead the highest slot seen is: one
    /// spoofed shred claiming a far future slot must not evict live slots.
    fn evict(&mut self, now: Instant) {
        if now.duration_since(self.last_evicted) < EVICT_INTERVAL
            && self.slots.len() <= MAX_BUFFERED_SLOTS
        {
            return;
        }
        self.last_evicted = now;

        let retention = self.retention;
        let metrics = &self.metrics;
        self.slots.retain(|slot, buffer| {
            let keep = now.duration_since(buffer.updated) < retention;
            if !keep {
                let missing = buffer.missing();
                if !missing.is_empty() {
                    metrics.shreds_missing(missing.len() as u64);
                    debug!(slot, lost = missing.len(), ?missing, "missing shreds");
                }
            }
            keep
        });

        // Nothing legitimate reaches the cap, so when it is hit the buffers to
        // give up are the ones that have gone quiet.
        if self.slots.len() > MAX_BUFFERED_SLOTS {
            let mut updated: Vec<Instant> =
                self.slots.values().map(|buffer| buffer.updated).collect();
            updated.sort_unstable();
            let cutoff = updated[updated.len() - MAX_BUFFERED_SLOTS];
            let before = self.slots.len();
            self.slots.retain(|_, buffer| buffer.updated >= cutoff);
            debug!(
                dropped = before - self.slots.len(),
                held = self.slots.len(),
                "slot buffers over the cap"
            );
        }

        self.metrics.set_buffered_slots(self.slots.len() as u64);
    }
}

enum Batch {
    Entries(Vec<Entry>),
    Marker,
    Invalid,
}

fn decode_batch(batch: &[u8]) -> Batch {
    if batch.len() < 8 {
        return Batch::Invalid;
    }
    let Ok(header) = batch[..8].try_into() else {
        return Batch::Invalid;
    };
    if u64::from_le_bytes(header) == 0 {
        return Batch::Marker;
    }
    match bincode::deserialize::<Vec<Entry>>(batch) {
        Ok(entries) => Batch::Entries(entries),
        Err(err) => {
            debug!(bytes = batch.len(), %err, "failed to decode entry batch");
            Batch::Invalid
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::shred::DataShred,
        opentelemetry::global,
        serde::Serialize,
        solana_keypair::Keypair,
        solana_signer::Signer,
        solana_transaction::{Address, CompiledInstruction, Message, VersionedMessage},
    };

    const SLOT: u64 = 42;
    const RETENTION: Duration = Duration::from_secs(30);
    /// Comfortably under the smallest shard a leader would produce.
    const CHUNK: usize = 900;

    /// Mirrors [`Entry`] on the wire; the real one is only ever deserialized.
    #[derive(Serialize)]
    struct WireEntry {
        num_hashes: u64,
        hash: Hash,
        transactions: Vec<VersionedTransaction>,
    }

    fn assembler() -> Assembler {
        Assembler::new(
            RETENTION,
            Arc::new(crate::metrics::Metrics::new(&global::meter("test"))),
        )
    }

    fn transaction(payer: &Keypair, program: &Address) -> VersionedTransaction {
        let message = Message {
            account_keys: vec![payer.pubkey(), *program],
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: vec![1, 2, 3],
            }],
            ..Default::default()
        };
        VersionedTransaction {
            signatures: vec![Default::default()],
            message: VersionedMessage::Legacy(message),
        }
    }

    /// A bincode `Vec<Entry>` batch, exactly what a leader shreds.
    fn batch(entries: usize, transactions: usize) -> (Vec<u8>, usize) {
        let payer = Keypair::new();
        let program = Keypair::new().pubkey();
        let entries: Vec<WireEntry> = (0..entries)
            .map(|index| WireEntry {
                num_hashes: index as u64,
                hash: Hash::default(),
                transactions: (0..transactions)
                    .map(|_| transaction(&payer, &program))
                    .collect(),
            })
            .collect();
        let expected = entries.iter().map(|entry| entry.transactions.len()).sum();
        (bincode::serialize(&entries).unwrap(), expected)
    }

    /// Feeds a batch to the assembler split across shreds, and reports the
    /// transactions that came back out.
    fn feed(assembler: &mut Assembler, slot: u64, payload: &[u8], reverse: bool) -> usize {
        let chunks: Vec<&[u8]> = payload.chunks(CHUNK).collect();
        let last = chunks.len() - 1;
        let mut shreds: Vec<(u32, &[u8])> = chunks
            .into_iter()
            .enumerate()
            .map(|(index, data)| (index as u32, data))
            .collect();
        if reverse {
            shreds.reverse();
        }

        let mut transactions = 0;
        for (index, data) in shreds {
            let shred = DataShred {
                slot,
                index,
                fec_set_index: 0,
                data_complete: index as usize == last,
                data,
                shard: &[],
            };
            for entry in assembler.insert(&shred) {
                transactions += entry.transactions.len();
            }
        }
        transactions
    }

    #[test]
    fn reassembles_a_batch_split_across_shreds() {
        let (payload, expected) = batch(4, 3);
        assert!(payload.len() > CHUNK, "batch should span several shreds");
        assert_eq!(feed(&mut assembler(), SLOT, &payload, false), expected);
    }

    #[test]
    fn reassembles_a_batch_delivered_out_of_order() {
        let (payload, expected) = batch(4, 3);
        assert_eq!(feed(&mut assembler(), SLOT, &payload, true), expected);
    }

    #[test]
    fn emits_a_batch_only_once() {
        let (payload, expected) = batch(2, 2);
        let mut assembler = assembler();
        assert_eq!(feed(&mut assembler, SLOT, &payload, false), expected);
        assert_eq!(
            feed(&mut assembler, SLOT, &payload, false),
            0,
            "the batch was emitted twice"
        );
    }

    /// Shreds carry no signature, so a spoofed slot number used to be enough
    /// to evict every live slot and blind the sniper for good.
    #[test]
    fn a_spoofed_slot_does_not_blind_the_assembler() {
        let mut assembler = assembler();
        for slot in [u64::MAX, u64::MAX - 1, 0] {
            assembler.insert(&DataShred {
                slot,
                index: 0,
                fec_set_index: 0,
                data_complete: false,
                data: &[1, 2, 3],
                shard: &[],
            });
        }

        let (payload, expected) = batch(2, 2);
        assert_eq!(feed(&mut assembler, SLOT, &payload, false), expected);
    }

    /// Spoofed slots can still cost memory until they age out, so the number
    /// of buffers they can pin has to be bounded.
    #[test]
    fn slot_buffers_stay_capped() {
        let mut assembler = assembler();
        for slot in 0..8 * MAX_BUFFERED_SLOTS as u64 {
            assembler.insert(&DataShred {
                slot,
                index: 0,
                fec_set_index: 0,
                data_complete: false,
                data: &[1, 2, 3],
                shard: &[],
            });
        }
        assert!(
            assembler.slots.len() <= MAX_BUFFERED_SLOTS + 1,
            "{} slot buffers held",
            assembler.slots.len()
        );
    }
}
