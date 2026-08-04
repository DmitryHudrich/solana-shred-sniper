use {
    crate::{
        aged::AgedMap,
        metrics::{AssemblerMetrics, BatchOutcome},
    },
    serde::Deserialize,
    solana_hash::Hash,
    solana_transaction::versioned::VersionedTransaction,
    std::{
        collections::{BTreeMap, BTreeSet, HashSet},
        sync::Arc,
        time::{Duration, Instant},
    },
    tracing::debug,
};

/// Retention is anchored to the clock, so spoofed slot numbers cost memory
/// until they age out rather than evicting the slots we care about. This caps
/// that cost; steady state needs one buffer per slot inside the window.
const MAX_BUFFERED_SLOTS: usize = 128;

/// An arena is rebuilt once the bytes stranded in it outweigh what is still
/// live. The floor keeps a slot that has seen a shred or two from compacting on
/// every duplicate, where copying costs more than the bytes it reclaims.
const COMPACT_FLOOR: usize = 64 * 1024;

#[derive(Debug, Deserialize)]
pub struct Entry {
    #[allow(dead_code)]
    pub num_hashes: u64,
    #[allow(dead_code)]
    pub hash: Hash,
    pub transactions: Vec<VersionedTransaction>,
}

struct StoredShred {
    /// Where this shred's entry bytes sit in the slot's arena.
    at: usize,
    len: u32,
    data_complete: bool,
    received: Instant,
    /// Whether this shred came off the wire or out of erasure recovery. Carried
    /// only so a batch can say which of the two paid for its latency.
    recovered: bool,
}

/// A completed batch's bytes. Shreds are appended to the arena as they arrive
/// and a batch is a run of consecutive indices, so one delivered in order is
/// already contiguous there and can be decoded where it lies. Only a batch
/// interleaved with something else has to be stitched into a buffer of its own.
enum Payload {
    Arena { at: usize, len: usize },
    Stitched(Vec<u8>),
}

/// A completed batch, before it is decoded.
struct Complete {
    payload: Payload,
    first_received: Instant,
    recovered: bool,
    first_shred: u32,
    last_shred: u32,
}

/// A batch's entries together with the shreds they came from.
///
/// The range is what places the batch inside its slot. Batches are runs of
/// consecutive shred indices, so sorting by where a batch begins sorts them the
/// way the leader laid them down — which is emphatically not the order they
/// finish arriving in, and the order is the whole point when the question is
/// which of two transactions came first.
pub struct DecodedBatch {
    pub first_shred: u32,
    pub last_shred: u32,
    pub entries: Vec<Entry>,
}

struct SlotBuffer {
    /// Entry bytes of every shred held, back to back. One growing buffer per
    /// slot rather than a `Vec` per shred: the packet path is what pays for
    /// those allocations, and a slot's bytes are all released together anyway.
    arena: Vec<u8>,
    /// Arena bytes no shred points at any more, left behind by duplicates.
    /// Nothing else ever reclaims, so compaction is what stops a stream of them
    /// from growing the arena without bound.
    stale: usize,
    shreds: BTreeMap<u32, StoredShred>,
    /// Indices at which a batch begins: zero, plus one past every
    /// data-complete shred held. Maintained on insert so that completion
    /// checks only ever touch the batches an insert could have changed,
    /// rather than rescanning the whole slot on every shred.
    starts: BTreeSet<u32>,
    emitted: HashSet<u32>,
    /// Index of the shred that closes the slot, once one has arrived. It is the
    /// only thing that tells us how many shreds the slot was supposed to have.
    last_index: Option<u32>,
}

impl SlotBuffer {
    fn new() -> Self {
        Self {
            arena: Vec::new(),
            stale: 0,
            shreds: BTreeMap::new(),
            starts: BTreeSet::from([0]),
            emitted: HashSet::new(),
            last_index: None,
        }
    }

    /// Stores a shred and says whether it displaced an earlier copy of itself.
    fn insert(
        &mut self,
        index: u32,
        data: &[u8],
        data_complete: bool,
        received: Instant,
        recovered: bool,
    ) -> bool {
        let (at, len) = self.store(data);
        let replaced = self.shreds.insert(
            index,
            StoredShred {
                at,
                len,
                data_complete,
                received,
                recovered,
            },
        );
        let duplicate = replaced.is_some();
        // The bytes a duplicate displaces stay in the arena with nothing
        // pointing at them, which is what compaction later reclaims.
        if let Some(replaced) = replaced {
            self.stale += replaced.len as usize;
            if replaced.data_complete && !data_complete {
                self.starts.remove(&(index + 1));
            }
        }
        if data_complete {
            self.starts.insert(index + 1);
        }
        duplicate
    }

    /// Puts a shred's entry bytes in the arena and says where they landed.
    fn store(&mut self, data: &[u8]) -> (usize, u32) {
        if self.stale > COMPACT_FLOOR && self.stale > self.arena.len() / 2 {
            self.compact();
        }
        let at = self.arena.len();
        self.arena.extend_from_slice(data);
        (at, data.len() as u32)
    }

    fn bytes(&self, shred: &StoredShred) -> &[u8] {
        &self.arena[shred.at..shred.at + shred.len as usize]
    }

    /// Rebuilds the arena around the shreds still held, rewriting their offsets.
    fn compact(&mut self) {
        let stranded = std::mem::take(&mut self.arena);
        let mut arena = Vec::with_capacity(stranded.len().saturating_sub(self.stale));
        for shred in self.shreds.values_mut() {
            let at = arena.len();
            arena.extend_from_slice(&stranded[shred.at..shred.at + shred.len as usize]);
            shred.at = at;
        }
        self.arena = arena;
        self.stale = 0;
    }

    /// Batches the shred at `index` could have completed: the one holding it
    /// and, when the shred closes a batch, the one beginning right after it —
    /// a boundary this insert may have just created in front of shreds already
    /// held. No other batch changes on one insert.
    fn complete_batches(&mut self, index: u32) -> Vec<Complete> {
        let containing = *self
            .starts
            .range(..=index)
            .next_back()
            .expect("zero is always a start");
        let following = self.starts.get(&(index + 1)).copied();

        let mut batches = Vec::new();
        for start in [Some(containing), following].into_iter().flatten() {
            if self.emitted.contains(&start) {
                continue;
            }
            if let Some(complete) = self.scan_batch(start) {
                self.emitted.insert(start);
                batches.push(complete);
            }
        }
        batches
    }

    /// Walks the run of consecutive shreds beginning at `start`. The batch is
    /// only whole once a data-complete shred closes it with no gap on the way.
    fn scan_batch(&self, start: u32) -> Option<Complete> {
        let mut index = start;
        let mut first_received: Option<Instant> = None;
        let mut recovered = false;
        // Where the batch begins in the arena, how long it is, and whether its
        // shreds turned out to be one unbroken run there.
        let mut at = 0;
        let mut len = 0;
        let mut next = None;
        let mut contiguous = true;

        loop {
            let shred = self.shreds.get(&index)?;
            match next {
                None => at = shred.at,
                Some(expected) => contiguous &= shred.at == expected,
            }
            next = Some(shred.at + shred.len as usize);
            len += shred.len as usize;

            first_received = Some(match first_received {
                Some(earliest) if earliest <= shred.received => earliest,
                _ => shred.received,
            });
            recovered |= shred.recovered;
            index += 1;
            if shred.data_complete {
                break;
            }
        }

        let payload = if contiguous {
            Payload::Arena { at, len }
        } else {
            let mut stitched = Vec::with_capacity(len);
            for member in start..index {
                stitched.extend_from_slice(self.bytes(&self.shreds[&member]));
            }
            Payload::Stitched(stitched)
        };
        Some(Complete {
            payload,
            first_received: first_received.expect("the loop ran at least once"),
            recovered,
            first_shred: start,
            // The loop leaves `index` one past the shred that closed the batch.
            last_shred: index - 1,
        })
    }

    /// Gaps below the highest shred held, and — once the slot's closing shred
    /// has arrived — everything past it that never did. Without that flag a
    /// slot whose tail was lost outright looks complete, because nothing above
    /// the gap is left to mark where the slot was supposed to end.
    fn missing(&self) -> Vec<u32> {
        let highest = self.shreds.keys().next_back().copied();
        let Some(last) = self.last_index.or(highest) else {
            return Vec::new();
        };
        (0..=last)
            .filter(|index| !self.shreds.contains_key(index))
            .collect()
    }
}

pub struct Assembler {
    slots: AgedMap<u64, SlotBuffer>,
    metrics: Arc<AssemblerMetrics>,
}

impl Assembler {
    pub fn new(retention: Duration, metrics: Arc<AssemblerMetrics>) -> Self {
        Self {
            slots: AgedMap::new(retention, MAX_BUFFERED_SLOTS, "slot buffers"),
            metrics,
        }
    }

    /// `recovered` says whether this shred came out of erasure recovery rather
    /// than off the wire, which is what lets a batch report which path it
    /// waited on.
    pub fn insert(
        &mut self,
        shred: &crate::shred::DataShred<'_>,
        recovered: bool,
    ) -> Vec<DecodedBatch> {
        let now = Instant::now();
        self.sweep(now);

        let buffer = self.slots.upsert(shred.slot, now, SlotBuffer::new);
        if shred.last_in_slot {
            buffer.last_index = Some(shred.index);
        }
        if buffer.insert(shred.index, shred.data, shred.data_complete, now, recovered) {
            self.metrics.duplicate();
        }

        let completed = buffer.complete_batches(shred.index);
        let mut batches = Vec::new();
        for complete in completed {
            let latency = complete.first_received.elapsed();
            let bytes = match &complete.payload {
                Payload::Arena { at, len } => &buffer.arena[*at..*at + *len],
                Payload::Stitched(stitched) => stitched.as_slice(),
            };
            match decode_batch(bytes) {
                Batch::Entries(entries) => {
                    self.metrics
                        .batch(BatchOutcome::Decoded, latency, complete.recovered);
                    self.metrics.entries(entries.len() as u64);
                    batches.push(DecodedBatch {
                        first_shred: complete.first_shred,
                        last_shred: complete.last_shred,
                        entries,
                    });
                }
                Batch::Marker => {
                    self.metrics
                        .batch(BatchOutcome::Marker, latency, complete.recovered)
                }
                Batch::Invalid => {
                    self.metrics
                        .batch(BatchOutcome::Failed, latency, complete.recovered)
                }
            }
        }
        batches
    }

    /// Closes out the accounting of every slot the sweep let go.
    fn sweep(&mut self, now: Instant) {
        let metrics = &self.metrics;
        let swept = self.slots.sweep(now, |slot, buffer| {
            let missing = buffer.missing();
            if !missing.is_empty() {
                metrics.missing(missing.len() as u64);
                debug!(slot, lost = missing.len(), ?missing, "missing shreds");
            }
            // A slot is only measurable against its true size once its closing
            // shred has told us what that size was. Slots evicted without one
            // are counted apart rather than folded in at a guessed denominator.
            match buffer.last_index {
                Some(last) => metrics.completeness(buffer.shreds.len() as u64, u64::from(last) + 1),
                None => metrics.unterminated(),
            }
        });
        if swept {
            self.metrics.set_buffered_slots(self.slots.len() as u64);
        }
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
            crate::metrics::Metrics::new(&global::meter("test"), crate::config::FireVia::Rpc)
                .assembler,
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
                last_in_slot: index as usize == last,
                reference_tick: 0,
                data,
                shard: &[],
            };
            for batch in assembler.insert(&shred, false) {
                transactions += batch
                    .entries
                    .iter()
                    .map(|entry| entry.transactions.len())
                    .sum::<usize>();
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
            assembler.insert(
                &DataShred {
                    slot,
                    index: 0,
                    fec_set_index: 0,
                    data_complete: false,
                    last_in_slot: false,
                    reference_tick: 0,
                    data: &[1, 2, 3],
                    shard: &[],
                },
                false,
            );
        }

        let (payload, expected) = batch(2, 2);
        assert_eq!(feed(&mut assembler, SLOT, &payload, false), expected);
    }

    /// A slot whose tail is lost outright leaves nothing above the gap to mark
    /// where it should have ended, so counting gaps below the highest shred
    /// held reports it as whole. Only the closing shred's index says otherwise.
    #[test]
    fn counts_a_lost_tail_as_missing() {
        let now = Instant::now();
        let mut buffer = SlotBuffer::new();
        for index in [0u32, 1, 3] {
            buffer.insert(index, &[], false, now, false);
        }

        assert_eq!(
            buffer.missing(),
            vec![2],
            "the interior gap is all that is visible without the closing shred"
        );

        buffer.last_index = Some(5);
        assert_eq!(
            buffer.missing(),
            vec![2, 4, 5],
            "the tail past the highest shred held has to count too"
        );
    }

    /// Shreds are appended to the arena as they arrive, so a batch delivered in
    /// order is already one run of bytes there and needs no staging at all.
    /// Anything else has to be stitched, and both paths have to yield the same
    /// bytes — the fast one is worth nothing if it quietly never fires.
    fn assembled(order: [u32; 3]) -> (Payload, Vec<u8>) {
        let now = Instant::now();
        let mut buffer = SlotBuffer::new();
        let mut batches = Vec::new();
        for index in order {
            buffer.insert(index, &[index as u8; 4], index == 2, now, false);
            batches.append(&mut buffer.complete_batches(index));
        }

        assert_eq!(batches.len(), 1, "the batch was complete");
        let payload = batches.remove(0).payload;
        let bytes = match &payload {
            Payload::Arena { at, len } => buffer.arena[*at..*at + *len].to_vec(),
            Payload::Stitched(stitched) => stitched.clone(),
        };
        (payload, bytes)
    }

    #[test]
    fn an_in_order_batch_is_decoded_where_it_lies() {
        let expected: Vec<u8> = [[0u8; 4], [1; 4], [2; 4]].concat();

        let (payload, bytes) = assembled([0, 1, 2]);
        assert!(matches!(payload, Payload::Arena { .. }));
        assert_eq!(bytes, expected);

        let (payload, bytes) = assembled([2, 0, 1]);
        assert!(matches!(payload, Payload::Stitched(_)));
        assert_eq!(bytes, expected);
    }

    /// A duplicate strands the bytes it displaces in the arena, and nothing but
    /// compaction ever takes them back. Without it one index resent often
    /// enough would grow a slot's arena until the process died — and the
    /// rewrite it does has to leave the shreds still held readable.
    #[test]
    fn duplicates_do_not_grow_the_arena_without_bound() {
        let (payload, expected) = batch(4, 3);
        let chunks: Vec<&[u8]> = payload.chunks(CHUNK).collect();
        assert!(chunks.len() > 1, "batch should span several shreds");

        let mut assembler = assembler();
        let duplicate = DataShred {
            slot: SLOT,
            index: 0,
            fec_set_index: 0,
            data_complete: false,
            last_in_slot: false,
            reference_tick: 0,
            data: chunks[0],
            shard: &[],
        };
        // Far more dead bytes than the floor, so compaction has to have run.
        let resends = 8 * COMPACT_FLOOR / CHUNK;
        for _ in 0..resends {
            assert!(assembler.insert(&duplicate, false).is_empty());
        }

        let arena = assembler.slots.get(&SLOT).unwrap().arena.len();
        assert!(
            arena < 4 * COMPACT_FLOOR,
            "{arena} bytes held for {resends} resends of one shred",
        );

        // The batch still has to come out whole once the rest of it arrives,
        // which is what says compaction rewrote the offsets rather than
        // shuffling the bytes out from under them.
        assert_eq!(feed(&mut assembler, SLOT, &payload, false), expected);
    }

    /// Spoofed slots can still cost memory until they age out, so the number
    /// of buffers they can pin has to be bounded.
    #[test]
    fn slot_buffers_stay_capped() {
        let mut assembler = assembler();
        for slot in 0..8 * MAX_BUFFERED_SLOTS as u64 {
            assembler.insert(
                &DataShred {
                    slot,
                    index: 0,
                    fec_set_index: 0,
                    data_complete: false,
                    last_in_slot: false,
                    reference_tick: 0,
                    data: &[1, 2, 3],
                    shard: &[],
                },
                false,
            );
        }
        assert!(
            assembler.slots.len() <= MAX_BUFFERED_SLOTS + 1,
            "{} slot buffers held",
            assembler.slots.len()
        );
    }

    /// A shred that closes a batch also opens the one after it, and the shreds
    /// of that later batch may already all be sitting in the buffer. The
    /// incremental completion check has to notice the batch the insert created
    /// a boundary in front of, not only the batch the insert landed in.
    #[test]
    fn a_late_terminator_releases_the_batch_behind_it() {
        let now = Instant::now();
        let mut buffer = SlotBuffer::new();
        // The second batch, whole and waiting: shreds 2..=3, closed at 3.
        buffer.insert(2, &[2; 4], false, now, false);
        buffer.insert(3, &[3; 4], true, now, false);
        assert!(
            buffer.complete_batches(3).is_empty(),
            "nothing can complete while the first batch is open"
        );

        // The terminator of the first batch arrives last and must release both.
        buffer.insert(0, &[0; 4], false, now, false);
        buffer.insert(1, &[1; 4], true, now, false);
        let batches = buffer.complete_batches(1);
        let ranges: Vec<(u32, u32)> = batches
            .iter()
            .map(|complete| (complete.first_shred, complete.last_shred))
            .collect();
        assert_eq!(ranges, vec![(0, 1), (2, 3)]);
    }
}
