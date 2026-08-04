//! Turning shreds back into transactions.
//!
//! A leader serializes a slot's entries into one `Vec<Entry>` per batch and
//! cuts that byte string into shreds, so a batch is only whole once a
//! data-complete shred closes a run of consecutive indices. Waiting for that is
//! the obvious way to decode it and the wrong one for a sniper: the entries at
//! the front of a batch are readable long before the shreds at its back arrive,
//! and the transaction worth reacting to is usually one of them — the leader
//! writes what it executed first, first.
//!
//! So a batch is decoded as it arrives. Every shred that extends the run of
//! bytes from the batch's first index hands over whatever entries have become
//! whole, and the decoder remembers how far into the batch it got. A batch
//! comes out in as many pieces as it takes; nothing is decoded twice.

use {
    crate::{
        aged::AgedMap,
        metrics::{AssemblerMetrics, BatchOutcome},
    },
    serde::Deserialize,
    solana_hash::Hash,
    solana_transaction::versioned::VersionedTransaction,
    std::{
        collections::{BTreeMap, BTreeSet},
        io::Cursor,
        sync::Arc,
        time::{Duration, Instant},
    },
    tracing::debug,
};

/// Retention is anchored to the clock, so spoofed slot numbers cost memory
/// until they age out rather than evicting the slots we care about. This caps
/// that cost; steady state needs one buffer per slot inside the window.
const MAX_BUFFERED_SLOTS: usize = 128;

/// Entry bytes one slot may hold. The caps above and in [`crate::shred`] bound
/// how many buffers and how many indices an unauthenticated sender can touch,
/// but nothing bounded what they hold: 32k indices at a kilobyte apiece is
/// 36 MB in a single slot, for a sender that only has to know our address. A
/// mainnet block runs to a megabyte or two, so this leaves several times what
/// a leader produces and still refuses the rest.
const MAX_SLOT_BYTES: usize = 8 * 1024 * 1024;

/// Shreds one slot may hold. The byte caps bound what a slot's shreds *carry*,
/// which is not the same as what they cost: the wire format lets a data shred
/// declare a size that stops exactly at its headers, and [`crate::shred`] parses
/// that into an empty payload. A stream of those is free against every byte
/// budget here while still taking a `StoredShred`, a place in `starts` and,
/// when it closes a batch, a `Progress` — some hundred bytes apiece that the
/// payload total cannot see. At the format's 32k indices per slot that is
/// several megabytes a slot, off the books. A real slot runs to a couple of
/// thousand shreds, so this leaves several times what a leader produces.
const MAX_SLOT_SHREDS: usize = 8 * 1024;

/// Roughly what one held shred costs outside the arena: a `StoredShred`, its
/// place in the `shreds` map, and the index it may add to `starts`. `BTreeMap`
/// node slack is real and not addressable, so this is an estimate — the point
/// is that the cost is counted at all, not that it is exact to the byte.
const PER_SHRED_OVERHEAD: usize = 64;

/// The same, for the decoding state one batch keeps between shreds.
const PER_BATCH_OVERHEAD: usize = 128;

/// What every slot held may cost the process, because the slot cap multiplied
/// by the buffer cap is a gigabyte. Steady state is the retention window's
/// worth of real blocks — some tens of slots at a megabyte or two — so this is
/// several times what the sniper needs and a fraction of what it could be made
/// to hold.
///
/// This is measured in resident bytes rather than payload bytes: arenas count
/// by capacity, and the per-shred bookkeeping counts too. Budgeting the payload
/// alone would have understated the real figure severalfold, since a `Vec` that
/// has doubled holds the untouched half resident just the same.
const MAX_BUFFERED_BYTES: usize = 512 * 1024 * 1024;

/// An arena is rebuilt once the bytes stranded in it outweigh what is still
/// live. The floor keeps a slot that has seen a shred or two from compacting on
/// every duplicate, where copying costs more than the bytes it reclaims.
const COMPACT_FLOOR: usize = 64 * 1024;

/// A batch opens with the number of entries in it, as bincode writes the length
/// of any sequence: eight little-endian bytes. Nothing else about the batch can
/// be read until they have arrived.
const ENTRY_COUNT: usize = 8;

/// The smallest an entry can be on the wire: a hash count, a hash, and a
/// transaction vector with nothing in it. A batch that declares more entries
/// than its bytes could ever hold has not been cut short, it is not a batch.
const MIN_ENTRY_BYTES: u64 = 8 + 32 + 8;

/// Bytes a batch may run to, with no shred closing it, before it is given up
/// on.
///
/// The reason for the bound is cost rather than plausibility. A prefix that
/// will not decode is re-read from the batch's first byte by every shred that
/// extends it, because there is nowhere to resume from until an entry comes out
/// whole — and the length of that run is whatever a sender chooses to send.
/// Measured: a few thousand shreds of bytes that are always one entry short of
/// decodable cost seconds of CPU, for traffic that costs the sender nothing.
///
/// The value is set where a legitimate batch cannot reach it. A batch is what
/// the leader hands to the shredder at one go, which a 6.25 ms tick bounds; a
/// mainnet block is a megabyte or two across a whole 400 ms slot, so about
/// 5 MB/s. Filling this inside one tick would be eight times that rate. The
/// batches given up on here are counted as [`BatchOutcome::Failed`], so if a
/// cluster ever does write batches this large it shows up as a rate rather than
/// as silence.
const MAX_BATCH_BYTES: usize = 256 * 1024;

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

/// The bytes of a batch that have arrived. Shreds are appended to the arena as
/// they arrive and a batch is a run of consecutive indices, so one delivered in
/// order is already contiguous there and can be read where it lies. Only a run
/// interleaved with something else has to be stitched into a buffer of its own.
enum Payload {
    Arena { at: usize, len: usize },
    Stitched(Vec<u8>),
}

/// How far the run of shreds beginning at a batch's first index reaches, and
/// where its bytes sit. Everything up to the first gap is readable, whether or
/// not the shred that closes the batch has turned up.
#[derive(Clone, Copy)]
struct Extent {
    /// Highest index in the run.
    last: u32,
    /// The run ends at a shred that closes the batch, so there is no more of it
    /// to come.
    complete: bool,
    first_received: Instant,
    recovered: bool,
    /// Bytes the run holds, counted from the batch's first byte.
    len: usize,
}

/// How far a batch has been decoded. Entries are handed over as the shreds
/// carrying them arrive, so what has to survive between shreds is the point in
/// the batch's bytes the decoder reached and how many entries it is still owed.
#[derive(Default)]
struct Progress {
    /// Bytes already turned into entries.
    consumed: usize,
    /// Entries still to come. `None` until the count the batch opens with has
    /// arrived.
    remaining: Option<u64>,
    /// Set once entries have been handed over, so the wait for the first of
    /// them is recorded once and a batch that has already yielded something is
    /// never mistaken for an empty one.
    opened: bool,
    /// Nothing more will come out of this batch: either every entry it declared
    /// was decoded, or its bytes turned out not to be entries at all.
    closed: bool,
    /// How far the run reached when it was last walked. A run only ever grows
    /// forward, so the next walk resumes at the frontier instead of retracing
    /// the shreds behind it — without this a batch of `n` shreds costs `n`
    /// steps for every one of them.
    extent: Option<Extent>,
    /// Where reading picks up: the first shred whose bytes have not all become
    /// entries, and the offset at which it begins in the batch. Kept for the
    /// same reason as `extent`, for the walk that skips what is already read.
    resume: Option<(u32, usize)>,
}

/// What one shred did for the batch it belongs to.
struct Advance {
    /// Highest shred index whose bytes are accounted for by the entries handed
    /// over so far.
    last_shred: u32,
    entries: Vec<Entry>,
    /// Time since the batch's first shred, for whichever of the two below is
    /// set.
    latency: Duration,
    /// Set on the pass that produced the batch's first entries.
    opened: bool,
    /// Set on the pass that finished the batch, with what became of it.
    finished: Option<BatchOutcome>,
    recovered: bool,
}

/// Some of a batch's entries, together with the shreds they came from.
///
/// A batch surfaces in as many pieces as the shreds carrying it allow, so this
/// is a piece of one rather than all of it — `first_shred` is what ties the
/// pieces together.
///
/// The range is what places the entries inside their slot. Batches are runs of
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
    /// Decoding state of every batch begun in this slot, by the index it begins
    /// at. Held between shreds, which is what lets a batch be read in pieces.
    progress: BTreeMap<u32, Progress>,
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
            progress: BTreeMap::new(),
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
        if duplicate {
            self.invalidate(index);
        }
        duplicate
    }

    /// Throws away what was learned by walking over a shred that has just been
    /// replaced. Everything the walk carries forward — how long the run is, how
    /// many of its bytes are read, whether it ends at a terminator — was
    /// measured over the copy that is now gone, and the new one may differ in
    /// all three. Duplicates are rare enough that starting the walk over costs
    /// less than unpicking it.
    fn invalidate(&mut self, index: u32) {
        for start in self.candidates(index).into_iter().flatten() {
            if let Some(progress) = self.progress.get_mut(&start) {
                progress.extent = None;
                progress.resume = None;
            }
        }
    }

    /// Arena bytes a held shred still points at. What the arena has grown to is
    /// a different number — it carries whatever duplicates stranded until the
    /// next compaction — and it is this one the per-slot cap is kept in, so
    /// that reclaiming bytes is not mistaken for holding fewer.
    fn live(&self) -> usize {
        self.arena.len() - self.stale
    }

    /// What this slot costs the process, as opposed to what its shreds carry.
    ///
    /// The arena counts by capacity because the untouched half of a `Vec` that
    /// has just doubled is resident all the same, and compaction is what
    /// returns it. The maps count because a shred with no payload at all is
    /// free by [`Self::live`] and is not free here — which is the whole reason
    /// the global budget is kept in this number rather than that one.
    fn footprint(&self) -> usize {
        self.arena.capacity()
            + self.shreds.len() * PER_SHRED_OVERHEAD
            + self.progress.len() * PER_BATCH_OVERHEAD
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

    /// Batches the shred at `index` could have carried forward: the one holding
    /// it and, when the shred closes a batch, the one beginning right after it —
    /// a boundary this insert may have just created in front of shreds already
    /// held. No other batch changes on one insert.
    ///
    /// A start that is not in `starts` yet is one whose preceding terminator has
    /// not arrived, and the shred is attributed to the nearest start below it
    /// instead. That is harmless: the run from that earlier start cannot reach
    /// past the terminator it is missing, so it never reads bytes that belong to
    /// a batch it is not.
    fn candidates(&self, index: u32) -> [Option<u32>; 2] {
        let containing = self.starts.range(..=index).next_back().copied();
        let following = self.starts.get(&(index + 1)).copied();
        [containing, following]
    }

    /// Decodes as much of the batch beginning at `start` as the shreds now held
    /// allow, and reports what that yielded.
    fn advance(&mut self, start: u32) -> Option<Advance> {
        let mut progress = self.progress.remove(&start).unwrap_or_default();
        let advance = self.decode_prefix(start, &mut progress);
        // A closed batch keeps its progress so that a duplicate of one of its
        // shreds cannot start it over.
        self.progress.insert(start, progress);
        advance
    }

    fn decode_prefix(&self, start: u32, progress: &mut Progress) -> Option<Advance> {
        if progress.closed {
            return None;
        }
        let extent = self.extent(start, progress.extent)?;
        // Kept whether or not this pass reads anything, since what it is for is
        // sparing the next one the walk.
        progress.extent = Some(extent);
        // A run this long with no terminator in it is not a batch that is still
        // arriving, and every further shred would have it re-read from the
        // start. Giving up is what keeps that cost bounded.
        if !extent.complete && extent.len > MAX_BATCH_BYTES {
            debug!(start, bytes = extent.len, "batch ran past its bounds");
            progress.closed = true;
            return Some(Advance {
                last_shred: extent.last,
                entries: Vec::new(),
                latency: extent.first_received.elapsed(),
                opened: false,
                finished: Some(BatchOutcome::Failed),
                recovered: extent.recovered,
            });
        }
        // Nothing new to read, and no terminator to force a verdict on what has
        // been read so far.
        if extent.len <= progress.consumed && !extent.complete {
            return None;
        }

        let mut entries = Vec::new();
        let (payload, base) = self.payload(start, &extent, progress);
        let bytes = match &payload {
            Payload::Arena { at, len } => &self.arena[*at..*at + *len],
            Payload::Stitched(stitched) => stitched.as_slice(),
        };
        let decoded = decode(bytes, base, progress, &mut entries);

        let opened = !progress.opened && !entries.is_empty();
        // A batch that has already handed something over is not an empty one,
        // however little the pass that finished it produced.
        let any = progress.opened || !entries.is_empty();
        progress.opened |= !entries.is_empty();

        let finished = match decoded {
            // Every entry the batch declared is out. The shreds that may still
            // be owed hold nothing but the padding to the end of the erasure
            // batch, so there is no reason to wait for them.
            Decoded::Done if any => Some(BatchOutcome::Decoded),
            Decoded::Done => Some(BatchOutcome::Marker),
            Decoded::Invalid => Some(BatchOutcome::Failed),
            // The batch is closed and still owes entries, so its bytes were
            // never a whole `Vec<Entry>` to begin with.
            Decoded::Waiting if extent.complete => Some(BatchOutcome::Failed),
            Decoded::Waiting => None,
        };
        progress.closed = finished.is_some();

        if entries.is_empty() && finished.is_none() {
            return None;
        }
        Some(Advance {
            last_shred: extent.last,
            entries,
            latency: extent.first_received.elapsed(),
            opened,
            finished,
            recovered: extent.recovered,
        })
    }

    /// Walks the run of consecutive shreds beginning at `start`, which is as
    /// much of the batch as has arrived. A gap ends the walk, and so does the
    /// data-complete shred that closes the batch.
    ///
    /// `cached` is where an earlier walk of this same run stopped. A run grows
    /// only at its far end and the shreds already crossed cannot change under
    /// it — a duplicate that would change one drops the cache — so the walk
    /// resumes at the frontier and every shred of a batch is crossed once
    /// rather than once per shred that follows it.
    fn extent(&self, start: u32, cached: Option<Extent>) -> Option<Extent> {
        // A run that has reached its terminator is all there will ever be of
        // the batch, so there is nothing left to walk.
        if matches!(&cached, Some(extent) if extent.complete) {
            return cached;
        }
        let mut index = cached.map_or(start, |extent| extent.last + 1);
        let mut first_received: Option<Instant> = cached.map(|extent| extent.first_received);
        let mut recovered = cached.is_some_and(|extent| extent.recovered);
        let mut complete = false;
        let mut len = cached.map_or(0, |extent| extent.len);

        while let Some(shred) = self.shreds.get(&index) {
            len += shred.len as usize;
            first_received = Some(match first_received {
                Some(earliest) if earliest <= shred.received => earliest,
                _ => shred.received,
            });
            recovered |= shred.recovered;
            index += 1;
            if shred.data_complete {
                complete = true;
                break;
            }
        }

        Some(Extent {
            // The loop leaves `index` one past the last shred it took.
            last: index.checked_sub(1).filter(|last| *last >= start)?,
            complete,
            first_received: first_received?,
            recovered,
            len,
        })
    }

    /// The run's bytes from `consumed` on, and where in the batch they begin.
    ///
    /// Shreds already turned into entries are left out, which is what keeps a
    /// run that arrived out of order from being stitched together again from
    /// scratch on every shred: what has to be copied is the undecoded tail, not
    /// the whole batch. A run laid end to end in the arena — which is what
    /// in-order delivery produces — is read where it lies and copied not at all.
    fn payload(&self, start: u32, extent: &Extent, progress: &mut Progress) -> (Payload, usize) {
        // Resuming where the last pass stopped rather than at the batch's first
        // shred: the shreds behind that point are read and stay read.
        let (mut from, mut base) = progress.resume.unwrap_or((start, 0));
        while from <= extent.last {
            let len = self.shreds[&from].len as usize;
            if base + len > progress.consumed {
                break;
            }
            base += len;
            from += 1;
        }
        progress.resume = Some((from, base));
        // Every byte held has been read already. There is nothing to hand the
        // decoder, but it is still owed the chance to say the batch is short.
        if from > extent.last {
            return (Payload::Arena { at: 0, len: 0 }, base);
        }

        let mut at = 0;
        let mut len = 0;
        let mut next = None;
        let mut contiguous = true;
        for member in from..=extent.last {
            let shred = &self.shreds[&member];
            match next {
                None => at = shred.at,
                Some(expected) => contiguous &= shred.at == expected,
            }
            next = Some(shred.at + shred.len as usize);
            len += shred.len as usize;
        }

        if contiguous {
            return (Payload::Arena { at, len }, base);
        }
        let mut stitched = Vec::with_capacity(len);
        for member in from..=extent.last {
            stitched.extend_from_slice(self.bytes(&self.shreds[&member]));
        }
        (Payload::Stitched(stitched), base)
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
    /// Entry bytes held across every slot. Kept as a running total because the
    /// budget has to be answered on the packet path, and resynced on each sweep
    /// so that slots let go without passing through it cannot drift it upwards.
    bytes: usize,
    metrics: Arc<AssemblerMetrics>,
}

impl Assembler {
    pub fn new(retention: Duration, metrics: Arc<AssemblerMetrics>) -> Self {
        Self {
            slots: AgedMap::new(retention, MAX_BUFFERED_SLOTS, "slot buffers"),
            bytes: 0,
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

        // Nothing signs a shred, so the sender of one is only ever a claim, and
        // the memory it asks for is the one cost that outlives the packet. The
        // budget is answered before the bytes are taken rather than after,
        // because after is where the machine is already out of them. The
        // bookkeeping is charged alongside the payload, because a shred that
        // carries no payload still costs it.
        if self.bytes + shred.data.len() + PER_SHRED_OVERHEAD + PER_BATCH_OVERHEAD
            > MAX_BUFFERED_BYTES
        {
            self.metrics.over_budget();
            return Vec::new();
        }

        let buffer = self.slots.upsert(shred.slot, now, SlotBuffer::new);
        // A slot is capped on what its shreds carry and on how many of them
        // there are, because the two come apart: an empty payload is legal on
        // the wire, and a slot full of those clears any byte budget while still
        // taking a map entry apiece. A second copy of an index already held
        // passes, since it adds no entry.
        if buffer.live() + shred.data.len() > MAX_SLOT_BYTES
            || (buffer.shreds.len() >= MAX_SLOT_SHREDS && !buffer.shreds.contains_key(&shred.index))
        {
            self.metrics.over_budget();
            return Vec::new();
        }
        if shred.last_in_slot {
            buffer.last_index = Some(shred.index);
        }
        let held = buffer.footprint();
        let duplicate = buffer.insert(shred.index, shred.data, shred.data_complete, now, recovered);
        if duplicate {
            self.metrics.duplicate();
        }

        let mut batches = Vec::new();
        for start in buffer.candidates(shred.index).into_iter().flatten() {
            let Some(advance) = buffer.advance(start) else {
                continue;
            };
            if advance.opened {
                self.metrics.opened(advance.latency, advance.recovered);
            }
            if let Some(outcome) = advance.finished {
                self.metrics
                    .batch(outcome, advance.latency, advance.recovered);
            }
            if !advance.entries.is_empty() {
                self.metrics.entries(advance.entries.len() as u64);
                batches.push(DecodedBatch {
                    first_shred: start,
                    last_shred: advance.last_shred,
                    entries: advance.entries,
                });
            }
        }
        // Taken after decoding rather than before it: `advance` is what creates
        // the `Progress` a batch keeps between shreds, and the arena may have
        // compacted or grown under the insert. The shred's own length is not
        // the delta either — a duplicate frees whatever the copy it displaced
        // was holding.
        self.bytes = self.bytes + buffer.footprint() - held;
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
            // Slots the cap gives up on never reach the callback above, so the
            // total is rebuilt from what is left rather than decremented on the
            // way out. Once a sweep, over some tens of slots.
            self.bytes = self.slots.values().map(SlotBuffer::footprint).sum();
            self.metrics.set_buffered_slots(self.slots.len() as u64);
            self.metrics.set_buffered_bytes(self.bytes as u64);
        }
    }
}

/// Where a pass of the decoder left the batch.
enum Decoded {
    /// The bytes end part way through an entry, which is what a batch still
    /// arriving looks like.
    Waiting,
    /// Every entry the batch declared has been decoded.
    Done,
    /// The bytes are not the entries they claim to be.
    Invalid,
}

/// Reads whole entries out of `bytes`, resuming where the last pass stopped and
/// appending what it gets to `out`.
///
/// Only entries that are entirely present are taken, so the pass that finds the
/// batch cut short leaves everything it could not finish for the next one. The
/// cost of that is re-reading the bytes of one part-arrived entry per shred,
/// which is bounded by an entry and is the price of not waiting for the rest of
/// the batch.
///
/// `base` is where `bytes` begins in the batch, since what is handed over is
/// only the part of it that has not been read yet.
fn decode(bytes: &[u8], base: usize, progress: &mut Progress, out: &mut Vec<Entry>) -> Decoded {
    if progress.remaining.is_none() {
        let at = progress.consumed - base;
        let Some(count) = bytes.get(at..at + ENTRY_COUNT) else {
            return Decoded::Waiting;
        };
        let Ok(count) = count.try_into() else {
            return Decoded::Invalid;
        };
        let count = u64::from_le_bytes(count);
        // Refused here rather than left to the loop below, which would other-
        // wise spend the rest of the batch's arrival being told it is one entry
        // short of a count nothing could satisfy.
        if count.saturating_mul(MIN_ENTRY_BYTES) > MAX_BATCH_BYTES as u64 {
            debug!(count, "batch declared more entries than it could hold");
            return Decoded::Invalid;
        }
        progress.remaining = Some(count);
        progress.consumed += ENTRY_COUNT;
    }

    while progress.remaining.is_some_and(|left| left > 0) {
        let rest = &bytes[progress.consumed - base..];
        if rest.is_empty() {
            return Decoded::Waiting;
        }
        // Deserializing through a cursor rather than off the slice is what says
        // where the entry ended, and so where the next one begins.
        let mut cursor = Cursor::new(rest);
        match bincode::deserialize_from::<_, Entry>(&mut cursor) {
            Ok(entry) => {
                progress.consumed += cursor.position() as usize;
                progress.remaining = progress.remaining.map(|left| left - 1);
                out.push(entry);
            }
            // Running out of bytes mid-entry is the ordinary case: the shreds
            // holding the rest of it have not arrived.
            Err(err) if truncated(&err) => return Decoded::Waiting,
            Err(err) => {
                debug!(bytes = rest.len(), %err, "failed to decode entry");
                return Decoded::Invalid;
            }
        }
    }
    Decoded::Done
}

/// Whether the decoder simply ran out of bytes, as opposed to reading bytes
/// that could not have come from a leader. The bytes we do hold are whatever the
/// leader wrote, so anything that is merely incomplete ends at the end.
fn truncated(err: &bincode::Error) -> bool {
    matches!(
        &**err,
        bincode::ErrorKind::Io(io) if io.kind() == std::io::ErrorKind::UnexpectedEof
    )
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

    fn shred(slot: u64, index: u32, data: &[u8], data_complete: bool) -> DataShred<'_> {
        DataShred {
            slot,
            index,
            fec_set_index: 0,
            data_complete,
            last_in_slot: data_complete,
            reference_tick: 0,
            data,
            shard: &[],
        }
    }

    /// Transactions in what a shred handed over.
    fn count(batches: &[DecodedBatch]) -> usize {
        batches
            .iter()
            .flat_map(|batch| &batch.entries)
            .map(|entry| entry.transactions.len())
            .sum()
    }

    /// Feeds a batch to the assembler split across shreds of `chunk` bytes, and
    /// reports the transactions each shred released. A batch is decoded as it
    /// arrives, so which shred released what is the whole point.
    fn feed_each(
        assembler: &mut Assembler,
        slot: u64,
        payload: &[u8],
        chunk: usize,
        reverse: bool,
    ) -> Vec<usize> {
        let chunks: Vec<&[u8]> = payload.chunks(chunk).collect();
        let last = chunks.len() - 1;
        let mut shreds: Vec<(u32, &[u8])> = chunks
            .into_iter()
            .enumerate()
            .map(|(index, data)| (index as u32, data))
            .collect();
        if reverse {
            shreds.reverse();
        }

        shreds
            .into_iter()
            .map(|(index, data)| {
                let shred = shred(slot, index, data, index as usize == last);
                count(&assembler.insert(&shred, false))
            })
            .collect()
    }

    /// Feeds a batch to the assembler split across shreds, and reports the
    /// transactions that came back out.
    fn feed(assembler: &mut Assembler, slot: u64, payload: &[u8], reverse: bool) -> usize {
        feed_each(assembler, slot, payload, CHUNK, reverse)
            .into_iter()
            .sum()
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
        for index in order {
            buffer.insert(index, &[index as u8; 4], index == 2, now, false);
        }

        let extent = buffer.extent(0, None).expect("the run begins at zero");
        assert!(extent.complete, "shred two closed the batch");
        let (payload, base) = buffer.payload(0, &extent, &mut Progress::default());
        assert_eq!(base, 0, "nothing had been read yet");
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
        let duplicate = shred(SLOT, 0, chunks[0], false);
        // The first copy releases whatever entries it already carries whole;
        // every copy after it is bytes we have already read.
        let opened = count(&assembler.insert(&duplicate, false));
        // Far more dead bytes than the floor, so compaction has to have run.
        let resends = 8 * COMPACT_FLOOR / CHUNK;
        for _ in 0..resends {
            assert!(
                assembler.insert(&duplicate, false).is_empty(),
                "a resent shred handed over its entries twice"
            );
        }

        let arena = assembler.slots.get(&SLOT).unwrap().arena.len();
        assert!(
            arena < 4 * COMPACT_FLOOR,
            "{arena} bytes held for {resends} resends of one shred",
        );

        // The batch still has to come out whole once the rest of it arrives,
        // which is what says compaction rewrote the offsets rather than
        // shuffling the bytes out from under them.
        assert_eq!(
            opened + feed(&mut assembler, SLOT, &payload, false),
            expected
        );
    }

    /// Bounding the buffers and the indices a sender can touch says nothing
    /// about what they hold. Every index a leader could use, filled with as
    /// much as a shred carries, is tens of megabytes in a single slot — and
    /// the sender of a shred is never checked.
    #[test]
    fn one_slot_cannot_be_filled_past_its_budget() {
        let mut assembler = assembler();
        let data = vec![0u8; 1024];
        let attempted = 32_768usize;
        for index in 0..attempted as u32 {
            assembler.insert(&shred(SLOT, index, &data, false), false);
        }

        assert!(
            attempted * data.len() > 2 * MAX_SLOT_BYTES,
            "the attempt has to overshoot the budget to prove anything"
        );
        let buffer = assembler.slots.get(&SLOT).unwrap();
        let held = buffer.live();
        assert!(
            held <= MAX_SLOT_BYTES,
            "{held} bytes held against a budget of {MAX_SLOT_BYTES}"
        );
        assert_eq!(
            assembler.bytes,
            buffer.footprint(),
            "the running total drifted"
        );
    }

    /// The budget has to be answered across slots too: the per-slot cap
    /// multiplied by the number of buffers is far more memory than the machine
    /// has, and a spoofed slot number is free.
    #[test]
    fn a_full_budget_refuses_shreds_it_would_otherwise_decode() {
        let (payload, expected) = batch(1, 1);
        assert!(expected > 0, "the payload has to be worth something");

        let mut assembler = assembler();
        assembler.bytes = MAX_BUFFERED_BYTES;
        let refused = assembler.insert(&shred(SLOT, 0, &payload, true), false);
        assert!(
            refused.is_empty(),
            "a refused shred still handed over entries"
        );
        assert!(
            assembler.slots.get(&SLOT).is_none(),
            "a refused shred was buffered anyway"
        );

        // The same shred against a clear budget, so what stopped it above was
        // the budget rather than anything about the payload.
        assembler.bytes = 0;
        let taken = assembler.insert(&shred(SLOT, 0, &payload, true), false);
        assert_eq!(count(&taken), expected);
    }

    /// A duplicate strands the bytes of the copy it displaced, and compaction
    /// is what takes them back. Without it one index, resent, would grow the
    /// arena without bound and fill the budget on its own.
    #[test]
    fn duplicates_do_not_fill_the_budget() {
        let mut assembler = assembler();
        let data = vec![7u8; 1024];
        let resends = 4096;
        for _ in 0..resends {
            assembler.insert(&shred(SLOT, 0, &data, false), false);
        }

        let buffer = assembler.slots.get(&SLOT).unwrap();
        assert_eq!(buffer.shreds.len(), 1, "one index, held once");
        assert_eq!(
            buffer.live(),
            data.len(),
            "one shred resent read as more than one shred held"
        );
        // Compaction only pays for itself above `COMPACT_FLOOR`, so the arena
        // is allowed to carry that much stranded before it is rebuilt — but not
        // the megabytes the resends would otherwise have appended.
        assert!(
            assembler.bytes < 4 * COMPACT_FLOOR,
            "{} bytes resident after {resends} resends of one shred",
            assembler.bytes
        );
        assert_eq!(
            assembler.bytes,
            buffer.footprint(),
            "the running total drifted"
        );
    }

    /// Slots given up on by the cap never pass through the sweep's callback, so
    /// a total only ever decremented on the way out would climb until it
    /// refused everything.
    #[test]
    fn the_budget_matches_what_is_actually_held() {
        let mut assembler = assembler();
        let data = vec![3u8; 512];
        for slot in 0..8 * MAX_BUFFERED_SLOTS as u64 {
            assembler.insert(&shred(slot, 0, &data, false), false);
        }

        let held: usize = assembler.slots.values().map(SlotBuffer::footprint).sum();
        assert!(held > 0, "everything was swept, which proves nothing");
        assert_eq!(assembler.bytes, held, "the running total drifted");
    }

    /// The byte budgets bound what shreds carry, and a shred is allowed to
    /// carry nothing: `size` stopping at the headers is a legal payload of zero
    /// length. Every one of those still takes a map entry, so without a cap on
    /// the count a sender could pin the format's whole index space in a slot
    /// for free — and every byte budget would read as satisfied while it did.
    #[test]
    fn empty_shreds_cannot_pin_a_slot_for_free() {
        let mut assembler = assembler();
        let attempted = 32_768u32;
        for index in 0..attempted {
            assembler.insert(&shred(SLOT, index, &[], false), false);
        }

        let buffer = assembler.slots.get(&SLOT).unwrap();
        assert_eq!(
            buffer.live(),
            0,
            "empty shreds are what makes this cost nothing by payload"
        );
        assert!(
            buffer.shreds.len() <= MAX_SLOT_SHREDS,
            "{} shreds held against a cap of {MAX_SLOT_SHREDS}",
            buffer.shreds.len()
        );
        assert!(
            assembler.bytes > 0,
            "the shreds held cost memory the budget could not see"
        );
    }

    /// A prefix that will not decode has nowhere to resume from, so every shred
    /// that extends the run has it read again from the batch's first byte. Left
    /// unbounded that is quadratic in what a sender chooses to send, and the
    /// bytes need only be undecodable, which is most bytes.
    #[test]
    fn a_run_that_never_decodes_is_given_up_on() {
        let mut assembler = assembler();
        // A plausible entry count, so the batch is refused for its length
        // rather than for declaring something absurd, followed by bytes that
        // will never deserialize into an entry.
        let mut opening = 4u64.to_le_bytes().to_vec();
        opening.resize(CHUNK, 0xff);

        let shreds = 2 * MAX_BATCH_BYTES / CHUNK;
        let started = Instant::now();
        for index in 0..shreds as u32 {
            let body = if index == 0 {
                &opening
            } else {
                &vec![0xffu8; CHUNK]
            };
            assert!(
                assembler
                    .insert(&shred(SLOT, index, body, false), false)
                    .is_empty(),
                "undecodable bytes handed over entries"
            );
        }
        let spent = started.elapsed();

        let buffer = assembler.slots.get(&SLOT).unwrap();
        assert!(
            buffer.progress[&0].closed,
            "the run was still being re-read after {} bytes",
            shreds * CHUNK
        );
        // Generous by orders of magnitude against a machine under load: what
        // this is here to catch is the quadratic blow-up, which ran to seconds
        // for a run this size before the bound existed.
        assert!(
            spent < Duration::from_secs(5),
            "{shreds} undecodable shreds took {spent:?}"
        );
    }

    /// The count a batch opens with is the sender's word for how many entries
    /// follow. Believing an impossible one costs the rest of the batch's
    /// arrival, each shred of it re-reading bytes that can never satisfy it.
    #[test]
    fn an_impossible_entry_count_is_refused_at_once() {
        let mut assembler = assembler();
        let mut body = u64::MAX.to_le_bytes().to_vec();
        body.resize(CHUNK, 0);

        assert!(
            assembler
                .insert(&shred(SLOT, 0, &body, false), false)
                .is_empty(),
            "a batch claiming u64::MAX entries handed some over"
        );
        assert!(
            assembler.slots.get(&SLOT).unwrap().progress[&0].closed,
            "an impossible count was left open to be re-read"
        );
    }

    /// The cap on how many shreds a slot may hold must not be reachable by
    /// resending one index, or a leader whose shred arrives twice would stop
    /// being decoded.
    #[test]
    fn a_resent_index_does_not_count_against_the_shred_cap() {
        let mut assembler = assembler();
        let data = vec![1u8; 64];
        for index in 0..MAX_SLOT_SHREDS as u32 {
            assembler.insert(&shred(SLOT, index, &data, false), false);
        }
        assert_eq!(
            assembler.slots.get(&SLOT).unwrap().shreds.len(),
            MAX_SLOT_SHREDS,
            "the slot has to be full for the rest of this to mean anything"
        );

        let replacement = vec![2u8; 64];
        assembler.insert(&shred(SLOT, 0, &replacement, false), false);

        let buffer = assembler.slots.get(&SLOT).unwrap();
        let stored = &buffer.shreds[&0];
        assert_eq!(
            buffer.bytes(stored),
            replacement.as_slice(),
            "a full slot refused a second copy of an index it already held"
        );
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
    /// completion check has to notice the batch the insert created a boundary in
    /// front of, not only the batch the insert landed in.
    #[test]
    fn a_late_terminator_releases_the_batch_behind_it() {
        let (first, first_expected) = batch(2, 2);
        let (second, second_expected) = batch(2, 2);
        let halves = |payload: &[u8]| -> Vec<Vec<u8>> {
            payload
                .chunks(payload.len().div_ceil(2))
                .map(<[u8]>::to_vec)
                .collect()
        };
        let (first, second) = (halves(&first), halves(&second));

        let mut assembler = assembler();
        // The second batch arrives whole while the first is still missing, so
        // nothing yet says where it begins.
        assert!(
            assembler
                .insert(&shred(SLOT, 2, &second[0], false), false)
                .is_empty()
        );
        assert!(
            assembler
                .insert(&shred(SLOT, 3, &second[1], true), false)
                .is_empty(),
            "no batch can be placed while the first one is open"
        );

        // The terminator of the first batch is what puts a boundary in front of
        // the second, and it has to release both.
        let opened = count(&assembler.insert(&shred(SLOT, 0, &first[0], false), false));
        let released = assembler.insert(&shred(SLOT, 1, &first[1], true), false);
        let ranges: Vec<(u32, u32)> = released
            .iter()
            .map(|batch| (batch.first_shred, batch.last_shred))
            .collect();
        assert_eq!(ranges, vec![(0, 1), (2, 3)]);
        assert_eq!(
            opened + count(&released),
            first_expected + second_expected,
            "every transaction of both batches has to come out exactly once"
        );
    }

    /// The point of the whole assembler: a batch is read as it arrives, so the
    /// entries at its front reach the sniper without waiting for the shreds at
    /// its back. Nothing may be handed over twice on the way.
    #[test]
    fn entries_come_out_before_the_batch_is_whole() {
        let (payload, expected) = batch(6, 2);
        let mut assembler = assembler();
        let released = feed_each(&mut assembler, SLOT, &payload, CHUNK, false);
        assert!(
            released.len() > 2,
            "a batch of one or two shreds proves nothing"
        );

        let early: usize = released[..released.len() - 1].iter().sum();
        assert!(
            early > 0,
            "nothing came out until the last shred: {released:?}"
        );
        assert_eq!(
            released.iter().sum::<usize>(),
            expected,
            "transactions were lost or repeated: {released:?}"
        );
    }

    /// Entries straddle shred boundaries, and so does the count a batch opens
    /// with. Both have to survive being cut anywhere, so the batch is fed in
    /// pieces far smaller than a leader would ever produce.
    #[test]
    fn an_entry_split_across_shreds_is_decoded_once() {
        let (payload, expected) = batch(4, 2);
        let mut assembler = assembler();
        let released = feed_each(&mut assembler, SLOT, &payload, 4, false);
        assert_eq!(released.iter().sum::<usize>(), expected);
    }

    /// Shreds that arrived out of order have to be stitched together, and doing
    /// that for the whole batch on every shred would make a batch cost the
    /// square of its length to read. Only the bytes still to be decoded are
    /// worth copying.
    #[test]
    fn stitching_only_covers_what_is_left_to_read() {
        let now = Instant::now();
        let mut buffer = SlotBuffer::new();
        // Out of order, so the run is never one stretch of the arena.
        for index in [2u32, 1, 0, 3] {
            buffer.insert(index, &[index as u8; 100], index == 3, now, false);
        }

        let extent = buffer.extent(0, None).expect("the run begins at zero");
        // A progress of its own per case: what has been read only ever moves
        // forward, so these are three batches at three points, not one batch
        // read backwards.
        let read = |consumed: usize| Progress {
            consumed,
            ..Progress::default()
        };

        let (whole, base) = buffer.payload(0, &extent, &mut read(0));
        assert_eq!(base, 0);
        assert!(
            matches!(&whole, Payload::Stitched(bytes) if bytes.len() == 400),
            "the whole run has to be stitched while none of it has been read"
        );

        // Two shreds in, only the two behind them are worth copying.
        let (tail, base) = buffer.payload(0, &extent, &mut read(200));
        assert_eq!(base, 200, "the tail begins where the reading stopped");
        assert!(
            matches!(&tail, Payload::Stitched(bytes) if bytes.len() == 200),
            "the bytes already read were copied again"
        );

        // Part way into a shred, that shred is still needed whole.
        let (straddled, base) = buffer.payload(0, &extent, &mut read(150));
        assert_eq!(base, 100, "the shred holding the next entry starts at 100");
        assert!(matches!(&straddled, Payload::Stitched(bytes) if bytes.len() == 300));
    }

    /// The point of carrying the walk between shreds: a batch of `n` shreds is
    /// crossed once, not once per shred. Both walks have to move — the run's
    /// frontier and the point reading resumes at — or a long batch costs the
    /// square of its length to take in.
    #[test]
    fn a_batch_is_walked_once_rather_than_once_per_shred() {
        // How far behind the run's end the two walks start on the last shred of
        // a batch of `entries`. Both have to be a constant: it is their growing
        // with the batch that made a batch cost the square of its length.
        let lag = |entries: usize| -> (usize, usize) {
            let (payload, expected) = batch(entries, 1);
            let chunks: Vec<&[u8]> = payload.chunks(64).collect();
            let last = chunks.len() - 1;
            assert!(last > 16, "a short batch would not show the difference");

            let mut assembler = assembler();
            let mut released = 0;
            for (index, data) in chunks.into_iter().enumerate() {
                let shred = shred(SLOT, index as u32, data, index == last);
                released += count(&assembler.insert(&shred, false));
            }
            assert_eq!(released, expected, "the batch still has to come out whole");

            let progress = &assembler.slots.get(&SLOT).unwrap().progress[&0];
            let extent = progress.extent.expect("the run was walked");
            assert_eq!(extent.last as usize, last, "the frontier reached the end");
            let (from, _) = progress.resume.expect("reading left a resume point");
            // The frontier is walked before this shred's bytes are read and the
            // resume point is set before they are decoded, so both are a pass
            // behind rather than at the end.
            (last - extent.last as usize, last - from as usize)
        };

        let short = lag(64);
        let long = lag(1024);
        assert_eq!(
            short, long,
            "the walks start further back on the longer batch: {short:?} against {long:?}"
        );
    }

    /// Bytes that are not entries have to be given up on rather than retried
    /// for every shred that follows them.
    #[test]
    fn a_batch_that_is_not_entries_is_given_up_on() {
        let mut buffer = SlotBuffer::new();
        let now = Instant::now();
        // A count no batch could hold, so the decoder is left owed entries that
        // never come.
        buffer.insert(0, &u64::MAX.to_le_bytes(), true, now, false);

        let advance = buffer
            .advance(0)
            .expect("the batch was closed by its shred");
        assert!(matches!(advance.finished, Some(BatchOutcome::Failed)));
        assert!(advance.entries.is_empty());
        assert!(
            buffer.advance(0).is_none(),
            "a batch already given up on was decoded again"
        );
    }
}
