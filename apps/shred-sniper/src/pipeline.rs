use {
    crate::{
        config::Config,
        entries::Assembler,
        erasure::Recovery,
        fire::{Fire, Firing},
        metrics::{Metrics, PacketKind},
        race,
        shred::{self, DataShred},
    },
    rustc_hash::FxHashSet,
    solana_streamer::packet::Packet,
    solana_transaction::{Address, Signature, versioned::VersionedTransaction},
    std::{
        collections::HashSet,
        net::IpAddr,
        sync::Arc,
        time::{Duration, Instant},
    },
    tracing::{Level, debug, enabled, info},
};

const VOTE_PROGRAM: Address =
    Address::from_str_const("Vote111111111111111111111111111111111111111");

/// Slot numbers come off the wire unauthenticated. Latching on to the highest
/// one ever seen would let a single spoofed shred freeze the per-slot counters
/// for good, so a slot this far below the current one re-anchors them instead.
const MAX_SLOT_ADVANCE: u64 = 1024;

/// A slot runs 64 ticks, so a shred's reference tick places it to about six
/// milliseconds within the slot *by the leader's clock*. Comparing that against
/// when the shred reached us is the only reading on delivery timing available
/// without a second source of truth. It is a cluster parameter, not a constant
/// of nature: a cluster with another tick rate would need this changed.
const TICK: Duration = Duration::from_nanos(400_000_000 / 64);

/// Everything that resets at a slot boundary, kept together so crossing one is
/// a single assignment and no counter can be left behind.
struct SlotState {
    /// The slot the packet path is anchored on.
    number: u64,
    /// When we first saw a shred of it, which is the only slot clock we have.
    started: Instant,
    shreds: u64,
    transactions: u64,
}

impl SlotState {
    fn new(number: u64) -> Self {
        Self {
            number,
            started: Instant::now(),
            shreds: 0,
            transactions: 0,
        }
    }
}

/// The parse path: a datagram in, metrics and snipe reports out.
pub struct Pipeline {
    assembler: Assembler,
    recovery: Recovery,
    metrics: Arc<Metrics>,
    shred_version: u16,
    snipe_program: Option<Address>,
    /// Peers that have sent us shreds, so a new one can be reported once
    /// rather than on every packet. Std hashing, since the wire gets to insert.
    sources: HashSet<IpAddr>,
    /// Fee payers of the wallets being raced. Reacting to one of their
    /// transactions is only possible with slot left to react in, so what these
    /// are here for is to time how much of it there is.
    watched: FxHashSet<Address>,
    /// Our own fee payers. Kept apart from `watched` because a transaction of
    /// ours is not something to react to — it is the answer to something we
    /// already reacted to, coming back around.
    searchers: FxHashSet<Address>,
    /// Present only when a wallet to watch is configured.
    race: Option<race::Tracker>,
    /// Present only when there is a key to sign with.
    fire: Option<Arc<Fire>>,
    shreds_seen: u64,
    slot: SlotState,
    started: Instant,
}

impl Pipeline {
    pub fn new(
        config: &Config,
        shred_version: u16,
        metrics: Arc<Metrics>,
        firing: Option<Firing>,
    ) -> Self {
        // The address we sign with counts as one of ours whether or not it was
        // also listed by hand, so arming the sniper is enough to have its own
        // transactions recognised on the way back.
        let mut searchers = config.searcher_wallets.clone();
        if let Some(firing) = &firing
            && !searchers.contains(&firing.searcher)
        {
            searchers.push(firing.searcher);
        }

        Self {
            assembler: Assembler::new(config.retention, metrics.assembler.clone()),
            recovery: Recovery::new(config.retention, metrics.recovery.clone()),
            metrics,
            shred_version,
            snipe_program: config.snipe_program,
            sources: HashSet::new(),
            watched: config.target_wallets.iter().copied().collect(),
            race: race::Tracker::new(&searchers, &config.target_wallets),
            fire: firing.map(|firing| firing.fire),
            searchers: searchers.into_iter().collect(),
            shreds_seen: 0,
            slot: SlotState::new(0),
            started: Instant::now(),
        }
    }

    /// One datagram. Coding shreds carry no entries of their own, they only let
    /// us reconstruct data shreds turbine failed to deliver, so what comes out
    /// of a packet is the data shred it held — if any — plus whatever its
    /// erasure batch could rebuild.
    pub fn packet(&mut self, packet: &Packet) {
        let Some(bytes) = packet.data(..) else {
            return;
        };
        let from = packet.meta().addr;
        let processing_started = Instant::now();
        let shred_version = self.shred_version;

        let recovered;
        let received = match shred::parse(bytes, shred_version) {
            Some(shred::Shred::Data(data_shred)) => {
                self.metrics.packets.received(PacketKind::Data);
                if self.sources.insert(from) {
                    self.metrics
                        .node
                        .set_turbine_sources(self.sources.len() as u64);
                    info!(source = %from, "new turbine source");
                }
                recovered = self.recovery.insert_data(&data_shred);
                Some(data_shred)
            }
            Some(shred::Shred::Coding(coding_shred)) => {
                self.metrics.packets.received(PacketKind::Coding);
                recovered = self.recovery.insert_coding(&coding_shred);
                None
            }
            None => {
                self.metrics.packets.received(PacketKind::Other);
                return;
            }
        };

        // Recovered shreds are tagged so a batch can later say whether it
        // waited on erasure rather than on the wire.
        if let Some(data_shred) = &received {
            self.data_shred(data_shred, false);
        }
        for body in &recovered {
            if let Some(data_shred) = shred::parse_data(body, shred_version) {
                self.data_shred(&data_shred, true);
            }
        }

        self.metrics.packets.processed(processing_started.elapsed());
    }

    fn data_shred(&mut self, shred: &DataShred<'_>, from_recovery: bool) {
        self.anchor(shred.slot);
        self.shreds_seen += 1;
        self.slot.shreds += 1;

        // How far into the slot we are, by our own clock. Only the anchored
        // slot has a start we can measure against: a shred of a slot we have
        // already left would be timed from the wrong origin and read as having
        // arrived far earlier than it did, which is precisely the direction
        // that would flatter every latency below.
        let slot_offset = (shred.slot == self.slot.number).then(|| self.slot.started.elapsed());

        // Recovered shreds arrive when we reconstruct them, not when the leader
        // sent them, so including them would measure our own recovery rather
        // than turbine's delivery.
        if let (Some(offset), false) = (slot_offset, from_recovery) {
            self.metrics
                .slots
                .delivery_skew(offset, TICK * u32::from(shred.reference_tick));
        }

        for batch in self.assembler.insert(shred, from_recovery) {
            for entry in &batch.entries {
                for transaction in &entry.transactions {
                    self.slot.transactions += 1;
                    self.report(shred.slot, slot_offset, transaction);
                }
            }
            if let Some(race) = &mut self.race {
                race.batch(shred.slot, &batch);
            }
        }
    }

    /// Moves the slot anchor, closing out the counters of the slot being left.
    /// It moves on two conditions rather than one: forward for a higher slot,
    /// and backward for a slot far enough below that what we are anchored on
    /// cannot have been the leader's own progress.
    fn anchor(&mut self, slot: u64) {
        let advanced = slot > self.slot.number;
        let stale = slot.saturating_add(MAX_SLOT_ADVANCE) < self.slot.number;
        if !advanced && !stale {
            return;
        }

        // The first slot we ever see has no predecessor to have taken time.
        let duration = (self.slot.number != 0).then(|| self.slot.started.elapsed());
        self.metrics
            .slots
            .completed(slot, duration, self.slot.shreds, self.slot.transactions);
        self.slot = SlotState::new(slot);
        info!(
            slot,
            shreds = self.shreds_seen,
            uptime_secs = self.started.elapsed().as_secs(),
            "new slot"
        );
    }

    fn report(&self, slot: u64, slot_offset: Option<Duration>, transaction: &VersionedTransaction) {
        let message = &transaction.message;
        let keys = message.static_account_keys();
        // The wallet being raced is known by who pays, not by what it calls: a
        // key further down the account list is not the sender.
        let payer = keys.first();
        let signature = transaction.signatures.first();
        self.react(slot, slot_offset, payer, signature);

        // Programs a lookup table would resolve are invisible here, so a snipe
        // target reached through one is missed rather than misreported. Counting
        // the transactions that carry one is what puts a size on that blind spot
        // instead of leaving it as a caveat in a comment.
        let opaque = message
            .address_table_lookups()
            .is_some_and(|lookups| !lookups.is_empty());
        let programs = || {
            message
                .instructions()
                .iter()
                .filter_map(|instruction| keys.get(instruction.program_id_index as usize))
        };
        let vote = programs().any(|program| *program == VOTE_PROGRAM);
        let hit = self
            .snipe_program
            .is_some_and(|target| programs().any(|program| *program == target));
        self.metrics
            .transactions
            .observed(vote, hit, opaque, slot_offset);

        // Base58 encoding every key of every transaction costs more than the
        // rest of the packet path at mainnet rates, so only a logged one pays
        // for it.
        if hit || enabled!(Level::DEBUG) {
            let programs = programs()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            self.log(slot, hit, transaction, payer, &programs);
        }
    }

    /// The two matches the sniper acts on: a watched wallet's transaction is a
    /// trigger, and one of our own coming back around is a landing.
    fn react(
        &self,
        slot: u64,
        slot_offset: Option<Duration>,
        payer: Option<&Address>,
        signature: Option<&Signature>,
    ) {
        if payer.is_some_and(|payer| self.watched.contains(payer)) {
            self.metrics.transactions.watched(slot_offset);
            // The clock the reaction is measured on starts here, at the first
            // instant the trigger was knowable, rather than wherever the sender
            // thread happens to pick it up.
            if let (Some(fire), Some(signature)) = (&self.fire, signature) {
                fire.trigger(slot, *signature, Instant::now());
            }
        }

        // Our own answer, back around through the same turbine that carried the
        // trigger. Matching it here is what closes the loop without asking the
        // RPC whether the send worked.
        if let Some(fire) = &self.fire
            && payer.is_some_and(|payer| self.searchers.contains(payer))
            && let Some(signature) = signature
        {
            fire.landed(signature, slot);
        }
    }

    fn log(
        &self,
        slot: u64,
        hit: bool,
        transaction: &VersionedTransaction,
        payer: Option<&Address>,
        programs: &str,
    ) {
        let signature = race::signature(transaction);
        let payer = payer
            .map(ToString::to_string)
            .unwrap_or_else(|| "?".to_string());

        if hit {
            info!(slot, %signature, %payer, %programs, "🎯 SNIPE");
        } else {
            debug!(slot, %signature, %payer, %programs, "tx");
        }
    }
}
