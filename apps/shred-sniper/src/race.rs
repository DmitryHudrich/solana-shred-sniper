//! Where the bot landed relative to the wallet it is racing.
//!
//! Both sides are known by address, so nothing here guesses who is who. What it
//! does have to work out is *order*: which of two transactions the leader put
//! first, and how many transactions it put between them. That cannot be read
//! off arrival times — a batch is decoded when its last shred turns up, so an
//! early batch delivered late is decoded after a later one. Order comes from
//! the shred indices instead, which is the order the leader wrote.
//!
//! One caveat rides along with every number here. Transactions inside a single
//! entry are executed in parallel — the leader put them there precisely because
//! they touch no common account — so a gap measured within one entry says
//! nothing about who went first. `same_entry` marks those lines.

use {
    crate::entries::DecodedBatch,
    solana_transaction::{Address, versioned::VersionedTransaction},
    std::{
        collections::{BTreeMap, HashMap, HashSet},
        time::{Duration, Instant},
    },
    tracing::{info, warn},
};

/// A slot is reported once nothing has landed in it for this long. Waiting for
/// the assembler's full retention would be correct and useless: the answer
/// would arrive half a minute after the race it describes. Turbine delivers a
/// slot inside its own 400 ms, so a second of quiet means the stragglers and
/// whatever erasure could rebuild are all in.
const SETTLE: Duration = Duration::from_secs(1);

/// Sweeping every slot on every batch would put this on the packet path.
const EVICT_INTERVAL: Duration = Duration::from_millis(200);

/// Slot numbers are unauthenticated, so spoofed ones must not be able to pin
/// memory. Well above what `SETTLE` can legitimately hold open.
const MAX_SLOTS: usize = 64;

/// Both sides are normally one transaction each. A slot that somehow holds
/// dozens of both would otherwise report their product.
const MAX_PAIRS: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Searcher,
    Target,
}

/// One transaction we care about, and where in the slot it sits.
struct Hit {
    role: Role,
    first_shred: u32,
    entry: usize,
    transaction: usize,
    signature: String,
}

/// What a decoded batch contributes to the slot's running order.
struct Span {
    last_shred: u32,
    /// Transactions in each entry of the batch, in order.
    entries: Vec<u32>,
}

/// The batches and hits of one slot, until it settles.
struct Slot {
    batches: BTreeMap<u32, Span>,
    hits: Vec<Hit>,
    updated: Instant,
}

impl Slot {
    fn new(now: Instant) -> Self {
        Self {
            batches: BTreeMap::new(),
            hits: Vec::new(),
            updated: now,
        }
    }

    /// Transactions and entries that precede `hit`, counting only the batches
    /// we hold. Whether that count is the leader's own is what [`Self::tiled`]
    /// answers.
    fn position(&self, hit: &Hit) -> (i64, i64) {
        let mut transactions = 0;
        let mut entries = 0;
        for (first_shred, span) in &self.batches {
            if *first_shred > hit.first_shred {
                break;
            }
            if *first_shred == hit.first_shred {
                transactions += span.entries[..hit.entry]
                    .iter()
                    .map(|count| i64::from(*count))
                    .sum::<i64>()
                    + hit.transaction as i64;
                entries += hit.entry as i64;
                break;
            }
            transactions += span
                .entries
                .iter()
                .map(|count| i64::from(*count))
                .sum::<i64>();
            entries += span.entries.len() as i64;
        }
        (transactions, entries)
    }

    /// Whether the batches between two shreds tile the range with no hole in
    /// it. A hole is a batch we never decoded sitting between the two
    /// transactions, and every transaction it carried is one the gap is short
    /// by — so the number is reported either way, but never as exact.
    fn tiled(&self, from: u32, to: u32) -> bool {
        let (low, high) = if from <= to { (from, to) } else { (to, from) };
        let mut expected = low;
        for (first_shred, span) in self.batches.range(low..=high) {
            if *first_shred != expected {
                return false;
            }
            expected = span.last_shred + 1;
        }
        self.batches.contains_key(&high)
    }

    /// Emits a line per pair. A side that never showed up is still reported —
    /// "the bot did not fire in this slot" is an outcome, not an absence of
    /// data, and a table that silently omits it reads as a clean sheet.
    fn report(&self, slot: u64) {
        let side = |role| self.hits.iter().filter(move |hit| hit.role == role);
        let searchers: Vec<&Hit> = side(Role::Searcher).collect();
        let targets: Vec<&Hit> = side(Role::Target).collect();

        match (searchers.is_empty(), targets.is_empty()) {
            (true, true) => return,
            (true, false) => {
                for target in targets {
                    info!(slot, target = %target.signature, "race");
                }
                return;
            }
            (false, true) => {
                for searcher in searchers {
                    info!(slot, searcher = %searcher.signature, "race");
                }
                return;
            }
            (false, false) => {}
        }

        if searchers.len() * targets.len() > MAX_PAIRS {
            warn!(
                slot,
                searchers = searchers.len(),
                targets = targets.len(),
                "too many transactions to pair, slot skipped"
            );
            return;
        }

        for target in &targets {
            for searcher in &searchers {
                let (target_transactions, target_entries) = self.position(target);
                let (searcher_transactions, searcher_entries) = self.position(searcher);
                info!(
                    slot,
                    target = %target.signature,
                    searcher = %searcher.signature,
                    // Negative means the bot is in front of the wallet.
                    tx_gap = searcher_transactions - target_transactions,
                    entry_gap = searcher_entries - target_entries,
                    same_entry = searcher.first_shred == target.first_shred
                        && searcher.entry == target.entry,
                    exact = self.tiled(searcher.first_shred, target.first_shred),
                    "race"
                );
            }
        }
    }
}

pub struct Tracker {
    searchers: HashSet<Address>,
    targets: HashSet<Address>,
    slots: HashMap<u64, Slot>,
    last_evicted: Instant,
}

impl Tracker {
    /// `None` when there is no wallet to watch, since then there is nothing to
    /// measure against and the packet path should not pay for it. The bot's
    /// side may be empty: until it exists, every slot the wallet traded in is
    /// still worth a row, and those rows are the baseline the bot will later be
    /// judged against.
    pub fn new(searchers: &[Address], targets: &[Address]) -> Option<Self> {
        if targets.is_empty() {
            return None;
        }
        Some(Self {
            searchers: searchers.iter().copied().collect(),
            targets: targets.iter().copied().collect(),
            slots: HashMap::new(),
            last_evicted: Instant::now(),
        })
    }

    pub fn batch(&mut self, slot: u64, batch: &DecodedBatch) {
        let now = Instant::now();
        self.settle(now);

        let mut hits = Vec::new();
        for (entry, decoded) in batch.entries.iter().enumerate() {
            for (transaction, signed) in decoded.transactions.iter().enumerate() {
                if let Some(role) = self.role(signed) {
                    hits.push(Hit {
                        role,
                        first_shred: batch.first_shred,
                        entry,
                        transaction,
                        signature: signature(signed),
                    });
                }
            }
        }
        let span = Span {
            last_shred: batch.last_shred,
            entries: batch
                .entries
                .iter()
                .map(|entry| entry.transactions.len() as u32)
                .collect(),
        };

        let held = self.slots.entry(slot).or_insert_with(|| Slot::new(now));
        held.updated = now;
        held.batches.insert(batch.first_shred, span);
        held.hits.append(&mut hits);
    }

    /// A transaction belongs to whoever is paying for it. A bot signs and pays
    /// with its own key, so the fee payer is the identity that matters; a key
    /// merely mentioned further down the account list is not the sender.
    fn role(&self, transaction: &VersionedTransaction) -> Option<Role> {
        let payer = transaction.message.static_account_keys().first()?;
        if self.searchers.contains(payer) {
            Some(Role::Searcher)
        } else if self.targets.contains(payer) {
            Some(Role::Target)
        } else {
            None
        }
    }

    fn settle(&mut self, now: Instant) {
        if now.duration_since(self.last_evicted) < EVICT_INTERVAL && self.slots.len() <= MAX_SLOTS {
            return;
        }
        self.last_evicted = now;

        self.slots.retain(|slot, held| {
            let waiting = now.duration_since(held.updated) < SETTLE;
            if !waiting {
                held.report(*slot);
            }
            waiting
        });

        // Nothing legitimate reaches the cap, so when it is hit the slots to
        // give up are the ones that have gone quiet.
        if self.slots.len() > MAX_SLOTS {
            let mut updated: Vec<Instant> = self.slots.values().map(|held| held.updated).collect();
            updated.sort_unstable();
            let cutoff = updated[updated.len() - MAX_SLOTS];
            self.slots.retain(|_, held| held.updated >= cutoff);
        }
    }
}

fn signature(transaction: &VersionedTransaction) -> String {
    transaction
        .signatures
        .first()
        .map(ToString::to_string)
        .unwrap_or_else(|| "<no signature>".to_string())
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        solana_keypair::Keypair,
        solana_signer::Signer,
        solana_transaction::{CompiledInstruction, Message, VersionedMessage},
    };

    fn slot_with(batches: &[(u32, u32, &[u32])]) -> Slot {
        let mut slot = Slot::new(Instant::now());
        for (first_shred, last_shred, entries) in batches {
            slot.batches.insert(
                *first_shred,
                Span {
                    last_shred: *last_shred,
                    entries: entries.to_vec(),
                },
            );
        }
        slot
    }

    fn hit(role: Role, first_shred: u32, entry: usize, transaction: usize) -> Hit {
        Hit {
            role,
            first_shred,
            entry,
            transaction,
            signature: String::new(),
        }
    }

    /// The gap has to count every transaction the leader put between the two,
    /// including the ones in batches neither of them is in.
    #[test]
    fn counts_the_transactions_between_two_batches() {
        // Batch at shreds 0..=2 holds entries of 2 and 1 transactions; the one
        // at 3..=5 holds a single entry of 4.
        let slot = slot_with(&[(0, 2, &[2, 1]), (3, 5, &[4])]);

        let target = hit(Role::Target, 0, 1, 0);
        let searcher = hit(Role::Searcher, 3, 0, 2);

        let (target_transactions, target_entries) = slot.position(&target);
        let (searcher_transactions, searcher_entries) = slot.position(&searcher);

        assert_eq!(
            (target_transactions, target_entries),
            (2, 1),
            "two transactions and one entry precede it inside its own batch"
        );
        assert_eq!(
            (searcher_transactions, searcher_entries),
            (5, 2),
            "the whole first batch precedes it, then two of its own entry"
        );
        assert_eq!(searcher_transactions - target_transactions, 3);
        assert_eq!(searcher_entries - target_entries, 1);
    }

    /// A batch that never decoded sits between the two, so the count is short
    /// by whatever it held and must not claim to be exact.
    #[test]
    fn a_hole_between_the_batches_is_not_exact() {
        let whole = slot_with(&[(0, 2, &[1]), (3, 5, &[1])]);
        assert!(whole.tiled(0, 3));

        let holed = slot_with(&[(0, 2, &[1]), (6, 8, &[1])]);
        assert!(
            !holed.tiled(0, 6),
            "the batch covering shreds 3..=5 is missing"
        );
    }

    /// Order within an entry is not order of execution, so the two have to be
    /// distinguishable from a pair that merely sits close together.
    #[test]
    fn transactions_of_one_entry_share_a_position() {
        let slot = slot_with(&[(0, 2, &[4])]);
        let first = hit(Role::Target, 0, 0, 0);
        let second = hit(Role::Searcher, 0, 0, 3);

        assert_eq!(slot.position(&first).1, slot.position(&second).1);
        assert_eq!(
            slot.position(&second).0 - slot.position(&first).0,
            3,
            "the transaction gap is still real, it just does not order them"
        );
    }

    /// A key further down the account list is not the sender, and counting it
    /// as one would pair the bot against transactions it never sent.
    #[test]
    fn only_the_fee_payer_decides_whose_transaction_it_is() {
        let bot = Keypair::new();
        let bystander = Keypair::new();
        let tracker = Tracker::new(&[bot.pubkey()], &[Keypair::new().pubkey()])
            .expect("both sides are configured");

        let transaction = |payer: &Keypair, mentioned: &Keypair| VersionedTransaction {
            signatures: vec![Default::default()],
            message: VersionedMessage::Legacy(Message {
                account_keys: vec![payer.pubkey(), mentioned.pubkey()],
                instructions: vec![CompiledInstruction {
                    program_id_index: 1,
                    accounts: vec![0],
                    data: Vec::new(),
                }],
                ..Default::default()
            }),
        };

        assert!(
            matches!(
                tracker.role(&transaction(&bot, &bystander)),
                Some(Role::Searcher)
            ),
            "the bot is paying"
        );
        assert!(
            tracker.role(&transaction(&bystander, &bot)).is_none(),
            "the bot is only mentioned"
        );
    }

    /// The bot does not exist yet, so watching a wallet on its own has to be a
    /// working configuration rather than a half-finished one.
    #[test]
    fn a_watched_wallet_alone_is_enough() {
        let wallet = Keypair::new().pubkey();
        assert!(Tracker::new(&[], &[wallet]).is_some());
        assert!(Tracker::new(&[wallet], &[wallet]).is_some());
        assert!(
            Tracker::new(&[wallet], &[]).is_none(),
            "a bot with nothing to race is nothing to measure"
        );
    }
}
