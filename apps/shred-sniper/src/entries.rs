use {
    serde::Deserialize,
    solana_hash::Hash,
    solana_transaction::versioned::VersionedTransaction,
    std::collections::{BTreeMap, HashMap, HashSet},
    tracing::debug,
};

#[derive(Debug, Deserialize)]
pub struct Entry {
    #[allow(dead_code)]
    pub num_hashes: u64,
    #[allow(dead_code)]
    pub hash: Hash,
    pub transactions: Vec<VersionedTransaction>,
}

#[derive(Default)]
struct SlotBuffer {
    shreds: BTreeMap<u32, (Vec<u8>, bool)>,
    emitted: HashSet<u32>,
}

impl SlotBuffer {
    fn take_complete_batches(&mut self) -> Vec<Vec<u8>> {
        let starts: Vec<u32> = std::iter::once(0)
            .chain(
                self.shreds
                    .iter()
                    .filter(|(_, (_, data_complete))| *data_complete)
                    .map(|(index, _)| index + 1),
            )
            .filter(|start| !self.emitted.contains(start))
            .collect();

        let mut batches = Vec::new();
        for start in starts {
            let mut payload = Vec::new();
            let mut index = start;
            let mut complete = false;

            while let Some((data, data_complete)) = self.shreds.get(&index) {
                payload.extend_from_slice(data);
                index += 1;
                if *data_complete {
                    complete = true;
                    break;
                }
            }

            if complete {
                self.emitted.insert(start);
                batches.push(payload);
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
    max_slot: u64,
    slot_retention: u64,
}

impl Assembler {
    pub fn new(slot_retention: u64) -> Self {
        Self {
            slots: HashMap::new(),
            max_slot: 0,
            slot_retention,
        }
    }

    pub fn insert(&mut self, shred: &crate::shred::DataShred<'_>) -> Vec<Entry> {
        self.max_slot = self.max_slot.max(shred.slot);
        let max_slot = self.max_slot;
        let slot_retention = self.slot_retention;
        self.slots.retain(|slot, buffer| {
            let keep = slot + slot_retention >= max_slot;
            if !keep {
                let missing = buffer.missing();
                if !missing.is_empty() {
                    debug!(slot, lost = missing.len(), ?missing, "missing shreds");
                }
            }
            keep
        });

        let buffer = self.slots.entry(shred.slot).or_default();
        buffer
            .shreds
            .insert(shred.index, (shred.data.to_vec(), shred.data_complete));

        buffer
            .take_complete_batches()
            .iter()
            .filter_map(|batch| decode_batch(batch))
            .flatten()
            .collect()
    }
}

fn decode_batch(batch: &[u8]) -> Option<Vec<Entry>> {
    if batch.len() < 8 {
        return None;
    }
    if u64::from_le_bytes(batch[..8].try_into().ok()?) == 0 {
        return None;
    }
    match bincode::deserialize::<Vec<Entry>>(batch) {
        Ok(entries) => Some(entries),
        Err(err) => {
            debug!(bytes = batch.len(), %err, "failed to decode entry batch");
            None
        }
    }
}
