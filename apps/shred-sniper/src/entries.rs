//! Сборка батчей энтри из data-шредов и их десериализация.
//!
//! Лидер режет слот на батчи энтри; каждый батч сериализуется и раскладывается
//! по подряд идущим data-шредам. У последнего шреда батча взведён флаг
//! DATA_COMPLETE. То есть чтобы получить транзакции, надо склеить payload'ы
//! шредов `[start..=complete]` и разобрать результат.
//!
//! Формат склеенного батча (agave `entry/src/block_component.rs`):
//!
//! ```text
//! [0..8)  количество энтри (u64 LE)
//! [8..)   энтри в bincode-формате
//! ```
//!
//! Если количество равно нулю — это не батч, а служебный block marker
//! (Alpenglow), транзакций в нём нет.

use {
    serde::Deserialize,
    solana_hash::Hash,
    solana_transaction::versioned::VersionedTransaction,
    std::collections::{BTreeMap, HashMap, HashSet},
};

#[derive(Debug, Deserialize)]
pub struct Entry {
    /// Сколько раз прогнали PoH-хеш с прошлой энтри.
    /// Нам не нужно, но без него не сойдётся раскладка байтов.
    #[allow(dead_code)]
    pub num_hashes: u64,
    /// Сам PoH-хеш. Тоже нужен только для корректного разбора.
    #[allow(dead_code)]
    pub hash: Hash,
    /// Транзакции, попавшие в эту энтри, — ради них всё и затевалось.
    pub transactions: Vec<VersionedTransaction>,
}

/// Накопитель шредов одного слота.
#[derive(Default)]
struct SlotBuffer {
    /// index шреда -> (payload, взведён ли DATA_COMPLETE)
    shreds: BTreeMap<u32, (Vec<u8>, bool)>,
    /// Индексы первых шредов уже отданных батчей — чтобы не отдать дважды.
    emitted: HashSet<u32>,
}

impl SlotBuffer {
    /// Отдаёт батчи, которые целиком собрались и ещё не отдавались.
    ///
    /// Батч начинается либо с нулевого шреда слота, либо сразу после шреда с
    /// DATA_COMPLETE. Поэтому потерянный шред ломает только свой батч, а не
    /// весь остаток слота.
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

            // Идём по подряд идущим шредам, пока не упрёмся в дырку или в конец батча.
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

    /// Индексы шредов, которых не хватает до сплошного ряда, — для диагностики.
    fn missing(&self) -> Vec<u32> {
        let Some(last) = self.shreds.keys().next_back().copied() else {
            return Vec::new();
        };
        (0..=last)
            .filter(|index| !self.shreds.contains_key(index))
            .collect()
    }
}

/// Копит шреды по слотам и выдаёт готовые батчи энтри.
#[derive(Default)]
pub struct Assembler {
    slots: HashMap<u64, SlotBuffer>,
    max_slot: u64,
}

/// Сколько слотов держим в памяти позади текущего, прежде чем выкинуть.
const SLOT_RETENTION: u64 = 64;

impl Assembler {
    /// Кладёт шред и возвращает энтри из батчей, которые он достроил.
    pub fn insert(&mut self, shred: &crate::shred::DataShred<'_>) -> Vec<Entry> {
        self.max_slot = self.max_slot.max(shred.slot);
        let max_slot = self.max_slot;
        self.slots.retain(|slot, buffer| {
            let keep = slot + SLOT_RETENTION >= max_slot;
            if !keep {
                let missing = buffer.missing();
                if !missing.is_empty() {
                    log::debug!(
                        "слот {slot}: потеряно {} шредов: {missing:?}",
                        missing.len()
                    );
                }
            }
            keep
        });

        let buffer = self.slots.entry(shred.slot).or_default();
        // Шред мог прийти повторно (ретрансляция) — тогда просто перезапишем.
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

/// Разбирает склеенный батч. `None` — если это block marker или мусор.
fn decode_batch(batch: &[u8]) -> Option<Vec<Entry>> {
    if batch.len() < 8 {
        return None;
    }
    // Нулевое количество энтри — служебный block marker, разбирать нечего.
    if u64::from_le_bytes(batch[..8].try_into().ok()?) == 0 {
        return None;
    }
    match bincode::deserialize::<Vec<Entry>>(batch) {
        Ok(entries) => Some(entries),
        Err(err) => {
            log::debug!(
                "не смогли разобрать батч энтри ({} байт): {err}",
                batch.len()
            );
            None
        }
    }
}
