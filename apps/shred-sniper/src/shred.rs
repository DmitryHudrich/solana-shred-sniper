//! Минимальный разбор шредов Agave 4.x.
//!
//! Нас интересуют только data-шреды: именно в них лежат куски сериализованного
//! батча энтри (а в энтри — транзакции). Coding-шреды (Reed-Solomon) для MVP
//! просто игнорируем: пока пакеты не теряются, данных хватает и без них.
//!
//! Раскладка байтов (agave `ledger/src/shred.rs`, `ShredCommonHeader` +
//! `DataShredHeader`):
//!
//! ```text
//! [  0.. 64)  signature лидера
//! [ 64.. 65)  shred_variant
//! [ 65.. 73)  slot           (u64 LE)
//! [ 73.. 77)  index          (u32 LE)  — номер шреда внутри слота
//! [ 77.. 79)  version        (u16 LE)  — shred_version кластера
//! [ 79.. 83)  fec_set_index  (u32 LE)
//! --- дальше только у data-шреда ---
//! [ 83.. 85)  parent_offset  (u16 LE)
//! [ 85.. 86)  flags          (u8)
//! [ 86.. 88)  size           (u16 LE)  — размер «заголовки + данные»
//! [ 88..size) payload        — кусок батча энтри
//! ```
//!
//! Хвост после `size` — нули, merkle-proof и (для resigned-варианта) подпись
//! ретранслятора; данных там нет.

/// Смещение, с которого в data-шреде начинается полезная нагрузка.
const DATA_OFFSET: usize = 88;

/// Шред — последний в своём батче энтри, батч можно десериализовать.
const FLAG_DATA_COMPLETE: u8 = 0b0100_0000;

#[derive(Debug)]
pub struct DataShred<'a> {
    pub slot: u64,
    pub index: u32,
    pub data_complete: bool,
    pub data: &'a [u8],
}

/// Разбирает UDP-пакет из turbine. `None` — это не data-шред либо он битый.
pub fn parse_data_shred(packet: &[u8]) -> Option<DataShred<'_>> {
    if packet.len() < DATA_OFFSET {
        return None;
    }

    // В 4.x остались только merkle-варианты. Старший ниббл shred_variant:
    // 0x6/0x7 — coding, 0x9/0xb — data (младший ниббл = размер merkle-proof).
    match packet[64] & 0xf0 {
        0x90 | 0xb0 => {}
        _ => return None,
    }

    let slot = u64::from_le_bytes(packet[65..73].try_into().ok()?);
    let index = u32::from_le_bytes(packet[73..77].try_into().ok()?);
    let flags = packet[85];
    let size = u16::from_le_bytes(packet[86..88].try_into().ok()?) as usize;

    // size меньше заголовков или больше пакета — шред битый.
    if !(DATA_OFFSET..=packet.len()).contains(&size) {
        return None;
    }

    Some(DataShred {
        slot,
        index,
        data_complete: flags & FLAG_DATA_COMPLETE != 0,
        data: &packet[DATA_OFFSET..size],
    })
}
