const DATA_OFFSET: usize = 88;

const FLAG_DATA_COMPLETE: u8 = 0b0100_0000;

#[derive(Debug)]
pub struct DataShred<'a> {
    pub slot: u64,
    pub index: u32,
    pub data_complete: bool,
    pub data: &'a [u8],
}

pub fn parse_data_shred(packet: &[u8]) -> Option<DataShred<'_>> {
    if packet.len() < DATA_OFFSET {
        return None;
    }

    match packet[64] & 0xf0 {
        0x90 | 0xb0 => {}
        _ => return None,
    }

    let slot = u64::from_le_bytes(packet[65..73].try_into().ok()?);
    let index = u32::from_le_bytes(packet[73..77].try_into().ok()?);
    let flags = packet[85];
    let size = u16::from_le_bytes(packet[86..88].try_into().ok()?) as usize;

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
