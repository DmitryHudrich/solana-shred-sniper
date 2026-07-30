//! Merkle shred wire format, as far as the sniper needs it.
//!
//! All offsets here are relative to the shred *body*: the payload with its
//! leading 64-byte signature stripped. Erasure recovery reconstructs bodies
//! rather than payloads, so live and recovered shreds share one parser.

const SIGNATURE: usize = 64;

// Common header, present in both shred types.
const SLOT: usize = 1;
const INDEX: usize = 9;
const VERSION: usize = 13;
const FEC_SET_INDEX: usize = 15;

// Data header.
const DATA_FLAGS: usize = 21;
const DATA_SIZE: usize = 22;
const DATA_HEADERS: usize = 88 - SIGNATURE;

// Coding header.
const CODE_NUM_DATA: usize = 19;
const CODE_NUM_CODING: usize = 21;
const CODE_POSITION: usize = 23;
const CODE_HEADERS: usize = 89 - SIGNATURE;

// A coding shred fills a whole packet, and everything past the erasure coded
// region is the Merkle root, the proof and, when resigned, the retransmitter
// signature. The shard is therefore longest for an unresigned shred with an
// empty proof.
const CODE_PAYLOAD: usize = 1228;
const MERKLE_ROOT: usize = 32;
const PROOF_ENTRY: usize = 20;
const MAX_SHARD: usize = CODE_PAYLOAD - (SIGNATURE + CODE_HEADERS) - MERKLE_ROOT;

const FLAG_DATA_COMPLETE: u8 = 0b0100_0000;

// Shreds carry no signature we can check, so every field is attacker
// controlled. A leader never puts more than this many data shreds in a slot
// (agave's MAX_DATA_SHREDS_PER_SLOT), and everything downstream sizes its
// bookkeeping by the index, so a bogus one has to be rejected here.
const MAX_SHREDS_PER_SLOT: u32 = 32_768;

#[derive(Debug)]
pub struct DataShred<'a> {
    pub slot: u64,
    pub index: u32,
    pub fec_set_index: u32,
    pub data_complete: bool,
    /// Entry bytes carried by this shred.
    pub data: &'a [u8],
    /// The slice erasure coding is computed over, needed to recover siblings.
    /// For a recovered shred this is the whole body.
    pub shard: &'a [u8],
}

#[derive(Debug)]
pub struct CodingShred<'a> {
    pub slot: u64,
    pub fec_set_index: u32,
    pub num_data: usize,
    pub num_coding: usize,
    pub position: usize,
    pub shard: &'a [u8],
}

pub enum Shred<'a> {
    Data(DataShred<'a>),
    Coding(CodingShred<'a>),
}

pub fn parse(packet: &[u8], shred_version: u16) -> Option<Shred<'_>> {
    let body = packet.get(SIGNATURE..)?;
    match body.first()? & 0xf0 {
        0x90 | 0xb0 => parse_data(body, shred_version).map(Shred::Data),
        0x60 | 0x70 => parse_coding(body, shred_version).map(Shred::Coding),
        _ => None,
    }
}

/// Shreds of another cluster, or of another fork of ours, carry a different
/// version. Dropping them costs nothing and keeps foreign traffic out of the
/// buffers. Nothing signs the field, so this is hygiene, not authentication:
/// it filters misdirected traffic, not an adversary who knows we are here.
fn version_matches(body: &[u8], shred_version: u16) -> bool {
    read_u16(body, VERSION) == Some(usize::from(shred_version))
}

/// Parses a data shred body. Recovered shreds are bodies truncated to their
/// erasure shard, which is why nothing past `shard` is required.
pub fn parse_data(body: &[u8], shred_version: u16) -> Option<DataShred<'_>> {
    if !version_matches(body, shred_version) {
        return None;
    }
    let shard_len = shard_len(*body.first()?)?;
    let shard = body.get(..shard_len)?;

    // DataShredHeader.size is an offset into the payload, not the body.
    let size = read_u16(body, DATA_SIZE)?
        .checked_sub(SIGNATURE)
        .filter(|size| (DATA_HEADERS..=shard_len).contains(size))?;

    // A shred belongs to the erasure batch it opens or a later one, never an
    // earlier one, and recovery indexes shards by the difference.
    let index = read_u32(body, INDEX).filter(|index| *index < MAX_SHREDS_PER_SLOT)?;
    let fec_set_index = read_u32(body, FEC_SET_INDEX).filter(|first| *first <= index)?;

    Some(DataShred {
        slot: read_u64(body, SLOT)?,
        index,
        fec_set_index,
        data_complete: body.get(DATA_FLAGS)? & FLAG_DATA_COMPLETE != 0,
        data: shard.get(DATA_HEADERS..size)?,
        shard,
    })
}

fn parse_coding(body: &[u8], shred_version: u16) -> Option<CodingShred<'_>> {
    if !version_matches(body, shred_version) {
        return None;
    }
    let shard_len = shard_len(*body.first()?)?;
    let shard = body.get(CODE_HEADERS..CODE_HEADERS + shard_len)?;

    Some(CodingShred {
        slot: read_u64(body, SLOT)?,
        fec_set_index: read_u32(body, FEC_SET_INDEX)
            .filter(|first| *first < MAX_SHREDS_PER_SLOT)?,
        num_data: read_u16(body, CODE_NUM_DATA)?,
        num_coding: read_u16(body, CODE_NUM_CODING)?,
        position: read_u16(body, CODE_POSITION)?,
        shard,
    })
}

/// Size of the erasure coded slice, which is the same for data and coding
/// shreds of one batch. The low nibble of the variant is the Merkle proof
/// length; resigned shreds also carry a retransmitter signature at the end.
fn shard_len(variant: u8) -> Option<usize> {
    let proof = usize::from(variant & 0x0f) * PROOF_ENTRY;
    let resigned = matches!(variant & 0xf0, 0x70 | 0xb0);
    MAX_SHARD
        .checked_sub(proof + if resigned { SIGNATURE } else { 0 })
        .filter(|shard_len| *shard_len > DATA_HEADERS)
}

fn read_u16(body: &[u8], offset: usize) -> Option<usize> {
    let bytes = body.get(offset..offset + 2)?.try_into().ok()?;
    Some(usize::from(u16::from_le_bytes(bytes)))
}

fn read_u32(body: &[u8], offset: usize) -> Option<u32> {
    let bytes = body.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_u64(body: &[u8], offset: usize) -> Option<u64> {
    let bytes = body.get(offset..offset + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        solana_hash::Hash,
        solana_keypair::Keypair,
        solana_ledger::shred::{
            ProcessShredsStats, ReedSolomonCache, Shred as AgaveShred, Shredder,
        },
    };

    /// Whatever a cluster would hash out; the point is that it is not zero.
    const SHRED_VERSION: u16 = 4242;

    /// One data shred, straight from the shredder a leader would use.
    fn data_shred() -> Vec<u8> {
        let payload: Vec<u8> = (0..4096u32).map(|byte| byte as u8).collect();
        Shredder::new(42, 41, 0, SHRED_VERSION)
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
            .into_iter()
            .find(AgaveShred::is_data)
            .unwrap()
            .payload()
            .to_vec()
    }

    /// Nothing checks the signature, so a forged field parses on its merits.
    fn forge(payload: &[u8], offset: usize, value: u32) -> Vec<u8> {
        let mut forged = payload.to_vec();
        let at = SIGNATURE + offset;
        forged[at..at + 4].copy_from_slice(&value.to_le_bytes());
        forged
    }

    /// Everything downstream sizes its bookkeeping by the shred index, so an
    /// index no leader could have produced has to be rejected right here.
    #[test]
    fn rejects_an_impossible_shred_index() {
        let payload = data_shred();
        assert!(
            parse(&payload, SHRED_VERSION).is_some(),
            "the untouched shred should parse"
        );

        for index in [MAX_SHREDS_PER_SLOT, u32::MAX] {
            let forged = forge(&payload, INDEX, index);
            assert!(
                parse(&forged, SHRED_VERSION).is_none(),
                "index {index} was accepted"
            );
        }
    }

    /// A shred belongs to the erasure batch it opens or a later one, never to
    /// one that starts after it.
    #[test]
    fn rejects_a_batch_starting_past_the_shred() {
        let payload = data_shred();
        let Some(Shred::Data(shred)) = parse(&payload, SHRED_VERSION) else {
            panic!("data shred did not parse");
        };
        let index = shred.index;

        for first in [index + 1, u32::MAX] {
            let forged = forge(&payload, FEC_SET_INDEX, first);
            assert!(
                parse(&forged, SHRED_VERSION).is_none(),
                "batch index {first} was accepted"
            );
        }
    }

    /// Shreds of another cluster carry another version, and we hold buffers
    /// for everything we accept, so they have no business getting in.
    #[test]
    fn rejects_a_foreign_shred_version() {
        let payload = data_shred();
        for version in [0, SHRED_VERSION - 1, SHRED_VERSION + 1, u16::MAX] {
            assert!(
                parse(&payload, version).is_none(),
                "version {version} was taken for {SHRED_VERSION}"
            );
        }
    }

    /// The version sits in the common header, so it guards coding shreds too.
    #[test]
    fn rejects_a_foreign_version_on_coding_shreds() {
        let payload: Vec<u8> = (0..40 * 1024u32).map(|byte| byte as u8).collect();
        let coding = Shredder::new(42, 41, 0, SHRED_VERSION)
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
            .into_iter()
            .find(|shred| !shred.is_data())
            .expect("a payload this size produces coding shreds")
            .payload()
            .to_vec();

        assert!(
            matches!(parse(&coding, SHRED_VERSION), Some(Shred::Coding(_))),
            "the untouched coding shred should parse"
        );
        assert!(parse(&coding, SHRED_VERSION + 1).is_none());
    }
}
