//! Merkle shred wire format, as far as the sniper needs it.
//!
//! All offsets here are relative to the shred *body*: the payload with its
//! leading 64-byte signature stripped. Erasure recovery reconstructs bodies
//! rather than payloads, so live and recovered shreds share one parser. The one
//! exception is [`signed`], which has to count from the packet, and says so.

use {solana_hash::Hash, solana_sha256_hasher::hashv};

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
/// A data shred's packet. Both types are cut so that their erasure coded
/// regions match, which leaves the data payload shorter than the coding one by
/// exactly the coding headers that are not covered.
const DATA_PAYLOAD: usize = CODE_PAYLOAD - CODE_HEADERS;
const MERKLE_ROOT: usize = 32;
const PROOF_ENTRY: usize = 20;
const MAX_SHARD: usize = CODE_PAYLOAD - (SIGNATURE + CODE_HEADERS) - MERKLE_ROOT;

/// Domain separators agave hashes the Merkle tree with. A leaf and a node of
/// the same bytes must not hash alike, or a proof could be replayed at the
/// wrong height.
const MERKLE_LEAF_PREFIX: &[u8] = b"\x00SOLANA_MERKLE_SHREDS_LEAF";
const MERKLE_NODE_PREFIX: &[u8] = b"\x01SOLANA_MERKLE_SHREDS_NODE";

const FLAG_DATA_COMPLETE: u8 = 0b0100_0000;

/// agave's `LAST_SHRED_IN_SLOT` sets the data-complete bit too, so the whole
/// mask has to match: plenty of shreds close an entry batch without closing the
/// slot. Knowing which shred ends a slot is what turns its index into the
/// number of shreds the slot was supposed to have.
const FLAG_LAST_IN_SLOT: u8 = 0b1100_0000;

/// The low six bits hold the tick the leader was on when it produced the shred,
/// saturating at 63. It is the only reference to the leader's own clock that
/// reaches us on the wire, so it is what makes delivery timing measurable
/// without a second source of truth.
const TICK_REFERENCE_MASK: u8 = 0b0011_1111;

// Parsing happens before anything is verified, so at this point every field is
// still only what the packet claims. A leader never puts more than this many
// data shreds in a slot (agave's MAX_DATA_SHREDS_PER_SLOT), and everything
// downstream sizes its bookkeeping by the index, so a bogus one has to be
// rejected here rather than left to [`signed`] — which cannot run at all on a
// shred whose own fields do not fit the packet.
const MAX_SHREDS_PER_SLOT: u32 = 32_768;

#[derive(Debug)]
pub struct DataShred<'a> {
    pub slot: u64,
    pub index: u32,
    pub fec_set_index: u32,
    pub data_complete: bool,
    /// Set on the shred that closes the slot, whose index therefore gives the
    /// slot's total data shred count.
    pub last_in_slot: bool,
    /// Tick within the slot at which the leader produced this shred.
    pub reference_tick: u8,
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
    const DATA: u8 = 0x90;
    const DATA_RESIGNED: u8 = 0xb0;
    const CODING: u8 = 0x60;
    const CODING_RESIGNED: u8 = 0x70;
    const MERKLE_PROOF_LEN: u8 = 0xf0;

    let body = packet.get(SIGNATURE..)?;
    match body.first()? & MERKLE_PROOF_LEN {
        DATA | DATA_RESIGNED => parse_data(body, shred_version).map(Shred::Data),
        CODING | CODING_RESIGNED => parse_coding(body, shred_version).map(Shred::Coding),
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

    let flags = *body.get(DATA_FLAGS)?;

    Some(DataShred {
        slot: read_u64(body, SLOT)?,
        index,
        fec_set_index,
        data_complete: flags & FLAG_DATA_COMPLETE != 0,
        last_in_slot: flags & FLAG_LAST_IN_SLOT == FLAG_LAST_IN_SLOT,
        reference_tick: flags & TICK_REFERENCE_MASK,
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

/// What a shred says about who produced it: the leader's signature, and the
/// Merkle root it was made over.
///
/// The signature covers the root of the erasure batch's Merkle tree, not the
/// shred, so every shred of a batch carries the same one — checking a batch
/// costs one verification rather than thirty-two. The root is not on the wire
/// either; it is rebuilt from the shred's own bytes and the proof it carries,
/// which is what makes a forged shred fail: to pass, it would have to hash to a
/// root the leader had already signed.
pub struct Signed<'a> {
    pub signature: &'a [u8],
    pub root: Hash,
}

/// Offsets from the start of the *packet*, unlike the rest of this module: the
/// Merkle leaf is hashed over the payload from the signature to the proof, so
/// both ends have to be counted from the same place.
fn proof_offset(variant: u8) -> Option<usize> {
    let proof = usize::from(variant & 0x0f) * PROOF_ENTRY;
    let resigned = matches!(variant & 0xf0, 0x70 | 0xb0);
    let payload = match variant & 0xf0 {
        0x90 | 0xb0 => DATA_PAYLOAD,
        0x60 | 0x70 => CODE_PAYLOAD,
        _ => return None,
    };
    payload.checked_sub(proof + if resigned { SIGNATURE } else { 0 })
}

/// Rebuilds the Merkle root the leader signed, from the shred and its proof.
///
/// Nothing here trusts the shred: every offset is bounds checked and a proof
/// that does not fit the packet gives no root at all. A shred that has been
/// tampered with yields *a* root, just not the signed one — which is the point,
/// and why the verification this feeds cannot be fooled by rewriting fields.
pub fn signed(packet: &[u8], shred_version: u16) -> Option<Signed<'_>> {
    let body = packet.get(SIGNATURE..)?;
    if !version_matches(body, shred_version) {
        return None;
    }
    let variant = *body.first()?;
    let proof_offset = proof_offset(variant)?;
    let proof =
        packet.get(proof_offset..proof_offset + usize::from(variant & 0x0f) * PROOF_ENTRY)?;

    // Which leaf of the batch's tree this shred is. Data shreds come first, in
    // index order; coding shreds follow, in position order.
    let fec_set_index = read_u32(body, FEC_SET_INDEX)?;
    let mut index = match variant & 0xf0 {
        0x90 | 0xb0 => read_u32(body, INDEX)?
            .checked_sub(fec_set_index)
            .map(|leaf| leaf as usize)?,
        _ => read_u16(body, CODE_NUM_DATA)?.checked_add(read_u16(body, CODE_POSITION)?)?,
    };

    let mut node = hashv(&[MERKLE_LEAF_PREFIX, packet.get(SIGNATURE..proof_offset)?]);
    for sibling in proof.chunks_exact(PROOF_ENTRY) {
        let (left, right) = if index % 2 == 0 {
            (&node.as_ref()[..PROOF_ENTRY], sibling)
        } else {
            (sibling, &node.as_ref()[..PROOF_ENTRY])
        };
        node = hashv(&[MERKLE_NODE_PREFIX, left, right]);
        index >>= 1;
    }

    Some(Signed {
        signature: packet.get(..SIGNATURE)?,
        root: node,
    })
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
        solana_signer::Signer,
    };

    /// Whatever a cluster would hash out; the point is that it is not zero.
    const SHRED_VERSION: u16 = 4242;

    /// Every shred of a slot, data and coding, as the leader emits them, with
    /// the keypair that signed them.
    fn signed_slot(resigned: bool) -> (Keypair, Vec<Vec<u8>>) {
        let leader = Keypair::new();
        let payload: Vec<u8> = (0..40 * 1024u32).map(|byte| byte as u8).collect();
        let shreds = Shredder::new(42, 41, 0, SHRED_VERSION)
            .unwrap()
            .make_shreds_from_data_slice(
                &leader,
                &payload,
                resigned,
                Hash::default(),
                0,
                0,
                &ReedSolomonCache::default(),
                &mut ProcessShredsStats::default(),
            )
            .unwrap()
            .map(|shred| shred.payload().to_vec())
            .collect();
        (leader, shreds)
    }

    /// The root is rebuilt from the shred's own bytes rather than read off the
    /// wire, so the only thing that says the reconstruction is right is agave
    /// arriving at the same hash from the same packet.
    #[test]
    fn rebuilds_the_merkle_root_agave_signed() {
        for resigned in [false, true] {
            let (_, shreds) = signed_slot(resigned);
            let mut data = 0;
            let mut coding = 0;
            for payload in &shreds {
                let ours = signed(payload, SHRED_VERSION).expect("a shred should be signed");
                let theirs = solana_ledger::shred::layout::get_merkle_root(payload)
                    .expect("agave should find a root");
                assert_eq!(ours.root, theirs, "the rebuilt root differs from agave's");
                match AgaveShred::new_from_serialized_shred(payload.clone())
                    .unwrap()
                    .is_data()
                {
                    true => data += 1,
                    false => coding += 1,
                }
            }
            assert!(
                data > 0 && coding > 0,
                "both shred types have to be covered"
            );
        }
    }

    /// The whole point of the root: it is what the leader signed, so a shred
    /// from anyone else fails against the leader the slot was scheduled to.
    #[test]
    fn the_leader_signature_verifies_against_the_root() {
        let (leader, shreds) = signed_slot(false);
        let payload = &shreds[0];
        let signed = signed(payload, SHRED_VERSION).unwrap();
        let signature = solana_signature::Signature::try_from(signed.signature).unwrap();
        assert!(
            signature.verify(leader.pubkey().as_ref(), signed.root.as_ref()),
            "the leader's own shred did not verify"
        );
        assert!(
            !signature.verify(Keypair::new().pubkey().as_ref(), signed.root.as_ref()),
            "a shred verified against someone who never signed it"
        );
    }

    /// A rewritten field changes the leaf it is hashed into, so the root moves
    /// and the signature the shred still carries no longer fits it. This is the
    /// property the whole check rests on.
    #[test]
    fn a_tampered_shred_no_longer_matches_its_signature() {
        let (leader, shreds) = signed_slot(false);
        let payload = &shreds[0];
        let honest = signed(payload, SHRED_VERSION).unwrap().root;

        // The flag byte, which is what a forged batch boundary would need.
        let mut tampered = payload.clone();
        tampered[SIGNATURE + DATA_FLAGS] ^= FLAG_DATA_COMPLETE;
        let forged = signed(&tampered, SHRED_VERSION).unwrap();
        assert_ne!(forged.root, honest, "flipping a flag left the root alone");

        let signature = solana_signature::Signature::try_from(forged.signature).unwrap();
        assert!(
            !signature.verify(leader.pubkey().as_ref(), forged.root.as_ref()),
            "a tampered shred still verified as the leader's"
        );
    }

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

    /// Every data shred of one slot, in index order, as the leader emits them.
    fn slot_shreds(reference_tick: u8, last_in_slot: bool) -> Vec<Vec<u8>> {
        let payload: Vec<u8> = (0..40 * 1024u32).map(|byte| byte as u8).collect();
        let mut shreds: Vec<AgaveShred> = Shredder::new(42, 41, reference_tick, SHRED_VERSION)
            .unwrap()
            .make_shreds_from_data_slice(
                &Keypair::new(),
                &payload,
                last_in_slot,
                Hash::default(),
                0,
                0,
                &ReedSolomonCache::default(),
                &mut ProcessShredsStats::default(),
            )
            .unwrap()
            .filter(AgaveShred::is_data)
            .collect();
        shreds.sort_by_key(AgaveShred::index);
        shreds
            .into_iter()
            .map(|shred| shred.payload().to_vec())
            .collect()
    }

    /// The slot's shred count is only knowable from the shred that closes it,
    /// and that flag shares a byte with the batch-complete one, so reading it
    /// as a whole mask rather than a single bit is the difference between
    /// knowing the slot's size and mistaking every batch boundary for its end.
    #[test]
    fn finds_the_shred_that_closes_the_slot() {
        let payloads = slot_shreds(0, true);
        assert!(payloads.len() > 1, "one shred would not prove the point");

        let flagged: Vec<u32> = payloads
            .iter()
            .filter_map(|payload| match parse(payload, SHRED_VERSION) {
                Some(Shred::Data(shred)) if shred.last_in_slot => Some(shred.index),
                _ => None,
            })
            .collect();

        let last = payloads.len() as u32 - 1;
        assert_eq!(
            flagged,
            vec![last],
            "only the closing shred carries the flag"
        );

        // A slot the leader has not finished must leave us without a count.
        assert!(
            slot_shreds(0, false)
                .iter()
                .filter_map(|payload| match parse(payload, SHRED_VERSION) {
                    Some(Shred::Data(shred)) => Some(shred.last_in_slot),
                    _ => None,
                })
                .all(|last_in_slot| !last_in_slot),
            "an unfinished slot must not look closed"
        );
    }

    /// The reference tick shares its byte with the flags, so a leader tick of
    /// zero and a masking bug look identical unless a non-zero one is checked.
    #[test]
    fn reads_the_leader_tick_out_of_the_flag_byte() {
        for tick in [0u8, 7, 63] {
            for payload in slot_shreds(tick, true) {
                let Some(Shred::Data(shred)) = parse(&payload, SHRED_VERSION) else {
                    panic!("data shred did not parse");
                };
                assert_eq!(shred.reference_tick, tick, "tick {tick} came back wrong");
            }
        }
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
