//! Reading keys off disk, in the format `solana-keygen` writes.
//!
//! Two things are read here and they are not the same thing. A keypair is a
//! secret and only the side that signs needs one; an address is public and is
//! all that watching a wallet requires. They share a file format only because
//! the bench happens to hold both keys of the wallet it is racing — reading an
//! address out of a keypair file is a convenience for that, not an invitation
//! to hand the sniper a secret it has no use for.

use {
    solana_keypair::Keypair,
    solana_signer::Signer,
    solana_transaction::Address,
    std::{
        fmt::{self, Display},
        fs,
        path::{Path, PathBuf},
    },
};

#[derive(Debug)]
pub struct KeyError {
    path: PathBuf,
    reason: String,
}

impl Display for KeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.path.display(), self.reason)
    }
}

impl std::error::Error for KeyError {}

/// A keypair from a `solana-keygen` JSON file: the 64 bytes of an ed25519
/// keypair as a decimal array.
pub fn keypair(path: &Path) -> Result<Keypair, KeyError> {
    let fail = |reason: String| KeyError {
        path: path.to_path_buf(),
        reason,
    };
    let text = fs::read_to_string(path).map_err(|err| fail(err.to_string()))?;
    let bytes: Vec<u8> =
        serde_json::from_str(&text).map_err(|err| fail(format!("not a keypair file: {err}")))?;
    Keypair::try_from(bytes.as_slice()).map_err(|err| fail(err.to_string()))
}

/// An address from either a keypair file or a file holding nothing but a
/// base58 pubkey, so that whichever of the two an operator has to hand works.
pub fn address(path: &Path) -> Result<Address, KeyError> {
    let fail = |reason: String| KeyError {
        path: path.to_path_buf(),
        reason,
    };
    let text = fs::read_to_string(path).map_err(|err| fail(err.to_string()))?;
    let trimmed = text.trim();
    if trimmed.starts_with('[') {
        return keypair(path).map(|keypair| keypair.pubkey());
    }
    trimmed
        .parse()
        .map_err(|err| fail(format!("not an address: {err}")))
}
