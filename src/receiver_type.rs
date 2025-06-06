use crate::CompactSize;
use crate::parser::prelude::*;
use crate::{parse, test_cbor_roundtrip};
use anyhow::{Result, bail};
use bc_envelope::prelude::*;

/// ZCash receiver types used in addresses, particularly in Unified Addresses.
///
/// `ReceiverType` represents the different address formats that can receive funds
/// in the Zcash network. Each type corresponds to a specific protocol implementation
/// (transparent, Sapling, or Orchard) and has its own encoding rules and privacy properties.
///
/// # Zcash Concept Relation
/// Zcash supports multiple address formats that reflect its evolution as a privacy-focused
/// cryptocurrency:
///
/// - **Transparent addresses** (P2PKH, P2SH): Bitcoin-compatible addresses with no privacy features
/// - **Sapling addresses**: First-generation shielded addresses with strong privacy guarantees
/// - **Orchard addresses**: Latest shielded protocol with improved performance and security
///
/// When Unified Addresses (UAs) were introduced, they needed to identify which specific
/// receiver types were included in each address. These enum values are used to tag
/// components in a UA and are also used in the binary encoding of UAs.
///
/// # Data Preservation
/// The `ReceiverType` enum preserves the exact type identifiers from wallet data,
/// ensuring that Unified Addresses can be properly reconstructed during wallet migration.
/// The underlying byte values match the Zcash protocol specification for UA encoding.
///
/// # Examples
/// In a Unified Address, multiple receiver types might be present:
/// ```
/// # use zewif::ReceiverType;
/// // A UA might contain both transparent and shielded receivers
/// let receivers = vec![ReceiverType::P2PKH, ReceiverType::Sapling];
///
/// // Check if this UA has Orchard support
/// let has_orchard = receivers.contains(&ReceiverType::Orchard);
/// assert!(!has_orchard);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ReceiverType {
    /// P2PKH (Pay to Public Key Hash) transparent address type
    P2PKH = 0x00,
    /// P2SH (Pay to Script Hash) transparent address type
    P2SH = 0x01,
    /// Sapling shielded address type
    Sapling = 0x02,
    /// Orchard shielded address type
    Orchard = 0x03,
}

/// Parses a ReceiverType from a binary data stream
impl Parse for ReceiverType {
    fn parse(p: &mut Parser) -> Result<Self> {
        let byte = *parse!(p, CompactSize, "ReceiverType")?;
        match byte {
            0x00 => Ok(ReceiverType::P2PKH),
            0x01 => Ok(ReceiverType::P2SH),
            0x02 => Ok(ReceiverType::Sapling),
            0x03 => Ok(ReceiverType::Orchard),
            _ => Err(anyhow::anyhow!("Invalid ReceiverType byte: 0x{:02x}", byte)),
        }
    }
}

impl From<ReceiverType> for String {
    fn from(value: ReceiverType) -> Self {
        match value {
            ReceiverType::P2PKH => "P2PKH".to_string(),
            ReceiverType::P2SH => "P2SH".to_string(),
            ReceiverType::Sapling => "Sapling".to_string(),
            ReceiverType::Orchard => "Orchard".to_string(),
        }
    }
}

impl TryFrom<String> for ReceiverType {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        match value.as_str() {
            "P2PKH" => Ok(ReceiverType::P2PKH),
            "P2SH" => Ok(ReceiverType::P2SH),
            "Sapling" => Ok(ReceiverType::Sapling),
            "Orchard" => Ok(ReceiverType::Orchard),
            _ => bail!("Invalid ReceiverType string: {}", value),
        }
    }
}

impl From<ReceiverType> for CBOR {
    fn from(value: ReceiverType) -> Self {
        String::from(value).into()
    }
}

impl TryFrom<CBOR> for ReceiverType {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Ok(cbor.try_into_text()?.try_into()?)
    }
}

#[cfg(test)]
impl crate::RandomInstance for ReceiverType {
    fn random() -> Self {
        let mut rng = rand::thread_rng();
        let a = rand::Rng::gen_range(&mut rng, 0..=3);
        match a {
            0 => ReceiverType::P2PKH,
            1 => ReceiverType::P2SH,
            2 => ReceiverType::Sapling,
            _ => ReceiverType::Orchard,
        }
    }
}

test_cbor_roundtrip!(ReceiverType);
