use crate::{DebugOption, Indexed};
use anyhow::{Context, Result};
use bc_envelope::prelude::*;

use super::ProtocolAddress;

/// A high-level address representation with metadata in a Zcash wallet.
///
/// `Address` serves as the primary container for all Zcash addresses, wrapping
/// the protocol-specific address details with additional wallet-level metadata
/// such as a user-assigned name, purpose descriptor, and arbitrary attachments.
/// This structure bridges the raw cryptographic address formats with the
/// user-facing wallet experience.
///
/// # Zcash Concept Relation
/// In Zcash wallets, users typically assign labels or metadata to their addresses
/// for easier identification. `Address` preserves these user-defined attributes
/// alongside the underlying cryptographic address details. It supports all Zcash
/// address protocols:
///
/// - **Transparent addresses**: Bitcoin-compatible addresses (t-prefixed)
/// - **Sapling addresses**: Shielded Sapling protocol addresses (z-prefixed)
/// - **Unified addresses**: Multi-protocol addresses (u-prefixed)
///
/// # Data Preservation
/// During wallet migration, the following components are preserved:
///
/// - **Address Data**: The complete protocol-specific address details
/// - **User Labels**: Custom names assigned to addresses by users
/// - **Purpose Strings**: Descriptions of the address's intended use
/// - **Attachments**: Any additional metadata associated with the address
///
/// # Examples
/// ```
/// # use zewif::{Address, ProtocolAddress, transparent};
/// #
/// // Create a transparent address
/// let t_addr = transparent::Address::new("t1exampleaddress");
/// let protocol_addr = ProtocolAddress::Transparent(t_addr);
///
/// // Wrap it in an Address with metadata
/// let mut address = Address::new(protocol_addr);
/// address.set_name("Donation Address".to_string());
/// address.set_purpose("Receiving public donations".to_string());
///
/// // Access the address string
/// assert!(address.as_string().starts_with("t1"));
/// assert_eq!(address.name(), "Donation Address");
/// ```
#[derive(Clone, PartialEq)]
pub struct Address {
    /// The index of this address in the wallet
    /// TODO: I'm not sure that this is useful; if it's intended to be used as a primary key then
    /// it should be of some non-conflicting type such as a UUID.
    index: usize,

    /// The underlying protocol-specific address
    address: ProtocolAddress,

    /// User-assigned name/label for this address
    name: String,

    /// Optional description of this address's purpose
    purpose: Option<String>,

    /// Additional metadata attached to this address
    attachments: Attachments,
}

impl Indexed for Address {
    fn index(&self) -> usize {
        self.index
    }

    fn set_index(&mut self, index: usize) {
        self.index = index;
    }
}

impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Address")
            .field("address", &self.address)
            .field("name", &self.name)
            .field("purpose", &DebugOption(&self.purpose))
            .field("attachments", &self.attachments)
            .finish()
    }
}

bc_envelope::impl_attachable!(Address);

impl Address {
    /// Creates a new `Address` with the specified protocol address.
    ///
    /// This constructor creates an `Address` with default empty metadata
    /// (blank name, no purpose) and the provided protocol-specific address.
    ///
    /// # Arguments
    /// * `address` - The protocol-specific address implementation
    ///
    /// # Examples
    /// ```
    /// # use zewif::{Address, ProtocolAddress, transparent};
    /// #
    /// let t_addr = transparent::Address::new("t1example");
    /// let protocol_addr = ProtocolAddress::Transparent(t_addr);
    /// let address = Address::new(protocol_addr);
    /// ```
    pub fn new(address: ProtocolAddress) -> Self {
        Self {
            index: 0,
            address,
            name: String::default(),
            purpose: None,
            attachments: Attachments::new(),
        }
    }

    /// Returns the user-assigned name for this address.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the purpose descriptor for this address.
    pub fn purpose(&self) -> Option<&str> {
        self.purpose.as_deref()
    }

    /// Sets the purpose descriptor for this address.
    pub fn set_purpose(&mut self, purpose: String) {
        self.purpose = Some(purpose);
    }

    /// Returns the address in canonical string format.
    pub fn as_string(&self) -> String {
        self.address.as_string()
    }

    /// Returns a reference to the protocol-specific address.
    pub fn address(&self) -> &ProtocolAddress {
        &self.address
    }

    /// Returns a mutable reference to the protocol-specific address.
    ///
    /// # Returns
    /// A mutable reference to the `ProtocolAddress` contained within this address.
    ///
    /// # Examples
    /// ```
    /// # use zewif::{Address, ProtocolAddress, transparent, sapling};
    /// #
    /// let mut address = Address::new(ProtocolAddress::Transparent(
    ///     transparent::Address::new("t1example")
    /// ));
    ///
    /// // Swap the address out for a Sapling address
    /// if let ProtocolAddress::Transparent(_) = address.address() {
    ///     *address.address_mut() = ProtocolAddress::Sapling(
    ///         Box::new(sapling::Address::new("zs1example".to_string()))
    ///     );
    /// }
    ///
    /// assert!(matches!(address.address(), ProtocolAddress::Sapling(_)));
    /// ```
    pub fn address_mut(&mut self) -> &mut ProtocolAddress {
        &mut self.address
    }

    /// Sets the name for this address.
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// Replaces the protocol-specific address.
    pub fn set_address(&mut self, address: ProtocolAddress) {
        self.address = address;
    }
}

impl From<Address> for Envelope {
    fn from(value: Address) -> Self {
        let envelope = Envelope::new(value.index)
            .add_type("Address")
            .add_assertion("address", value.address)
            .add_assertion("name", value.name)
            .add_optional_assertion("purpose", value.purpose);
        value.attachments.add_to_envelope(envelope)
    }
}

impl TryFrom<Envelope> for Address {
    type Error = anyhow::Error;

    fn try_from(envelope: Envelope) -> Result<Self, Self::Error> {
        envelope.check_type_envelope("Address").context("Address")?;
        let index = envelope.extract_subject().context("index")?;
        let address = envelope
            .try_object_for_predicate("address")
            .context("address")?;
        let name = envelope.try_object_for_predicate("name").context("name")?;
        let purpose = envelope
            .try_optional_object_for_predicate("purpose")
            .context("purpose")?;
        let attachments = Attachments::try_from_envelope(&envelope).context("attachments")?;
        Ok(Address {
            index,
            address,
            name,
            purpose,
            attachments,
        })
    }
}

#[cfg(test)]
mod tests {
    use bc_envelope::Attachments;

    use crate::{ProtocolAddress, test_envelope_roundtrip};

    use super::Address;

    impl crate::RandomInstance for Address {
        fn random() -> Self {
            Self {
                index: 0,
                name: String::random(),
                purpose: String::opt_random(),
                address: ProtocolAddress::random(),
                attachments: Attachments::random(),
            }
        }
    }

    test_envelope_roundtrip!(Address);
}
