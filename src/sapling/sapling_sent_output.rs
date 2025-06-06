use anyhow::Context;
use bc_envelope::prelude::*;
use crate::{test_envelope_roundtrip, Indexed};

use super::super::{u256, Amount, Blob};

/// Represents a sent output in a Sapling shielded transaction within a Zcash wallet.
///
/// `SaplingSentOutput` stores the plaintext details of a Sapling note that was sent by the
/// wallet, which are not recoverable from the blockchain after transmission. This information
/// enables selective disclosure, allowing a sender to prove they made a payment to a specific
/// shielded address without revealing additional transaction details.
///
/// # Zcash Concept Relation
/// In Zcash's Sapling protocol (activated in October 2018):
///
/// - **Shielded transactions** encrypt transaction details on the blockchain using zk-SNARKs
/// - **Notes** are the fundamental unit of value transfer, similar to UTXOs in transparent transactions
/// - **Sent output information** is stored by the sender's wallet to enable proofs of payment
///
/// Each sent output contains components of the Sapling note:
/// - Diversifier: Part of the recipient's shielded address derivation
/// - Public key: The recipient's public key for the transaction
/// - Value: The amount of ZEC transferred
/// - Rcm: Random commitment material used to construct the note commitment
///
/// # Data Preservation
/// During wallet migration, sent output information must be preserved to maintain
/// the ability to generate payment proofs for regulatory compliance, auditing,
/// or other selective disclosure purposes. The sending wallet is the only entity
/// that has this information in plaintext form.
///
/// # Examples
/// ```
/// # use zewif::{sapling::SaplingSentOutput, Blob, u256, Amount};
/// # use anyhow::Result;
/// # fn example() -> Result<()> {
/// // Create a new sent output
/// let mut sent_output = SaplingSentOutput::new();
///
/// // Set the note components
/// let diversifier = Blob::<11>::default(); // In practice, this would be the actual diversifier
/// sent_output.set_diversifier(diversifier);
///
/// let pk = u256::default(); // In practice, this would be the recipient's public key
/// sent_output.set_receipient_public_key(pk);
///
/// let value = Amount::from_u64(5000000)?; // 0.05 ZEC
/// sent_output.set_value(value);
///
/// let rcm = u256::default(); // In practice, this would be random commitment material
/// sent_output.set_rcm(rcm);
///
/// // Access the components
/// let amount = sent_output.value();
/// let zats: i64 = amount.into();
/// assert_eq!(zats, 5000000);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaplingSentOutput {
    /// The index of the output in the transaction.
    index: usize,

    /// The diversifier used in deriving the recipient's shielded address.
    ///
    /// This 11-byte value is part of the Sapling address construction, allowing multiple
    /// unique addresses to be generated from a single key pair. It is critical for
    /// identifying the recipient and reconstructing the note for proof generation.
    diversifier: Blob<11>,

    /// The recipient's public key, serialized in compressed form.
    ///
    /// This 32-byte value represents a point on the Jubjub curve, used in Sapling's
    /// cryptographic operations. It is part of the note plaintext and is needed to
    /// verify the recipient of the sent funds during selective disclosure.
    receipient_public_key: u256,

    /// The value of ZEC sent in this output, in zatoshis (1 ZEC = 10^8 zatoshis).
    ///
    /// This 64-bit unsigned integer specifies the amount transferred. It is constrained
    /// by the protocol to a maximum value (2^63 - 1 zatoshis), ensuring it fits within
    /// the note's value field for Sapling transactions.
    value: Amount,

    /// The random commitment material used in the note commitment.
    ///
    /// This 32-byte value (256-bit scalar) is a randomly generated element used to
    /// construct the note commitment on the blockchain, ensuring privacy by masking
    /// the note's contents. It is stored here to allow reconstruction of the commitment
    /// for proving purposes.
    rcm: u256,
}

impl Indexed for SaplingSentOutput {
    fn index(&self) -> usize {
        self.index
    }

    fn set_index(&mut self, index: usize) {
        self.index = index;
    }
}

impl SaplingSentOutput {
    /// Creates a new `SaplingSentOutput` with default values.
    ///
    /// This constructor initializes a `SaplingSentOutput` with empty default values
    /// for all fields. In practical use, these values would be set using the setter
    /// methods before the object is used.
    ///
    /// # Returns
    /// A new `SaplingSentOutput` instance with default values.
    ///
    /// # Examples
    /// ```
    /// # use zewif::sapling::SaplingSentOutput;
    /// let sent_output = SaplingSentOutput::new();
    /// ```
    pub fn new() -> Self {
        Self {
            index: 0,
            diversifier: Blob::default(),
            receipient_public_key: u256::default(),
            value: Amount::zero(),
            rcm: u256::default(),
        }
    }

    /// Returns a reference to the diversifier used in the recipient's address derivation.
    ///
    /// The diversifier is an 11-byte value that's part of Sapling shielded address construction.
    /// It allows multiple unique addresses to be generated from a single key pair, enhancing
    /// privacy by preventing address reuse.
    ///
    /// # Returns
    /// A reference to the 11-byte `Blob` containing the diversifier.
    ///
    /// # Examples
    /// ```
    /// # use zewif::{sapling::SaplingSentOutput, Blob};
    /// let sent_output = SaplingSentOutput::new();
    /// let diversifier = sent_output.diversifier();
    /// ```
    pub fn diversifier(&self) -> &Blob<11> {
        &self.diversifier
    }

    /// Sets the diversifier for this sent output.
    ///
    /// # Arguments
    /// * `diversifier` - The 11-byte diversifier value used in the recipient's shielded address
    ///
    /// # Examples
    /// ```
    /// # use zewif::{sapling::SaplingSentOutput, Blob};
    /// let mut sent_output = SaplingSentOutput::new();
    /// let diversifier = Blob::<11>::default();
    /// sent_output.set_diversifier(diversifier);
    /// ```
    pub fn set_diversifier(&mut self, diversifier: Blob<11>) {
        self.diversifier = diversifier;
    }

    /// Returns a reference to the recipient's public key.
    ///
    /// This is a 32-byte representation of a point on the Jubjub curve, used to encrypt
    /// the note content for the recipient. It is part of the plaintext information
    /// that the sender's wallet must store to enable selective disclosure.
    ///
    /// # Returns
    /// A reference to the recipient's public key as a `u256`.
    ///
    /// # Examples
    /// ```
    /// # use zewif::{sapling::SaplingSentOutput, u256};
    /// let sent_output = SaplingSentOutput::new();
    /// let recipient_pk = sent_output.receipient_public_key();
    /// ```
    pub fn receipient_public_key(&self) -> &u256 {
        &self.receipient_public_key
    }

    /// Sets the recipient's public key.
    ///
    /// # Arguments
    /// * `key` - The 32-byte recipient public key value
    ///
    /// # Examples
    /// ```
    /// # use zewif::{sapling::SaplingSentOutput, u256};
    /// let mut sent_output = SaplingSentOutput::new();
    /// let pk = u256::default();
    /// sent_output.set_receipient_public_key(pk);
    /// ```
    pub fn set_receipient_public_key(&mut self, key: u256) {
        self.receipient_public_key = key;
    }

    /// Returns the value (amount) of ZEC sent in this output.
    ///
    /// This represents the amount of ZEC transferred in this specific note,
    /// measured in zatoshis (1 ZEC = 10^8 zatoshis).
    ///
    /// # Returns
    /// The amount of ZEC as an `Amount`.
    ///
    /// # Examples
    /// ```
    /// # use zewif::{sapling::SaplingSentOutput, Amount};
    /// # use anyhow::Result;
    /// # fn example() -> Result<()> {
    /// let mut sent_output = SaplingSentOutput::new();
    /// sent_output.set_value(Amount::from_u64(10_000_000)?); // 0.1 ZEC
    ///
    /// let value = sent_output.value();
    /// let zats: i64 = value.into();
    /// assert_eq!(zats, 10_000_000);
    /// # Ok(())
    /// # }
    /// ```
    pub fn value(&self) -> Amount {
        self.value
    }

    /// Sets the value (amount) of ZEC for this sent output.
    ///
    /// # Arguments
    /// * `value` - The amount of ZEC to set
    ///
    /// # Examples
    /// ```
    /// # use zewif::{sapling::SaplingSentOutput, Amount};
    /// # use anyhow::Result;
    /// # fn example() -> Result<()> {
    /// let mut sent_output = SaplingSentOutput::new();
    /// let amount = Amount::from_u64(50_000_000)?; // 0.5 ZEC
    /// sent_output.set_value(amount);
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_value(&mut self, value: Amount) {
        self.value = value;
    }

    /// Returns a reference to the random commitment material.
    ///
    /// The rcm (random commitment material) is a 32-byte value used in constructing
    /// the note commitment on the blockchain. It ensures privacy by masking the
    /// note's contents. The sender must store this value to enable selective disclosure
    /// or payment proofs.
    ///
    /// # Returns
    /// A reference to the random commitment material as a `u256`.
    ///
    /// # Examples
    /// ```
    /// # use zewif::{sapling::SaplingSentOutput, u256};
    /// let sent_output = SaplingSentOutput::new();
    /// let rcm = sent_output.rcm();
    /// ```
    pub fn rcm(&self) -> &u256 {
        &self.rcm
    }

    /// Sets the random commitment material for this sent output.
    ///
    /// # Arguments
    /// * `rcm` - The 32-byte random commitment material
    ///
    /// # Examples
    /// ```
    /// # use zewif::{sapling::SaplingSentOutput, u256};
    /// let mut sent_output = SaplingSentOutput::new();
    /// let rcm = u256::default();
    /// sent_output.set_rcm(rcm);
    /// ```
    pub fn set_rcm(&mut self, rcm: u256) {
        self.rcm = rcm;
    }
}

impl Default for SaplingSentOutput {
    fn default() -> Self {
        Self::new()
    }
}

impl From<SaplingSentOutput> for Envelope {
    fn from(value: SaplingSentOutput) -> Self {
        Envelope::new(value.index)
            .add_type("SaplingSentOutput")
            .add_assertion("diversifier", value.diversifier)
            .add_assertion("receipient_public_key", value.receipient_public_key)
            .add_assertion("value", value.value)
            .add_assertion("rcm", value.rcm)
    }
}

impl TryFrom<Envelope> for SaplingSentOutput {
    type Error = anyhow::Error;

    fn try_from(envelope: Envelope) -> Result<Self, Self::Error> {
        envelope.check_type_envelope("SaplingSentOutput").context("SaplingSentOutput")?;
        let index = envelope.extract_subject().context("index")?;
        let diversifier = envelope.extract_object_for_predicate("diversifier").context("diversifier")?;
        let receipient_public_key = envelope.extract_object_for_predicate("receipient_public_key").context("receipient_public_key")?;
        let value = envelope.extract_object_for_predicate("value").context("value")?;
        let rcm = envelope.extract_object_for_predicate("rcm").context("rcm")?;

        Ok(SaplingSentOutput {
            index,
            diversifier,
            receipient_public_key,
            value,
            rcm,
        })
    }
}

#[cfg(test)]
impl crate::RandomInstance for SaplingSentOutput {
    fn random() -> Self {
        Self {
            index: 0,
            diversifier: Blob::random(),
            receipient_public_key: u256::random(),
            value: Amount::random(),
            rcm: u256::random(),
        }
    }
}

test_envelope_roundtrip!(SaplingSentOutput);
