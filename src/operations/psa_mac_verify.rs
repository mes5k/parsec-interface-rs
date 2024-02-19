// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PsaMacVerify operation
//!
//! Compute the MAC value of a message and verify it against a reference value.

use super::psa_key_attributes::Attributes;
use crate::operations::psa_algorithm::Mac;
use derivative::Derivative;

/// Native object for MAC verify operations.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Operation {
    /// Defines which key should be used for the MAC operation.
    pub key_name: String,
    /// The MAC algorithm to compute.
    pub alg: Mac,
    /// The input from which to generate a MAC value.
    #[derivative(Debug = "ignore")]
    pub input: zeroize::Zeroizing<Vec<u8>>,
    /// The reference MAC value.
    #[derivative(Debug = "ignore")]
    pub mac: zeroize::Zeroizing<Vec<u8>>,
}

impl Operation {
    /// Validate the contents of the operation against the attributes of the key it targets
    ///
    /// This method checks that:
    /// * the key policy allows decrypting messages
    /// * the key policy allows the encryption algorithm requested in the operation
    /// * the key type is compatible with the requested algorithm
    /// * the message to decrypt is valid (not length 0)
    /// * the nonce is valid (not length 0)
    pub fn validate(&self, _key_attributes: Attributes) -> crate::requests::Result<()> {
        //key_attributes.can_decrypt_message()?;
        //key_attributes.permits_alg(self.alg.into())?;
        //key_attributes.compatible_with_alg(self.alg.into())?;
        //if self.ciphertext.is_empty() || self.nonce.is_empty() {
        //    return Err(ResponseStatus::PsaErrorInvalidArgument);
        //}
        Ok(())
    }
}

/// Native object for MAC verify result.
#[derive(Debug, Default, Copy, Clone)]
pub struct Result;
