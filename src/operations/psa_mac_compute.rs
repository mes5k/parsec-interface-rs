// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PsaMacCompute operation
//!
//! Compute the MAC value of a message.

use super::psa_key_attributes::Attributes;
use crate::operations::psa_algorithm::Mac;
use derivative::Derivative;

/// Native object for MAC compute operations.
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
}

impl Operation {
    /// Validate the contents of the operation against the attributes of the key it targets
    ///
    /// This method checks that:
    /// * the key policy allows the encryption algorithm requested in the operation
    /// * there is sufficient buffer size for the MAC of the specified algorithm, if compatible
    pub fn validate(&self, key_attributes: Attributes) -> crate::requests::Result<()> {
        key_attributes.permits_alg(self.alg.into())?;
        let _size = key_attributes.mac_length(self.alg.into())?;
        Ok(())
    }
}

/// Native object for MAC compute result.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Result {
    /// The `mac` field contains the MAC value of the message.
    #[derivative(Debug = "ignore")]
    pub mac: zeroize::Zeroizing<Vec<u8>>,
}
