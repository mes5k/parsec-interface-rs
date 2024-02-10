// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PsaMacCompute operation
//!
//! Compute the MAC value of a message.

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

/// Native object for MAC compute result.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Result {
    /// The `mac` field contains the MAC value of the message.
    #[derivative(Debug = "ignore")]
    pub mac: zeroize::Zeroizing<Vec<u8>>,
}
