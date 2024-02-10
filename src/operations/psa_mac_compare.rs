// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PsaMacCompare operation
//!
//! Compute the MAC value of a message and compare it with a reference value.

use crate::operations::psa_algorithm::Mac;
use derivative::Derivative;

/// Native object for MAC compare operations.
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

/// Native object for MAC compare result.
#[derive(Debug, Default, Copy, Clone)]
pub struct Result;
