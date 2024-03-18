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
    /// * the key policy usage allows signing of the hash
    /// * the key policy allows the encryption algorithm requested in the operation
    /// * there is sufficient buffer size for the MAC of the specified algorithm, if compatible
    pub fn validate(&self, key_attributes: Attributes) -> crate::requests::Result<()> {
        key_attributes.can_sign_hash()?;
        key_attributes.permits_alg(self.alg.into())?;
        let size = key_attributes.mac_length(self.alg.into())?;
        println!("SIZE: {}",size);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::psa_algorithm::{Algorithm, Mac, FullLengthMac, Hash};
    use crate::operations::psa_key_attributes::{Lifetime, Policy, Type, UsageFlags};
    use crate::requests::ResponseStatus;

    fn get_attrs(mac: Mac) -> Attributes {
        let permitted_alg = Algorithm::Mac(mac);
        // UsageFlags defined in psa-cryto/src/types/keys.rs, gets re-exported by parsec-client-rust
        let mut usage = UsageFlags::default();
        // set_sign_hash is needed for mac_compute, set_verify_hash is needed for mac_verify
        let _ = usage.set_sign_hash().set_verify_hash();
        // Attributes defined in psa-cryto/src/types/keys.rs, gets re-exported by parsec-client-rust
        let attributes = Attributes {
            key_type: Type::Hmac,
            bits: 256,
            lifetime: Lifetime::Volatile,
            policy: Policy {
                usage_flags: usage,
                permitted_algorithms: permitted_alg,
            },
        };
        attributes
    }

    #[test]
    fn validate_success() {
        let alg = Mac::FullLength(FullLengthMac::Hmac { hash_alg: Hash::Sha256 });
        (Operation {
            key_name: String::from("some key"),
            alg,
            input: vec![0xff; 32].into(),
        })
        .validate(get_attrs(alg))
        .unwrap();
    }

    #[test]
    fn cannot_sign() {
        let alg = Mac::FullLength(FullLengthMac::Hmac { hash_alg: Hash::Sha256 });
        let mut attrs = get_attrs(alg);
        attrs.policy.usage_flags = UsageFlags::default();
        assert_eq!(
            (Operation {
                key_name: String::from("some key"),
                alg,
                input: vec![0xff; 32].into(),
            })
            .validate(attrs)
            .unwrap_err(),
            ResponseStatus::PsaErrorNotPermitted
        );
    }

    #[test]
    fn wrong_algorithm() {
        let right = Mac::FullLength(FullLengthMac::Hmac { hash_alg: Hash::Sha1 });
        let wrong = Mac::FullLength(FullLengthMac::Hmac { hash_alg: Hash::Sha256 });
        assert_eq!(
            (Operation {
                key_name: String::from("some key"),
                alg: right,
                input: vec![0xff; 32].into(),
            })
            .validate(get_attrs(wrong))
            .unwrap_err(),
            ResponseStatus::PsaErrorNotPermitted
        );
    }

//    #[test]
//    fn bad_mac_length() {
//        let alg = Mac::FullLength(FullLengthMac::Hmac { hash_alg: Hash::Sha1 });
//        let attrs = get_attrs(alg);
//        assert_eq!(
//            (Operation {
//                key_name: String::from("some key"),
//                alg,
//                input: vec![0xff; 32].into(),
//            })
//            .validate(attrs)
//            .unwrap_err(),
//            ResponseStatus::PsaErrorNotPermitted
//        );
//    }
}
