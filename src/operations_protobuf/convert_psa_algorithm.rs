// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
// Protobuf imports
use super::generated_ops::psa_algorithm::algorithm;
use super::generated_ops::psa_algorithm::algorithm::aead;
use super::generated_ops::psa_algorithm::algorithm::aead::AeadWithDefaultLengthTag as AeadWithDefaultLengthTagProto;
use super::generated_ops::psa_algorithm::algorithm::asymmetric_encryption;
use super::generated_ops::psa_algorithm::algorithm::asymmetric_signature;
use super::generated_ops::psa_algorithm::algorithm::asymmetric_signature::sign_hash;
use super::generated_ops::psa_algorithm::algorithm::asymmetric_signature::SignHash as SignHashProto;
use super::generated_ops::psa_algorithm::algorithm::key_agreement;
use super::generated_ops::psa_algorithm::algorithm::key_agreement::Raw as RawKeyAgreementProto;
use super::generated_ops::psa_algorithm::algorithm::key_derivation;
use super::generated_ops::psa_algorithm::algorithm::Aead as AeadProto;
use super::generated_ops::psa_algorithm::algorithm::AsymmetricEncryption as AsymmetricEncryptionProto;
use super::generated_ops::psa_algorithm::algorithm::AsymmetricSignature as AsymmetricSignatureProto;
use super::generated_ops::psa_algorithm::algorithm::Cipher as CipherProto;
use super::generated_ops::psa_algorithm::algorithm::Hash as HashProto;
use super::generated_ops::psa_algorithm::algorithm::KeyAgreement as KeyAgreementProto;
use super::generated_ops::psa_algorithm::algorithm::KeyDerivation as KeyDerivationProto;
use super::generated_ops::psa_algorithm::algorithm::Mac as MacProto;
use super::generated_ops::psa_algorithm::algorithm::None as NoneProto;
use super::generated_ops::psa_algorithm::algorithm::{mac, mac::FullLength as FullLengthMacProto};
use super::generated_ops::psa_algorithm::Algorithm as AlgorithmProto;

// Native imports
use crate::operations::psa_algorithm::{
    Aead, AeadWithDefaultLengthTag, Algorithm, AsymmetricEncryption, AsymmetricSignature, Cipher,
    FullLengthMac, Hash, KeyAgreement, KeyDerivation, Mac, RawKeyAgreement, SignHash,
};

use crate::requests::{ResponseStatus, Result};
use log::error;
use std::convert::{TryFrom, TryInto};

// Hash algorithms: from protobuf to native
impl TryFrom<HashProto> for Hash {
    type Error = ResponseStatus;

    fn try_from(hash_val: HashProto) -> Result<Self> {
        match hash_val {
            HashProto::None => {
                error!("The None value of Hash enumeration is not allowed (mandatory field).");
                Err(ResponseStatus::InvalidEncoding)
            }
            #[allow(deprecated)]
            HashProto::Md2 => Ok(Hash::Md2),
            #[allow(deprecated)]
            HashProto::Md4 => Ok(Hash::Md4),
            #[allow(deprecated)]
            HashProto::Md5 => Ok(Hash::Md5),
            HashProto::Ripemd160 => Ok(Hash::Ripemd160),
            #[allow(deprecated)]
            HashProto::Sha1 => Ok(Hash::Sha1),
            HashProto::Sha224 => Ok(Hash::Sha224),
            HashProto::Sha256 => Ok(Hash::Sha256),
            HashProto::Sha384 => Ok(Hash::Sha384),
            HashProto::Sha512 => Ok(Hash::Sha512),
            HashProto::Sha512224 => Ok(Hash::Sha512_224),
            HashProto::Sha512256 => Ok(Hash::Sha512_256),
            HashProto::Sha3224 => Ok(Hash::Sha3_224),
            HashProto::Sha3256 => Ok(Hash::Sha3_256),
            HashProto::Sha3384 => Ok(Hash::Sha3_384),
            HashProto::Sha3512 => Ok(Hash::Sha3_512),
        }
    }
}

// Hash algorithms: from protobuf to native
pub fn i32_to_hash(hash_val: i32) -> Result<Hash> {
    let hash_proto_alg: HashProto = hash_val.try_into()?;
    hash_proto_alg.try_into()
}

// Hash algorithms: from native to protobuf
pub fn hash_to_i32(hash: Hash) -> i32 {
    match hash {
        #[allow(deprecated)]
        Hash::Md2 => HashProto::Md2.into(),
        #[allow(deprecated)]
        Hash::Md4 => HashProto::Md4.into(),
        #[allow(deprecated)]
        Hash::Md5 => HashProto::Md5.into(),
        Hash::Ripemd160 => HashProto::Ripemd160.into(),
        #[allow(deprecated)]
        Hash::Sha1 => HashProto::Sha1.into(),
        Hash::Sha224 => HashProto::Sha224.into(),
        Hash::Sha256 => HashProto::Sha256.into(),
        Hash::Sha384 => HashProto::Sha384.into(),
        Hash::Sha512 => HashProto::Sha512.into(),
        Hash::Sha512_224 => HashProto::Sha512224.into(),
        Hash::Sha512_256 => HashProto::Sha512256.into(),
        Hash::Sha3_224 => HashProto::Sha3224.into(),
        Hash::Sha3_256 => HashProto::Sha3256.into(),
        Hash::Sha3_384 => HashProto::Sha3384.into(),
        Hash::Sha3_512 => HashProto::Sha3512.into(),
    }
}

impl TryFrom<SignHashProto> for SignHash {
    type Error = ResponseStatus;

    fn try_from(sign_hash_val: SignHashProto) -> Result<Self> {
        let sign_hash_variant = sign_hash_val.variant.ok_or_else(|| {
            error!("The SignHash variant used is not supported.");
            ResponseStatus::InvalidEncoding
        })?;
        match sign_hash_variant {
            sign_hash::Variant::Any(_) => Ok(SignHash::Any),
            sign_hash::Variant::Specific(hash_val) => Ok(SignHash::Specific(
                HashProto::try_from(hash_val)?.try_into()?,
            )),
        }
    }
}

impl From<SignHash> for SignHashProto {
    fn from(sign_hash: SignHash) -> Self {
        match sign_hash {
            SignHash::Any => SignHashProto {
                variant: Some(sign_hash::Variant::Any(sign_hash::Any {})),
            },
            SignHash::Specific(hash) => SignHashProto {
                variant: Some(sign_hash::Variant::Specific(hash_to_i32(hash))),
            },
        }
    }
}

// FullLengthMac algorithms: from protobuf to native
impl TryFrom<FullLengthMacProto> for FullLengthMac {
    type Error = ResponseStatus;

    fn try_from(alg: FullLengthMacProto) -> Result<Self> {
        let alg_variant = alg.variant.ok_or_else(|| {
            error!("The FullLengthMac variant used is not supported.");
            ResponseStatus::InvalidEncoding
        })?;
        match alg_variant {
            mac::full_length::Variant::Hmac(hmac) => Ok(FullLengthMac::Hmac {
                hash_alg: HashProto::try_from(hmac.hash_alg)?.try_into()?,
            }),
            mac::full_length::Variant::CbcMac(_) => Ok(FullLengthMac::CbcMac),
            mac::full_length::Variant::Cmac(_) => Ok(FullLengthMac::Cmac),
        }
    }
}

// FullLengthMac algorithms: from native to protobuf
impl TryFrom<FullLengthMac> for FullLengthMacProto {
    type Error = ResponseStatus;

    fn try_from(alg: FullLengthMac) -> Result<Self> {
        match alg {
            FullLengthMac::Hmac { hash_alg } => Ok(FullLengthMacProto {
                variant: Some(mac::full_length::Variant::Hmac(mac::full_length::Hmac {
                    hash_alg: hash_to_i32(hash_alg),
                })),
            }),
            FullLengthMac::CbcMac => Ok(FullLengthMacProto {
                variant: Some(mac::full_length::Variant::CbcMac(
                    mac::full_length::CbcMac {},
                )),
            }),
            FullLengthMac::Cmac => Ok(FullLengthMacProto {
                variant: Some(mac::full_length::Variant::Cmac(mac::full_length::Cmac {})),
            }),
        }
    }
}

// Mac algorithms: from protobuf to native
impl TryFrom<MacProto> for Mac {
    type Error = ResponseStatus;

    fn try_from(alg: MacProto) -> Result<Self> {
        let alg_variant = alg.variant.ok_or_else(|| {
            error!("The Mac variant used is not supported.");
            ResponseStatus::InvalidEncoding
        })?;
        match alg_variant {
            mac::Variant::FullLength(full_length) => Ok(Mac::FullLength(full_length.try_into()?)),
            mac::Variant::Truncated(truncated) => Ok(Mac::Truncated {
                mac_alg: truncated.mac_alg.ok_or_else(|| {
                    error!("The mac_alg field of mac::Truncated message is not set (mandatory field).");
                    ResponseStatus::InvalidEncoding
                })?.try_into()?,
                mac_length: truncated.mac_length.try_into().map_err(|e| {
                    error!("mac_length field of mac::Truncated message can not be represented by an usize ({}).", e);
                    ResponseStatus::InvalidEncoding
                })?,
            }),
        }
    }
}

// Mac algorithms: from native to protobuf
impl TryFrom<Mac> for MacProto {
    type Error = ResponseStatus;

    fn try_from(alg: Mac) -> Result<Self> {
        match alg {
            Mac::FullLength(full_length_mac) => Ok(MacProto {
                variant: Some(mac::Variant::FullLength(full_length_mac.try_into()?)),
            }),
            Mac::Truncated {
                mac_alg,
                mac_length,
            } => Ok(MacProto {
                variant: Some(mac::Variant::Truncated(mac::Truncated {
                    mac_alg: Some(mac_alg.try_into()?),
                    mac_length: mac_length.try_into().map_err(|e| {
                        error!(
                            "mac_length field of Mac can not be represented by an u32 ({}).",
                            e
                        );
                        ResponseStatus::InvalidEncoding
                    })?,
                })),
            }),
        }
    }
}

// Cipher algorithms: from protobuf to native
impl TryFrom<CipherProto> for Cipher {
    type Error = ResponseStatus;

    fn try_from(cipher_val: CipherProto) -> Result<Self> {
        match cipher_val {
            CipherProto::None => {
                error!("The None value of Cipher enumeration is not allowed (mandatory field).");
                Err(ResponseStatus::InvalidEncoding)
            }
            CipherProto::StreamCipher => Ok(Cipher::StreamCipher),
            CipherProto::Ctr => Ok(Cipher::Ctr),
            CipherProto::Cfb => Ok(Cipher::Cfb),
            CipherProto::Ofb => Ok(Cipher::Ofb),
            CipherProto::Xts => Ok(Cipher::Xts),
            CipherProto::EcbNoPadding => Ok(Cipher::EcbNoPadding),
            CipherProto::CbcNoPadding => Ok(Cipher::CbcNoPadding),
            CipherProto::CbcPkcs7 => Ok(Cipher::CbcPkcs7),
        }
    }
}

// Cipher algorithms: from protobuf to native
pub fn i32_to_cipher(cipher_val: i32) -> Result<Cipher> {
    let cipher_proto_alg: CipherProto = cipher_val.try_into()?;
    cipher_proto_alg.try_into()
}

// Cipher algorithms: from native to protobuf
pub fn cipher_to_i32(cipher: Cipher) -> i32 {
    match cipher {
        Cipher::StreamCipher => CipherProto::StreamCipher.into(),
        Cipher::Ctr => CipherProto::Ctr.into(),
        Cipher::Cfb => CipherProto::Cfb.into(),
        Cipher::Ofb => CipherProto::Ofb.into(),
        Cipher::Xts => CipherProto::Xts.into(),
        Cipher::EcbNoPadding => CipherProto::EcbNoPadding.into(),
        Cipher::CbcNoPadding => CipherProto::CbcNoPadding.into(),
        Cipher::CbcPkcs7 => CipherProto::CbcPkcs7.into(),
    }
}

// AeadWithDefaultLengthTag algorithms: from protobuf to native
impl TryFrom<AeadWithDefaultLengthTagProto> for AeadWithDefaultLengthTag {
    type Error = ResponseStatus;

    fn try_from(aead_val: AeadWithDefaultLengthTagProto) -> Result<Self> {
        match aead_val {
            AeadWithDefaultLengthTagProto::None => {
                error!("The None value of AeadWithDefaultLengthTag enumeration is not allowed (mandatory field).");
                Err(ResponseStatus::InvalidEncoding)
            }
            AeadWithDefaultLengthTagProto::Ccm => Ok(AeadWithDefaultLengthTag::Ccm),
            AeadWithDefaultLengthTagProto::Gcm => Ok(AeadWithDefaultLengthTag::Gcm),
            AeadWithDefaultLengthTagProto::Chacha20Poly1305 => {
                Ok(AeadWithDefaultLengthTag::Chacha20Poly1305)
            }
        }
    }
}

// AeadWithDefaultLengthTag algorithms: from native to protobuf
fn aead_with_default_length_tag_to_i32(cipher: AeadWithDefaultLengthTag) -> i32 {
    match cipher {
        AeadWithDefaultLengthTag::Ccm => AeadWithDefaultLengthTagProto::Ccm.into(),
        AeadWithDefaultLengthTag::Gcm => AeadWithDefaultLengthTagProto::Gcm.into(),
        AeadWithDefaultLengthTag::Chacha20Poly1305 => {
            AeadWithDefaultLengthTagProto::Chacha20Poly1305.into()
        }
    }
}

// Aead algorithms: from protobuf to native
impl TryFrom<AeadProto> for Aead {
    type Error = ResponseStatus;

    fn try_from(alg: AeadProto) -> Result<Self> {
        let alg_variant = alg.variant.ok_or_else(|| {
            error!("The Aead variant used is not supported.");
            ResponseStatus::InvalidEncoding
        })?;
        match alg_variant {
            aead::Variant::AeadWithDefaultLengthTag(aead_with_default_length_tag) => {
                Ok(Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTagProto::try_from(aead_with_default_length_tag)?.try_into()?))
            },
            aead::Variant::AeadWithShortenedTag(aead_with_shortened_tag) => Ok(Aead::AeadWithShortenedTag {
                aead_alg: AeadWithDefaultLengthTagProto::try_from(aead_with_shortened_tag.aead_alg)?.try_into()?,
                tag_length: aead_with_shortened_tag.tag_length.try_into().map_err(|e| {
                        error!("tag_length field of aead::AeadWithShortenedTag can not be represented by an usize ({}).", e);
                        ResponseStatus::InvalidEncoding
                })?,
            }),
        }
    }
}

// Aead algorithms: from native to protobuf
impl TryFrom<Aead> for AeadProto {
    type Error = ResponseStatus;

    fn try_from(alg: Aead) -> Result<Self> {
        match alg {
            Aead::AeadWithDefaultLengthTag(aead_with_default_length_tag) => Ok(AeadProto {
                variant: Some(aead::Variant::AeadWithDefaultLengthTag(aead_with_default_length_tag_to_i32(aead_with_default_length_tag))),
            }),
            Aead::AeadWithShortenedTag { aead_alg, tag_length } => Ok(AeadProto {
                variant: Some(aead::Variant::AeadWithShortenedTag(aead::AeadWithShortenedTag {
                    aead_alg: aead_with_default_length_tag_to_i32(aead_alg),
                    tag_length: tag_length.try_into().map_err(|e| {
                        error!("tag_length field of Aead::AeadWithShortenedTag can not be represented by an u32 ({}).", e);
                        ResponseStatus::InvalidEncoding
                    })?,
                })),
            }),
        }
    }
}

// AsymmetricSignature algorithms: from protobuf to native
impl TryFrom<AsymmetricSignatureProto> for AsymmetricSignature {
    type Error = ResponseStatus;

    fn try_from(alg: AsymmetricSignatureProto) -> Result<Self> {
        let alg_variant = alg.variant.ok_or_else(|| {
            error!("The AsymmetricSignature variant used is not supported.");
            ResponseStatus::InvalidEncoding
        })?;
        match alg_variant {
            asymmetric_signature::Variant::RsaPkcs1v15Sign(rsa_pkcs1v15_sign) => {
                Ok(AsymmetricSignature::RsaPkcs1v15Sign {
                    hash_alg: rsa_pkcs1v15_sign
                        .hash_alg
                        .ok_or_else(|| {
                            error!("The hash_alg field of RsaPkcs1v15Sign message is not set (mandatory field).");
                            ResponseStatus::InvalidEncoding
                        })?
                        .try_into()?,
                })
            }
            asymmetric_signature::Variant::RsaPkcs1v15SignRaw(_) => {
                Ok(AsymmetricSignature::RsaPkcs1v15SignRaw)
            }
            asymmetric_signature::Variant::RsaPss(rsa_pss) => Ok(AsymmetricSignature::RsaPss {
                hash_alg: rsa_pss
                    .hash_alg
                    .ok_or_else(|| {
                        error!("The hash_alg field of RsaPss message is not set (mandatory field).");
                        ResponseStatus::InvalidEncoding
                    })?
                    .try_into()?,
            }),
            asymmetric_signature::Variant::Ecdsa(ecdsa) => Ok(AsymmetricSignature::Ecdsa {
                hash_alg: ecdsa
                    .hash_alg
                    .ok_or_else(|| {
                        error!("The hash_alg field of Ecdsa message is not set (mandatory field).");
                        ResponseStatus::InvalidEncoding
                    })?
                    .try_into()?,
            }),
            asymmetric_signature::Variant::EcdsaAny(_) => Ok(AsymmetricSignature::EcdsaAny),
            asymmetric_signature::Variant::DeterministicEcdsa(deterministic_ecdsa) => {
                Ok(AsymmetricSignature::DeterministicEcdsa {
                    hash_alg: deterministic_ecdsa
                        .hash_alg
                        .ok_or_else(|| {
                            error!("The hash_alg field of DeterministicEcdsa message is not set (mandatory field).");
                            ResponseStatus::InvalidEncoding
                        })?
                        .try_into()?,
                })
            }
        }
    }
}

// AsymmetricSignature algorithms: from native to protobuf
impl TryFrom<AsymmetricSignature> for AsymmetricSignatureProto {
    type Error = ResponseStatus;

    fn try_from(alg: AsymmetricSignature) -> Result<Self> {
        match alg {
            AsymmetricSignature::RsaPkcs1v15Sign { hash_alg } => Ok(AsymmetricSignatureProto {
                variant: Some(asymmetric_signature::Variant::RsaPkcs1v15Sign(
                    asymmetric_signature::RsaPkcs1v15Sign {
                        hash_alg: Some(hash_alg.into()),
                    },
                )),
            }),
            AsymmetricSignature::RsaPkcs1v15SignRaw => Ok(AsymmetricSignatureProto {
                variant: Some(asymmetric_signature::Variant::RsaPkcs1v15SignRaw(
                    asymmetric_signature::RsaPkcs1v15SignRaw {},
                )),
            }),
            AsymmetricSignature::RsaPss { hash_alg } => Ok(AsymmetricSignatureProto {
                variant: Some(asymmetric_signature::Variant::RsaPss(
                    asymmetric_signature::RsaPss {
                        hash_alg: Some(hash_alg.into()),
                    },
                )),
            }),
            AsymmetricSignature::Ecdsa { hash_alg } => Ok(AsymmetricSignatureProto {
                variant: Some(asymmetric_signature::Variant::Ecdsa(
                    asymmetric_signature::Ecdsa {
                        hash_alg: Some(hash_alg.into()),
                    },
                )),
            }),
            AsymmetricSignature::EcdsaAny => Ok(AsymmetricSignatureProto {
                variant: Some(asymmetric_signature::Variant::EcdsaAny(
                    asymmetric_signature::EcdsaAny {},
                )),
            }),
            AsymmetricSignature::DeterministicEcdsa { hash_alg } => Ok(AsymmetricSignatureProto {
                variant: Some(asymmetric_signature::Variant::DeterministicEcdsa(
                    asymmetric_signature::DeterministicEcdsa {
                        hash_alg: Some(hash_alg.into()),
                    },
                )),
            }),
        }
    }
}

// AsymmetricEncryption algorithms: from protobuf to native
impl TryFrom<AsymmetricEncryptionProto> for AsymmetricEncryption {
    type Error = ResponseStatus;

    fn try_from(alg: AsymmetricEncryptionProto) -> Result<Self> {
        let alg_variant = alg.variant.ok_or_else(|| {
            error!("The AsymmetricSignature variant used is not supported.");
            ResponseStatus::InvalidEncoding
        })?;
        match alg_variant {
            asymmetric_encryption::Variant::RsaPkcs1v15Crypt(_) => {
                Ok(AsymmetricEncryption::RsaPkcs1v15Crypt)
            }
            asymmetric_encryption::Variant::RsaOaep(rsa_oaep) => {
                Ok(AsymmetricEncryption::RsaOaep {
                    hash_alg: HashProto::try_from(rsa_oaep.hash_alg)?.try_into()?,
                })
            }
        }
    }
}

// AsymmetricEncryption algorithms: from native to protobuf
impl TryFrom<AsymmetricEncryption> for AsymmetricEncryptionProto {
    type Error = ResponseStatus;

    fn try_from(alg: AsymmetricEncryption) -> Result<Self> {
        match alg {
            AsymmetricEncryption::RsaPkcs1v15Crypt => Ok(AsymmetricEncryptionProto {
                variant: Some(asymmetric_encryption::Variant::RsaPkcs1v15Crypt(
                    asymmetric_encryption::RsaPkcs1v15Crypt {},
                )),
            }),
            AsymmetricEncryption::RsaOaep { hash_alg } => Ok(AsymmetricEncryptionProto {
                variant: Some(asymmetric_encryption::Variant::RsaOaep(
                    asymmetric_encryption::RsaOaep {
                        hash_alg: hash_to_i32(hash_alg),
                    },
                )),
            }),
        }
    }
}

// RawKeyAgreement algorithms: from protobuf to native
impl TryFrom<RawKeyAgreementProto> for RawKeyAgreement {
    type Error = ResponseStatus;

    fn try_from(raw_key_agreement_val: RawKeyAgreementProto) -> Result<Self> {
        match raw_key_agreement_val {
            RawKeyAgreementProto::None => {
                error!("The None value of RawKeyAgreement enumeration is not allowed (mandatory field).");
                Err(ResponseStatus::InvalidEncoding)
            }
            RawKeyAgreementProto::Ffdh => Ok(RawKeyAgreement::Ffdh),
            RawKeyAgreementProto::Ecdh => Ok(RawKeyAgreement::Ecdh),
        }
    }
}

// RawKeyAgreement algorithms: from native to protobuf
pub fn raw_key_agreement_to_i32(raw_key_agreement: RawKeyAgreement) -> i32 {
    match raw_key_agreement {
        RawKeyAgreement::Ffdh => RawKeyAgreementProto::Ffdh.into(),
        RawKeyAgreement::Ecdh => RawKeyAgreementProto::Ecdh.into(),
    }
}

// RawKeyAgreement algorithms: from protobuf to native
pub fn i32_to_raw_key_agreement(raw_key_agreement_val: i32) -> Result<RawKeyAgreement> {
    let raw_key_agreement_alg: RawKeyAgreementProto = raw_key_agreement_val.try_into()?;
    raw_key_agreement_alg.try_into()
}

// KeyAgreement algorithms: from protobuf to native
impl TryFrom<KeyAgreementProto> for KeyAgreement {
    type Error = ResponseStatus;

    fn try_from(alg: KeyAgreementProto) -> Result<Self> {
        let alg_variant = alg.variant.ok_or_else(|| {
            error!("The KeyAgreement variant used is not supported.");
            ResponseStatus::InvalidEncoding
        })?;
        match alg_variant {
            key_agreement::Variant::Raw(raw) => Ok(KeyAgreement::Raw(RawKeyAgreementProto::try_from(raw)?.try_into()?)),
            key_agreement::Variant::WithKeyDerivation(with_key_derivation) => Ok(KeyAgreement::WithKeyDerivation {
                ka_alg: RawKeyAgreementProto::try_from(with_key_derivation.ka_alg)?.try_into()?,
                kdf_alg: with_key_derivation.kdf_alg.ok_or_else(|| {
                    error!("The kdf_alg field of key_agreement::WithKeyDerivation message is not set (mandatory field).");
                    ResponseStatus::InvalidEncoding
                })?.try_into()?,
            }),
        }
    }
}

// KeyAgreement algorithms: from native to protobuf
impl TryFrom<KeyAgreement> for KeyAgreementProto {
    type Error = ResponseStatus;

    fn try_from(alg: KeyAgreement) -> Result<Self> {
        match alg {
            KeyAgreement::Raw(raw_key_agreement) => Ok(KeyAgreementProto {
                variant: Some(key_agreement::Variant::Raw(raw_key_agreement_to_i32(
                    raw_key_agreement,
                ))),
            }),
            KeyAgreement::WithKeyDerivation { ka_alg, kdf_alg } => Ok(KeyAgreementProto {
                variant: Some(key_agreement::Variant::WithKeyDerivation(
                    key_agreement::WithKeyDerivation {
                        ka_alg: raw_key_agreement_to_i32(ka_alg),
                        kdf_alg: Some(kdf_alg.try_into()?),
                    },
                )),
            }),
        }
    }
}

// KeyDerivation algorithms: from protobuf to native
impl TryFrom<KeyDerivationProto> for KeyDerivation {
    type Error = ResponseStatus;

    fn try_from(alg: KeyDerivationProto) -> Result<Self> {
        let alg_variant = alg.variant.ok_or_else(|| {
            error!("The KeyDerivation variant used is not supported.");
            ResponseStatus::InvalidEncoding
        })?;
        match alg_variant {
            key_derivation::Variant::Hkdf(hkdf) => Ok(KeyDerivation::Hkdf {
                hash_alg: HashProto::try_from(hkdf.hash_alg)?.try_into()?,
            }),
            key_derivation::Variant::Tls12Prf(tls12_prf) => Ok(KeyDerivation::Tls12Prf {
                hash_alg: HashProto::try_from(tls12_prf.hash_alg)?.try_into()?,
            }),
            key_derivation::Variant::Tls12PskToMs(tls12_psk_to_ms) => {
                Ok(KeyDerivation::Tls12PskToMs {
                    hash_alg: HashProto::try_from(tls12_psk_to_ms.hash_alg)?.try_into()?,
                })
            }
        }
    }
}

// KeyDerivation algorithms: from native to protobuf
impl TryFrom<KeyDerivation> for KeyDerivationProto {
    type Error = ResponseStatus;

    fn try_from(alg: KeyDerivation) -> Result<Self> {
        match alg {
            KeyDerivation::Hkdf { hash_alg } => Ok(KeyDerivationProto {
                variant: Some(key_derivation::Variant::Hkdf(key_derivation::Hkdf {
                    hash_alg: hash_to_i32(hash_alg),
                })),
            }),
            KeyDerivation::Tls12Prf { hash_alg } => Ok(KeyDerivationProto {
                variant: Some(key_derivation::Variant::Tls12Prf(
                    key_derivation::Tls12Prf {
                        hash_alg: hash_to_i32(hash_alg),
                    },
                )),
            }),
            KeyDerivation::Tls12PskToMs { hash_alg } => Ok(KeyDerivationProto {
                variant: Some(key_derivation::Variant::Tls12PskToMs(
                    key_derivation::Tls12PskToMs {
                        hash_alg: hash_to_i32(hash_alg),
                    },
                )),
            }),
        }
    }
}

// Algorithm: from protobug to native
impl TryFrom<AlgorithmProto> for Algorithm {
    type Error = ResponseStatus;

    fn try_from(alg: AlgorithmProto) -> Result<Self> {
        let alg_variant = alg.variant.ok_or_else(|| {
            error!("The Algorithm variant used is not supported.");
            ResponseStatus::InvalidEncoding
        })?;
        match alg_variant {
            algorithm::Variant::None(_) => Ok(Algorithm::None),
            algorithm::Variant::Hash(hash) => {
                Ok(Algorithm::Hash(HashProto::try_from(hash)?.try_into()?))
            }
            algorithm::Variant::Mac(mac) => Ok(Algorithm::Mac(mac.try_into()?)),
            algorithm::Variant::Cipher(cipher) => Ok(Algorithm::Cipher(
                CipherProto::try_from(cipher)?.try_into()?,
            )),
            algorithm::Variant::Aead(aead) => Ok(Algorithm::Aead(aead.try_into()?)),
            algorithm::Variant::AsymmetricSignature(asymmetric_signature) => Ok(
                Algorithm::AsymmetricSignature(asymmetric_signature.try_into()?),
            ),
            algorithm::Variant::AsymmetricEncryption(asymmetric_encryption) => Ok(
                Algorithm::AsymmetricEncryption(asymmetric_encryption.try_into()?),
            ),
            algorithm::Variant::KeyAgreement(key_agreement) => {
                Ok(Algorithm::KeyAgreement(key_agreement.try_into()?))
            }
            algorithm::Variant::KeyDerivation(key_derivation) => {
                Ok(Algorithm::KeyDerivation(key_derivation.try_into()?))
            }
        }
    }
}

// Algorithm: from native to protobuf
impl TryFrom<Algorithm> for AlgorithmProto {
    type Error = ResponseStatus;

    fn try_from(alg: Algorithm) -> Result<Self> {
        match alg {
            Algorithm::None => Ok(AlgorithmProto {
                variant: Some(algorithm::Variant::None(NoneProto {})),
            }),
            Algorithm::Hash(hash) => Ok(AlgorithmProto {
                variant: Some(algorithm::Variant::Hash(hash_to_i32(hash))),
            }),
            Algorithm::Mac(mac) => Ok(AlgorithmProto {
                variant: Some(algorithm::Variant::Mac(mac.try_into()?)),
            }),
            Algorithm::Cipher(cipher) => Ok(AlgorithmProto {
                variant: Some(algorithm::Variant::Cipher(cipher_to_i32(cipher))),
            }),
            Algorithm::Aead(aead) => Ok(AlgorithmProto {
                variant: Some(algorithm::Variant::Aead(aead.try_into()?)),
            }),
            Algorithm::AsymmetricSignature(asymmetric_signature) => Ok(AlgorithmProto {
                variant: Some(algorithm::Variant::AsymmetricSignature(
                    asymmetric_signature.try_into()?,
                )),
            }),
            Algorithm::AsymmetricEncryption(asymmetric_encryption) => Ok(AlgorithmProto {
                variant: Some(algorithm::Variant::AsymmetricEncryption(
                    asymmetric_encryption.try_into()?,
                )),
            }),
            Algorithm::KeyAgreement(key_agreement) => Ok(AlgorithmProto {
                variant: Some(algorithm::Variant::KeyAgreement(key_agreement.try_into()?)),
            }),
            Algorithm::KeyDerivation(key_derivation) => Ok(AlgorithmProto {
                variant: Some(algorithm::Variant::KeyDerivation(
                    key_derivation.try_into()?,
                )),
            }),
        }
    }
}

#[cfg(test)]
mod test {
    #![allow(deprecated)]
    use super::super::generated_ops::psa_algorithm::{
        self as algorithm_proto,
        algorithm::asymmetric_signature::{sign_hash, SignHash as SignHashProto},
        Algorithm as AlgorithmProto,
    };
    use crate::operations::psa_algorithm::{Algorithm, AsymmetricSignature, Hash};
    use std::convert::TryInto;

    #[test]
    fn sign_algo_from_proto() {
        let proto_sign = algorithm_proto::Algorithm {
            variant: Some(algorithm_proto::algorithm::Variant::AsymmetricSignature(
                algorithm_proto::algorithm::AsymmetricSignature {
                    variant: Some(
                        algorithm_proto::algorithm::asymmetric_signature::Variant::RsaPkcs1v15Sign(
                            algorithm_proto::algorithm::asymmetric_signature::RsaPkcs1v15Sign {
                                hash_alg: Some(SignHashProto {
                                    variant: Some(sign_hash::Variant::Specific(
                                        algorithm_proto::algorithm::Hash::Sha1.into(),
                                    )),
                                }),
                            },
                        ),
                    ),
                },
            )),
        };

        let sign: Algorithm = proto_sign.try_into().unwrap();
        let sign_expected = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha1.into(),
        });

        assert_eq!(sign, sign_expected);
    }

    #[test]
    fn sign_algo_to_proto() {
        let sign = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha1.into(),
        });

        let proto_sign: AlgorithmProto = sign.try_into().unwrap();
        let proto_sign_expected = algorithm_proto::Algorithm {
            variant: Some(algorithm_proto::algorithm::Variant::AsymmetricSignature(
                algorithm_proto::algorithm::AsymmetricSignature {
                    variant: Some(
                        algorithm_proto::algorithm::asymmetric_signature::Variant::RsaPkcs1v15Sign(
                            algorithm_proto::algorithm::asymmetric_signature::RsaPkcs1v15Sign {
                                hash_alg: Some(SignHashProto {
                                    variant: Some(sign_hash::Variant::Specific(
                                        algorithm_proto::algorithm::Hash::Sha1.into(),
                                    )),
                                }),
                            },
                        ),
                    ),
                },
            )),
        };

        assert_eq!(proto_sign, proto_sign_expected);
    }
}
