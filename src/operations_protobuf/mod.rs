// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # Protobuf converter
//!
//! This module exposes the `ProtobufConverter` struct that implements the `Convert` trait.
mod convert_psa_algorithm;
mod convert_ping;
mod convert_psa_generate_key;
mod convert_psa_key_attributes;
mod convert_psa_import_key;
mod convert_psa_export_public_key;
mod convert_psa_export_key;
mod convert_psa_destroy_key;
mod convert_psa_sign_hash;
mod convert_psa_verify_hash;
mod convert_psa_sign_message;
mod convert_psa_verify_message;
mod convert_psa_hash_compute;
mod convert_psa_hash_compare;
mod convert_psa_mac_compute;
mod convert_psa_mac_compare;
mod convert_list_providers;
mod convert_list_opcodes;
mod convert_list_authenticators;
mod convert_list_keys;
mod convert_list_clients;
mod convert_delete_client;
mod convert_psa_asymmetric_encrypt;
mod convert_psa_asymmetric_decrypt;
mod convert_psa_aead_encrypt;
mod convert_psa_aead_decrypt;
mod convert_psa_cipher_encrypt;
mod convert_psa_cipher_decrypt;
mod convert_psa_generate_random;
mod convert_psa_raw_key_agreement;
mod convert_can_do_crypto;
mod convert_attest_key;
mod convert_prepare_key_attestation;

#[rustfmt::skip]
#[allow(unused_qualifications, missing_copy_implementations, clippy::pedantic, clippy::module_inception, clippy::upper_case_acronyms, clippy::enum_variant_names)]
mod generated_ops;

use crate::operations::{Convert, NativeOperation, NativeResult};
use crate::requests::{
    request::RequestBody, response::ResponseBody, BodyType, Opcode, ResponseStatus, Result,
};
use generated_ops::attest_key as attest_key_proto;
use generated_ops::can_do_crypto as can_do_crypto_proto;
use generated_ops::delete_client as delete_client_proto;
use generated_ops::list_authenticators as list_authenticators_proto;
use generated_ops::list_clients as list_clients_proto;
use generated_ops::list_keys as list_keys_proto;
use generated_ops::list_opcodes as list_opcodes_proto;
use generated_ops::list_providers as list_providers_proto;
use generated_ops::ping as ping_proto;
use generated_ops::prepare_key_attestation as prepare_key_attestation_proto;
use generated_ops::psa_aead_decrypt as psa_aead_decrypt_proto;
use generated_ops::psa_aead_encrypt as psa_aead_encrypt_proto;
use generated_ops::psa_asymmetric_decrypt as psa_asymmetric_decrypt_proto;
use generated_ops::psa_asymmetric_encrypt as psa_asymmetric_encrypt_proto;
use generated_ops::psa_cipher_decrypt as psa_cipher_decrypt_proto;
use generated_ops::psa_cipher_encrypt as psa_cipher_encrypt_proto;
use generated_ops::psa_destroy_key as psa_destroy_key_proto;
use generated_ops::psa_export_key as psa_export_key_proto;
use generated_ops::psa_export_public_key as psa_export_public_key_proto;
use generated_ops::psa_generate_key as psa_generate_key_proto;
use generated_ops::psa_generate_random as psa_generate_random_proto;
use generated_ops::psa_hash_compare as psa_hash_compare_proto;
use generated_ops::psa_hash_compute as psa_hash_compute_proto;
use generated_ops::psa_mac_verify as psa_mac_compare_proto;
use generated_ops::psa_mac_compute as psa_mac_compute_proto;
use generated_ops::psa_import_key as psa_import_key_proto;
use generated_ops::psa_raw_key_agreement as psa_raw_key_agreement_proto;
use generated_ops::psa_sign_hash as psa_sign_hash_proto;
use generated_ops::psa_sign_message as psa_sign_message_proto;
use generated_ops::psa_verify_hash as psa_verify_hash_proto;
use generated_ops::psa_verify_message as psa_verify_message_proto;
use generated_ops::ClearProtoMessage;
use prost::Message;
use std::convert::TryInto;

macro_rules! wire_to_native {
    ($body:expr, $proto_type:ty) => {{
        let mut proto: $proto_type = Default::default();
        if proto.merge($body).is_err() {
            return Err(ResponseStatus::DeserializingBodyFailed);
        }
        proto.try_into()?
    }};
}

macro_rules! native_to_wire {
    ($native_msg:expr, $proto_type:ty) => {{
        let mut proto: $proto_type = $native_msg.try_into()?;
        let mut bytes = Vec::new();
        if proto.encode(&mut bytes).is_err() {
            proto.clear_message();
            return Err(ResponseStatus::SerializingBodyFailed);
        }
        proto.clear_message();
        bytes
    }};
}

/// Implementation for a converter between protobuf-encoded bodies and native
/// objects.
#[derive(Copy, Clone, Debug)]
pub struct ProtobufConverter;

impl Convert for ProtobufConverter {
    fn body_type(&self) -> BodyType {
        BodyType::Protobuf
    }

    fn body_to_operation(&self, body: RequestBody, opcode: Opcode) -> Result<NativeOperation> {
        match opcode {
            Opcode::ListProviders => Ok(NativeOperation::ListProviders(wire_to_native!(
                body.bytes(),
                list_providers_proto::Operation
            ))),
            Opcode::ListOpcodes => Ok(NativeOperation::ListOpcodes(wire_to_native!(
                body.bytes(),
                list_opcodes_proto::Operation
            ))),
            Opcode::ListAuthenticators => Ok(NativeOperation::ListAuthenticators(wire_to_native!(
                body.bytes(),
                list_authenticators_proto::Operation
            ))),
            Opcode::ListKeys => Ok(NativeOperation::ListKeys(wire_to_native!(
                body.bytes(),
                list_keys_proto::Operation
            ))),
            Opcode::ListClients => Ok(NativeOperation::ListClients(wire_to_native!(
                body.bytes(),
                list_clients_proto::Operation
            ))),
            Opcode::DeleteClient => Ok(NativeOperation::DeleteClient(wire_to_native!(
                body.bytes(),
                delete_client_proto::Operation
            ))),
            Opcode::Ping => Ok(NativeOperation::Ping(wire_to_native!(
                body.bytes(),
                ping_proto::Operation
            ))),
            Opcode::PsaGenerateKey => Ok(NativeOperation::PsaGenerateKey(wire_to_native!(
                body.bytes(),
                psa_generate_key_proto::Operation
            ))),
            Opcode::PsaImportKey => Ok(NativeOperation::PsaImportKey(wire_to_native!(
                body.bytes(),
                psa_import_key_proto::Operation
            ))),
            Opcode::PsaExportPublicKey => Ok(NativeOperation::PsaExportPublicKey(wire_to_native!(
                body.bytes(),
                psa_export_public_key_proto::Operation
            ))),
            Opcode::PsaExportKey => Ok(NativeOperation::PsaExportKey(wire_to_native!(
                body.bytes(),
                psa_export_key_proto::Operation
            ))),
            Opcode::PsaDestroyKey => Ok(NativeOperation::PsaDestroyKey(wire_to_native!(
                body.bytes(),
                psa_destroy_key_proto::Operation
            ))),
            Opcode::PsaSignHash => Ok(NativeOperation::PsaSignHash(wire_to_native!(
                body.bytes(),
                psa_sign_hash_proto::Operation
            ))),
            Opcode::PsaVerifyHash => Ok(NativeOperation::PsaVerifyHash(wire_to_native!(
                body.bytes(),
                psa_verify_hash_proto::Operation
            ))),
            Opcode::PsaSignMessage => Ok(NativeOperation::PsaSignMessage(wire_to_native!(
                body.bytes(),
                psa_sign_message_proto::Operation
            ))),
            Opcode::PsaVerifyMessage => Ok(NativeOperation::PsaVerifyMessage(wire_to_native!(
                body.bytes(),
                psa_verify_message_proto::Operation
            ))),
            Opcode::PsaAsymmetricEncrypt => Ok(NativeOperation::PsaAsymmetricEncrypt(
                wire_to_native!(body.bytes(), psa_asymmetric_encrypt_proto::Operation),
            )),
            Opcode::PsaAsymmetricDecrypt => Ok(NativeOperation::PsaAsymmetricDecrypt(
                wire_to_native!(body.bytes(), psa_asymmetric_decrypt_proto::Operation),
            )),
            Opcode::PsaAeadEncrypt => Ok(NativeOperation::PsaAeadEncrypt(wire_to_native!(
                body.bytes(),
                psa_aead_encrypt_proto::Operation
            ))),
            Opcode::PsaAeadDecrypt => Ok(NativeOperation::PsaAeadDecrypt(wire_to_native!(
                body.bytes(),
                psa_aead_decrypt_proto::Operation
            ))),
            Opcode::PsaCipherEncrypt => Ok(NativeOperation::PsaCipherEncrypt(wire_to_native!(
                body.bytes(),
                psa_cipher_encrypt_proto::Operation
            ))),
            Opcode::PsaCipherDecrypt => Ok(NativeOperation::PsaCipherDecrypt(wire_to_native!(
                body.bytes(),
                psa_cipher_decrypt_proto::Operation
            ))),
            Opcode::PsaGenerateRandom => Ok(NativeOperation::PsaGenerateRandom(wire_to_native!(
                body.bytes(),
                psa_generate_random_proto::Operation
            ))),
            Opcode::PsaHashCompare => Ok(NativeOperation::PsaHashCompare(wire_to_native!(
                body.bytes(),
                psa_hash_compare_proto::Operation
            ))),
            Opcode::PsaHashCompute => Ok(NativeOperation::PsaHashCompute(wire_to_native!(
                body.bytes(),
                psa_hash_compute_proto::Operation
            ))),
            Opcode::PsaMacCompare => Ok(NativeOperation::PsaMacCompare(wire_to_native!(
                body.bytes(),
                psa_mac_compare_proto::Operation
            ))),
            Opcode::PsaMacCompute => Ok(NativeOperation::PsaMacCompute(wire_to_native!(
                body.bytes(),
                psa_mac_compute_proto::Operation
            ))),
            Opcode::PsaRawKeyAgreement => Ok(NativeOperation::PsaRawKeyAgreement(wire_to_native!(
                body.bytes(),
                psa_raw_key_agreement_proto::Operation
            ))),
            Opcode::CanDoCrypto => Ok(NativeOperation::CanDoCrypto(wire_to_native!(
                body.bytes(),
                can_do_crypto_proto::Operation
            ))),
            Opcode::AttestKey => Ok(NativeOperation::AttestKey(wire_to_native!(
                body.bytes(),
                attest_key_proto::Operation
            ))),
            Opcode::PrepareKeyAttestation => Ok(NativeOperation::PrepareKeyAttestation(
                wire_to_native!(body.bytes(), prepare_key_attestation_proto::Operation),
            )),
        }
    }

    fn operation_to_body(&self, operation: NativeOperation) -> Result<RequestBody> {
        match operation {
            NativeOperation::ListProviders(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, list_providers_proto::Operation),
            )),
            NativeOperation::ListOpcodes(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, list_opcodes_proto::Operation),
            )),
            NativeOperation::ListAuthenticators(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, list_authenticators_proto::Operation),
            )),
            NativeOperation::ListKeys(operation) => Ok(RequestBody::from_bytes(native_to_wire!(
                operation,
                list_keys_proto::Operation
            ))),
            NativeOperation::ListClients(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, list_clients_proto::Operation),
            )),
            NativeOperation::DeleteClient(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, delete_client_proto::Operation),
            )),
            NativeOperation::Ping(operation) => Ok(RequestBody::from_bytes(native_to_wire!(
                operation,
                ping_proto::Operation
            ))),
            NativeOperation::PsaGenerateKey(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_generate_key_proto::Operation),
            )),
            NativeOperation::PsaImportKey(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_import_key_proto::Operation),
            )),
            NativeOperation::PsaExportPublicKey(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_export_public_key_proto::Operation),
            )),
            NativeOperation::PsaExportKey(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_export_key_proto::Operation),
            )),
            NativeOperation::PsaDestroyKey(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_destroy_key_proto::Operation),
            )),
            NativeOperation::PsaSignHash(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_sign_hash_proto::Operation),
            )),
            NativeOperation::PsaVerifyHash(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_verify_hash_proto::Operation),
            )),
            NativeOperation::PsaSignMessage(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_sign_message_proto::Operation),
            )),
            NativeOperation::PsaVerifyMessage(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_verify_message_proto::Operation),
            )),
            NativeOperation::PsaAsymmetricEncrypt(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_asymmetric_encrypt_proto::Operation),
            )),
            NativeOperation::PsaAsymmetricDecrypt(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_asymmetric_decrypt_proto::Operation),
            )),
            NativeOperation::PsaAeadEncrypt(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_aead_encrypt_proto::Operation),
            )),
            NativeOperation::PsaAeadDecrypt(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_aead_decrypt_proto::Operation),
            )),
            NativeOperation::PsaCipherEncrypt(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_cipher_encrypt_proto::Operation),
            )),
            NativeOperation::PsaCipherDecrypt(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_cipher_decrypt_proto::Operation),
            )),
            NativeOperation::PsaGenerateRandom(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_generate_random_proto::Operation),
            )),
            NativeOperation::PsaHashCompare(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_hash_compare_proto::Operation),
            )),
            NativeOperation::PsaHashCompute(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_hash_compute_proto::Operation),
            )),
            NativeOperation::PsaMacCompare(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_mac_compare_proto::Operation),
            )),
            NativeOperation::PsaMacCompute(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_mac_compute_proto::Operation),
            )),
            NativeOperation::PsaRawKeyAgreement(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_raw_key_agreement_proto::Operation),
            )),
            NativeOperation::CanDoCrypto(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, can_do_crypto_proto::Operation),
            )),
            NativeOperation::AttestKey(operation) => Ok(RequestBody::from_bytes(native_to_wire!(
                operation,
                attest_key_proto::Operation
            ))),
            NativeOperation::PrepareKeyAttestation(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, prepare_key_attestation_proto::Operation),
            )),
        }
    }

    fn body_to_result(&self, body: ResponseBody, opcode: Opcode) -> Result<NativeResult> {
        match opcode {
            Opcode::ListProviders => Ok(NativeResult::ListProviders(wire_to_native!(
                body.bytes(),
                list_providers_proto::Result
            ))),
            Opcode::ListOpcodes => Ok(NativeResult::ListOpcodes(wire_to_native!(
                body.bytes(),
                list_opcodes_proto::Result
            ))),
            Opcode::ListAuthenticators => Ok(NativeResult::ListAuthenticators(wire_to_native!(
                body.bytes(),
                list_authenticators_proto::Result
            ))),
            Opcode::ListKeys => Ok(NativeResult::ListKeys(wire_to_native!(
                body.bytes(),
                list_keys_proto::Result
            ))),
            Opcode::ListClients => Ok(NativeResult::ListClients(wire_to_native!(
                body.bytes(),
                list_clients_proto::Result
            ))),
            Opcode::DeleteClient => Ok(NativeResult::DeleteClient(wire_to_native!(
                body.bytes(),
                delete_client_proto::Result
            ))),
            Opcode::Ping => Ok(NativeResult::Ping(wire_to_native!(
                body.bytes(),
                ping_proto::Result
            ))),
            Opcode::PsaGenerateKey => Ok(NativeResult::PsaGenerateKey(wire_to_native!(
                body.bytes(),
                psa_generate_key_proto::Result
            ))),
            Opcode::PsaImportKey => Ok(NativeResult::PsaImportKey(wire_to_native!(
                body.bytes(),
                psa_import_key_proto::Result
            ))),
            Opcode::PsaExportPublicKey => Ok(NativeResult::PsaExportPublicKey(wire_to_native!(
                body.bytes(),
                psa_export_public_key_proto::Result
            ))),
            Opcode::PsaExportKey => Ok(NativeResult::PsaExportKey(wire_to_native!(
                body.bytes(),
                psa_export_key_proto::Result
            ))),
            Opcode::PsaDestroyKey => Ok(NativeResult::PsaDestroyKey(wire_to_native!(
                body.bytes(),
                psa_destroy_key_proto::Result
            ))),
            Opcode::PsaSignHash => Ok(NativeResult::PsaSignHash(wire_to_native!(
                body.bytes(),
                psa_sign_hash_proto::Result
            ))),
            Opcode::PsaVerifyHash => Ok(NativeResult::PsaVerifyHash(wire_to_native!(
                body.bytes(),
                psa_verify_hash_proto::Result
            ))),
            Opcode::PsaSignMessage => Ok(NativeResult::PsaSignMessage(wire_to_native!(
                body.bytes(),
                psa_sign_message_proto::Result
            ))),
            Opcode::PsaVerifyMessage => Ok(NativeResult::PsaVerifyMessage(wire_to_native!(
                body.bytes(),
                psa_verify_message_proto::Result
            ))),
            Opcode::PsaAsymmetricEncrypt => Ok(NativeResult::PsaAsymmetricEncrypt(
                wire_to_native!(body.bytes(), psa_asymmetric_encrypt_proto::Result),
            )),
            Opcode::PsaAsymmetricDecrypt => Ok(NativeResult::PsaAsymmetricDecrypt(
                wire_to_native!(body.bytes(), psa_asymmetric_decrypt_proto::Result),
            )),
            Opcode::PsaAeadEncrypt => Ok(NativeResult::PsaAeadEncrypt(wire_to_native!(
                body.bytes(),
                psa_aead_encrypt_proto::Result
            ))),
            Opcode::PsaAeadDecrypt => Ok(NativeResult::PsaAeadDecrypt(wire_to_native!(
                body.bytes(),
                psa_aead_decrypt_proto::Result
            ))),
            Opcode::PsaCipherEncrypt => Ok(NativeResult::PsaCipherEncrypt(wire_to_native!(
                body.bytes(),
                psa_cipher_encrypt_proto::Result
            ))),
            Opcode::PsaCipherDecrypt => Ok(NativeResult::PsaCipherDecrypt(wire_to_native!(
                body.bytes(),
                psa_cipher_decrypt_proto::Result
            ))),
            Opcode::PsaGenerateRandom => Ok(NativeResult::PsaGenerateRandom(wire_to_native!(
                body.bytes(),
                psa_generate_random_proto::Result
            ))),
            Opcode::PsaHashCompare => Ok(NativeResult::PsaHashCompare(wire_to_native!(
                body.bytes(),
                psa_hash_compare_proto::Result
            ))),
            Opcode::PsaHashCompute => Ok(NativeResult::PsaHashCompute(wire_to_native!(
                body.bytes(),
                psa_hash_compute_proto::Result
            ))),
            Opcode::PsaMacCompare => Ok(NativeResult::PsaMacCompare(wire_to_native!(
                body.bytes(),
                psa_mac_compare_proto::Result
            ))),
            Opcode::PsaMacCompute => Ok(NativeResult::PsaMacCompute(wire_to_native!(
                body.bytes(),
                psa_mac_compute_proto::Result
            ))),
            Opcode::PsaRawKeyAgreement => Ok(NativeResult::PsaRawKeyAgreement(wire_to_native!(
                body.bytes(),
                psa_raw_key_agreement_proto::Result
            ))),
            Opcode::CanDoCrypto => Ok(NativeResult::CanDoCrypto(wire_to_native!(
                body.bytes(),
                can_do_crypto_proto::Result
            ))),
            Opcode::AttestKey => Ok(NativeResult::AttestKey(wire_to_native!(
                body.bytes(),
                attest_key_proto::Result
            ))),
            Opcode::PrepareKeyAttestation => Ok(NativeResult::PrepareKeyAttestation(
                wire_to_native!(body.bytes(), prepare_key_attestation_proto::Result),
            )),
        }
    }

    fn result_to_body(&self, result: NativeResult) -> Result<ResponseBody> {
        match result {
            NativeResult::ListProviders(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                list_providers_proto::Result
            ))),
            NativeResult::ListOpcodes(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                list_opcodes_proto::Result
            ))),
            NativeResult::ListAuthenticators(result) => Ok(ResponseBody::from_bytes(
                native_to_wire!(result, list_authenticators_proto::Result),
            )),
            NativeResult::ListKeys(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                list_keys_proto::Result
            ))),
            NativeResult::ListClients(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                list_clients_proto::Result
            ))),
            NativeResult::DeleteClient(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                delete_client_proto::Result
            ))),
            NativeResult::Ping(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                ping_proto::Result
            ))),
            NativeResult::PsaGenerateKey(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                psa_generate_key_proto::Result
            ))),
            NativeResult::PsaImportKey(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                psa_import_key_proto::Result
            ))),
            NativeResult::PsaExportPublicKey(result) => Ok(ResponseBody::from_bytes(
                native_to_wire!(result, psa_export_public_key_proto::Result),
            )),
            NativeResult::PsaExportKey(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                psa_export_key_proto::Result
            ))),
            NativeResult::PsaDestroyKey(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                psa_destroy_key_proto::Result
            ))),
            NativeResult::PsaSignHash(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                psa_sign_hash_proto::Result
            ))),
            NativeResult::PsaVerifyHash(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                psa_verify_hash_proto::Result
            ))),
            NativeResult::PsaSignMessage(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                psa_sign_message_proto::Result
            ))),
            NativeResult::PsaVerifyMessage(result) => Ok(ResponseBody::from_bytes(
                native_to_wire!(result, psa_verify_message_proto::Result),
            )),
            NativeResult::PsaAsymmetricEncrypt(result) => Ok(ResponseBody::from_bytes(
                native_to_wire!(result, psa_asymmetric_encrypt_proto::Result),
            )),
            NativeResult::PsaAsymmetricDecrypt(result) => Ok(ResponseBody::from_bytes(
                native_to_wire!(result, psa_asymmetric_decrypt_proto::Result),
            )),
            NativeResult::PsaAeadEncrypt(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                psa_aead_encrypt_proto::Result
            ))),
            NativeResult::PsaAeadDecrypt(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                psa_aead_decrypt_proto::Result
            ))),
            NativeResult::PsaCipherEncrypt(result) => Ok(ResponseBody::from_bytes(
                native_to_wire!(result, psa_cipher_encrypt_proto::Result),
            )),
            NativeResult::PsaCipherDecrypt(result) => Ok(ResponseBody::from_bytes(
                native_to_wire!(result, psa_cipher_decrypt_proto::Result),
            )),
            NativeResult::PsaGenerateRandom(result) => Ok(ResponseBody::from_bytes(
                native_to_wire!(result, psa_generate_random_proto::Result),
            )),
            NativeResult::PsaHashCompare(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                psa_hash_compare_proto::Result
            ))),
            NativeResult::PsaHashCompute(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                psa_hash_compute_proto::Result
            ))),
            NativeResult::PsaMacCompare(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                psa_mac_compare_proto::Result
            ))),
            NativeResult::PsaMacCompute(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                psa_mac_compute_proto::Result
            ))),
            NativeResult::PsaRawKeyAgreement(result) => Ok(ResponseBody::from_bytes(
                native_to_wire!(result, psa_raw_key_agreement_proto::Result),
            )),
            NativeResult::CanDoCrypto(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                can_do_crypto_proto::Result
            ))),
            NativeResult::AttestKey(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                attest_key_proto::Result
            ))),
            NativeResult::PrepareKeyAttestation(result) => Ok(ResponseBody::from_bytes(
                native_to_wire!(result, prepare_key_attestation_proto::Result),
            )),
        }
    }
}
