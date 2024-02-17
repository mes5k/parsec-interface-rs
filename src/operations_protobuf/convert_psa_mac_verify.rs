// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//use super::convert_psa_algorithm;
use super::generated_ops::psa_mac_verify::{Operation as OperationProto, Result as ResultProto};
use crate::operations::psa_mac_verify::{Operation, Result};
use crate::requests::ResponseStatus;
use log::error;
use std::convert::{TryFrom, TryInto};

impl TryFrom<OperationProto> for Operation {
    type Error = ResponseStatus;

    fn try_from(proto_op: OperationProto) -> std::result::Result<Self, Self::Error> {
        let key_name = proto_op.key_name.into();
        let alg = proto_op
                .alg
                .ok_or_else(|| {
                    error!("The alg field of PsaMacVerify::Operation message is not set (mandatory field).");
                    ResponseStatus::InvalidEncoding
                })?
                .try_into()?;
        let mac = proto_op.mac.into();
        let input = proto_op.input.into();
        Ok(Operation {
            key_name,
            alg,
            input,
            mac,
        })
    }
}

impl TryFrom<Operation> for OperationProto {
    type Error = ResponseStatus;

    fn try_from(op: Operation) -> std::result::Result<Self, Self::Error> {
        let alg = Some(op.alg.try_into()?);
        Ok(OperationProto {
            key_name: op.key_name.to_string(),
            mac: op.mac.to_vec(),
            input: op.input.to_vec(),
            alg,
        })
    }
}

impl TryFrom<ResultProto> for Result {
    type Error = ResponseStatus;

    fn try_from(_proto_result: ResultProto) -> std::result::Result<Self, Self::Error> {
        Ok(Default::default())
    }
}

impl TryFrom<Result> for ResultProto {
    type Error = ResponseStatus;

    fn try_from(_result: Result) -> std::result::Result<Self, Self::Error> {
        Ok(ResultProto {})
    }
}

#[cfg(test)]
mod test {
    use super::super::generated_ops::psa_algorithm as algorithm_proto;
    use super::super::generated_ops::psa_mac_verify;
    use super::super::generated_ops::psa_mac_verify::{
        Operation as OperationProto, Result as ResultProto,
    };
    use super::super::{Convert, ProtobufConverter};
    use crate::operations::psa_mac_verify::{Operation, Result};
    use crate::operations::NativeOperation;
    use crate::requests::{request::RequestBody, response::ResponseBody, Opcode};
    use std::convert::TryInto;
    use zeroize::Zeroizing;

    static CONVERTER: ProtobufConverter = ProtobufConverter {};

    fn make_mac() -> Option<algorithm_proto::algorithm::Mac> {
        Some(algorithm_proto::algorithm::Mac {
            variant: Some(algorithm_proto::algorithm::mac::Variant::FullLength(
                algorithm_proto::algorithm::mac::FullLength {
                    variant: Some(algorithm_proto::algorithm::mac::full_length::Variant::Hmac(
                        algorithm_proto::algorithm::mac::full_length::Hmac {
                            hash_alg: algorithm_proto::algorithm::Hash::Sha256.into(),
                        },
                    )),
                },
            )),
        })
    }

    #[test]
    fn mac_verify_proto_to_op() {
        let key_name = "test".to_string();
        let input = vec![0x11, 0x22, 0x33];
        let mac = vec![0x44, 0x55, 0x66];
        let alg = make_mac();

        let mut proto: OperationProto = Default::default();
        proto.key_name = key_name.clone();
        proto.input = input.clone();
        proto.mac = mac.clone();
        proto.alg = alg.clone();

        let op: Operation = proto.try_into().expect("Failed to convert");

        assert_eq!(op.key_name, key_name);
        assert_eq!(op.input, input.into());
        assert_eq!(op.mac, mac.into());
        assert_eq!(op.alg, alg.unwrap().try_into().unwrap());
    }

    #[test]
    fn mac_verify_bad_proto_to_op() {
        let key_name = "test".to_string();
        let input = vec![0x11, 0x22, 0x33];
        let mac = vec![0x44, 0x55, 0x66];

        let mut proto: OperationProto = Default::default();
        proto.key_name = key_name.clone();
        proto.input = input.clone();
        proto.mac = mac.clone();
        proto.alg = None;

        assert!(<psa_mac_verify::Operation as TryInto<Operation>>::try_into(proto).is_err());
    }

    #[test]
    fn mac_verify_op_to_proto() {
        let key_name = "test".to_string();
        let input = vec![0x11, 0x22, 0x33];
        let mac = vec![0x44, 0x55, 0x66];
        let alg = make_mac();

        let op = Operation {
            key_name: key_name.clone().into(),
            alg: alg.unwrap().try_into().unwrap(),
            input: input.clone().into(),
            mac: mac.clone().into(),
        };

        let proto: OperationProto = op.try_into().expect("Failed to convert");

        assert_eq!(proto.input, input);
        assert_eq!(proto.mac, mac);
        assert_eq!(proto.key_name, key_name);
    }

    #[test]
    fn mac_verify_proto_to_resp() {
        let proto = ResultProto {};
        let _res: Result = proto.try_into().expect("Failed conversion");
    }

    #[test]
    fn mac_verify_resp_to_proto() {
        let res = Result {};
        let _proto: ResultProto = res.try_into().expect("Failed conversion");
    }

    #[test]
    fn op_hash_compare_e2e() {
        let alg = make_mac();
        let key_name = "test".to_string();
        let op = Operation {
            key_name: key_name.clone().into(),
            input: Zeroizing::new(vec![0x11, 0x22, 0x33]),
            mac: Zeroizing::new(vec![0x44, 0x55, 0x66]),
            alg: alg.unwrap().try_into().unwrap(),
        };
        let body = CONVERTER
            .operation_to_body(NativeOperation::PsaMacVerify(op))
            .expect("Failed to convert request");

        assert!(CONVERTER
            .body_to_operation(body, Opcode::PsaMacVerify)
            .is_ok());
    }

    #[test]
    fn result_from_mangled_resp_body() {
        let resp_body =
            ResponseBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert!(CONVERTER
            .body_to_result(resp_body, Opcode::PsaMacVerify)
            .is_err());
    }

    #[test]
    fn op_from_mangled_req_body() {
        let req_body =
            RequestBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::PsaMacVerify)
            .is_err());
    }
}
