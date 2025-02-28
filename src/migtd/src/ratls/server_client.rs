// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::{string::ToString, vec::Vec};
use crypto::{
    ecdsa::{ecdsa_verify, EcdsaPk},
    hash::digest_sha384,
    tls::{SecureChannel, TlsConfig},
    x509::{
        AlgorithmIdentifier, Any, BitString, Certificate, CertificateBuilder, Decodable, Encodable,
        ExtendedKeyUsage, Extension, Extensions, Tag,
    },
    Error as CryptoError, Result as CryptoResult,
};
use td_payload::println;
use log::error;
use policy::PolicyError;
use rust_std_stub::io::{Read, Write};

use super::*;
use crate::{event_log::get_event_log, mig_policy};

const PUBLIC_KEY_HASH_SIZE: usize = 48;

type Result<T> = core::result::Result<T, RatlsError>;

pub fn server<T: Read + Write>(stream: T) -> Result<SecureChannel<T>> {
    println!("Inside ratls::server");
    let signing_key = EcdsaPk::new()?;
    println!("Created signing key");
    let (certs, quote) = gen_cert(&signing_key)?;
    println!("Generated cert");
    let certs = vec![certs];

    // Server verifies certificate of client
    let config = TlsConfig::new(certs, signing_key, verify_client_cert, quote)?;
    println!("Created config");
    config.tls_server(stream).map_err(|e| e.into())
}

pub fn client<T: Read + Write>(stream: T) -> Result<SecureChannel<T>> {
    let signing_key = EcdsaPk::new()?;
    println!("Generating cert");
    let (certs, quote) = gen_cert(&signing_key)?;
    println!("Generated cert");
    let certs = vec![certs];

    // Client verifies certificate of server
    println!("Creating new TLS config");
    let config = TlsConfig::new(certs, signing_key, verify_server_cert, quote)?;
    println!("Calling config.tls_client");
    config.tls_client(stream).map_err(|e| e.into())
}

fn gen_cert(signing_key: &EcdsaPk) -> Result<(Vec<u8>, Vec<u8>)> {
    let algorithm = AlgorithmIdentifier {
        algorithm: ID_EC_PUBKEY_OID,
        parameters: Some(Any::new(Tag::ObjectIdentifier, SECP384R1_OID.as_bytes())?),
    };
    let eku = vec![SERVER_AUTH, CLIENT_AUTH, MIGTD_EXTENDED_KEY_USAGE].to_vec()?;

    let pub_key = signing_key.public_key()?;
    let sig_alg = AlgorithmIdentifier {
        algorithm: ID_EC_SIG_OID,
        parameters: None,
    };
    let key_usage = BitString::from_bytes(&[0x80])?.to_vec()?;
    println!("gen_quote");
    let quote = gen_quote(&pub_key)?;
    println!("get_event_log");
    let event_log = get_event_log().ok_or(RatlsError::InvalidEventlog)?;
    println!("build x509 cert");
    let mut x509_certificate = CertificateBuilder::new(sig_alg, algorithm, &pub_key)?
        // 1970-01-01T00:00:00Z
        .set_not_before(core::time::Duration::new(0, 0))?
        // 9999-12-31T23:59:59Z
        .set_not_after(core::time::Duration::new(253402300799, 0))?
        .add_extension(Extension::new(
            KEY_USAGE_EXTENSION,
            Some(true),
            Some(key_usage.as_slice()),
        )?)?
        .add_extension(Extension::new(
            EXTENDED_KEY_USAGE,
            Some(false),
            Some(eku.as_slice()),
        )?)?
        .add_extension(Extension::new(
            EXTNID_MIGTD_QUOTE_REPORT,
            Some(false),
            Some(quote.as_slice()),
        )?)?
        .add_extension(Extension::new(
            EXTNID_MIGTD_EVENT_LOG,
            Some(false),
            Some(event_log),
        )?)?
        .build();
    let tbs = x509_certificate.tbs_certificate.to_vec()?;
    let signature = signing_key.sign(&tbs)?;
    x509_certificate.set_signature(&signature)?;

    Ok((x509_certificate.to_vec().map_err(CryptoError::from)?, quote))
}

fn gen_quote(public_key: &[u8]) -> Result<Vec<u8>> {
    let hash = digest_sha384(public_key)?;

    // Generate the TD Report that contains the public key hash as nonce
    let mut additional_data = [0u8; 64];
    additional_data[..hash.len()].copy_from_slice(hash.as_ref());
    println!("Calling tdcall_report");
    let td_report = tdx_tdcall::tdreport::tdcall_report(&additional_data)?;
    println!("Got td report");
    #[cfg(not(feature = "test_disable_ra_and_accept_all"))]
    {
        println!("Getting quote");
        let r = attestation::get_quote(td_report.as_bytes());
        println!("Got quote yayyyy: {:?}", r);
        if r.is_err() {
            println!("Get Quote failed :(");
            return Err(RatlsError::GetQuote);
        }
        return Ok(r.unwrap());
    }

    // Only for test purpose to bypass the remote attestation
    #[cfg(feature = "test_disable_ra_and_accept_all")]
    Ok(td_report.as_bytes().to_vec())
}

fn verify_server_cert(cert: &[u8], quote: &[u8]) -> core::result::Result<(), CryptoError> {
    verify_peer_cert(true, cert, quote)
}

fn verify_client_cert(cert: &[u8], quote: &[u8]) -> core::result::Result<(), CryptoError> {
    verify_peer_cert(false, cert, quote)
}

#[cfg(not(feature = "test_disable_ra_and_accept_all"))]
fn verify_peer_cert(
    is_client: bool,
    cert: &[u8],
    quote_local: &[u8],
) -> core::result::Result<(), CryptoError> {
    let verified_report_local = attestation::verify_quote(quote_local)
        .map_err(|_| CryptoError::TlsVerifyPeerCert(MUTUAL_ATTESTATION_ERROR.to_string()))?;
    let cert = Certificate::from_der(cert).map_err(|_| CryptoError::ParseCertificate)?;

    let extensions = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or(CryptoError::ParseCertificate)?;

    let (quote_report, event_log) =
        parse_extensions(extensions).ok_or(CryptoError::ParseCertificate)?;

    if let Ok(verified_report_peer) = attestation::verify_quote(quote_report) {
        verify_signature(&cert, verified_report_peer.as_slice())?;

        // MigTD-src acts as TLS client
        let policy_check_result = mig_policy::authenticate_policy(
            is_client,
            verified_report_local.as_slice(),
            verified_report_peer.as_slice(),
            event_log,
        );

        if let Err(e) = &policy_check_result {
            error!("Policy check failed, below is the detail information:\n");
            error!("{:x?}\n", e);
        }

        return policy_check_result.map_err(|e| match e {
            PolicyError::InvalidPolicy => {
                CryptoError::TlsVerifyPeerCert(INVALID_MIG_POLICY_ERROR.to_string())
            }
            _ => CryptoError::TlsVerifyPeerCert(MIG_POLICY_UNSATISFIED_ERROR.to_string()),
        });
    } else {
        Err(CryptoError::TlsVerifyPeerCert(
            MUTUAL_ATTESTATION_ERROR.to_string(),
        ))
    }
}

// Only for test to bypass the quote verification
#[cfg(feature = "test_disable_ra_and_accept_all")]
fn verify_peer_cert(
    _is_client: bool,
    cert: &[u8],
    _quote_local: &[u8],
) -> core::result::Result<(), CryptoError> {
    let cert = Certificate::from_der(cert).map_err(|_| CryptoError::ParseCertificate)?;

    let extensions = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or(CryptoError::ParseCertificate)?;
    let _ = parse_extensions(extensions).ok_or(CryptoError::ParseCertificate)?;

    // As the remote attestation is disabled, the certificate can't be verified. Aways return
    // success for test purpose.
    Ok(())
}

fn parse_extensions<'a>(extensions: &'a Extensions) -> Option<(&'a [u8], &'a [u8])> {
    let mut has_migtd_usage = false;
    let mut quote_report = None;
    let mut eventlog = None;

    for extn in extensions.get() {
        if extn.extn_id == EXTENDED_KEY_USAGE {
            if let Some(extn_value) = extn.extn_value {
                let eku = ExtendedKeyUsage::from_der(extn_value.as_bytes()).ok()?;
                if eku.contains(&MIGTD_EXTENDED_KEY_USAGE) {
                    has_migtd_usage = true;
                }
            }
        } else if extn.extn_id == EXTNID_MIGTD_QUOTE_REPORT {
            quote_report = extn.extn_value.map(|v| v.as_bytes());
        } else if extn.extn_id == EXTNID_MIGTD_EVENT_LOG {
            eventlog = extn.extn_value.map(|v| v.as_bytes());
        }
    }

    if !has_migtd_usage {
        return None;
    }

    if let (Some(quote_report), Some(eventlog)) = (quote_report, eventlog) {
        Some((quote_report, eventlog))
    } else {
        None
    }
}

fn verify_signature(cert: &Certificate, verified_report: &[u8]) -> CryptoResult<()> {
    let public_key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or(CryptoError::ParseCertificate)?;
    let tbs = cert.tbs_certificate.to_vec()?;
    let signature = cert
        .signature_value
        .as_bytes()
        .ok_or(CryptoError::ParseCertificate)?;

    verify_public_key(verified_report, public_key)?;
    ecdsa_verify(public_key, &tbs, signature)
}

fn verify_public_key(verified_report: &[u8], public_key: &[u8]) -> CryptoResult<()> {
    let report_data = &verified_report[520..520 + PUBLIC_KEY_HASH_SIZE];
    let digest = digest_sha384(public_key)?;

    if report_data == digest.as_slice() {
        Ok(())
    } else {
        Err(CryptoError::TlsVerifyPeerCert(
            MISMATCH_PUBLIC_KEY.to_string(),
        ))
    }
}
