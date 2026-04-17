use blsful::inner_types::*;
use credx::blind::BlindCredentialRequest;
use credx::claim::{
    ClaimData, ClaimType, ClaimValidator, HashedClaim, NumberClaim, RevocationClaim, ScalarClaim,
};
use credx::credential::{ClaimSchema, CredentialSchema};
use credx::error::Error;
use credx::issuer::{Issuer, IssuerPublic};
use credx::knox::bbs::BbsScheme;
use credx::knox::ps::PsScheme;
use credx::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use credx::prelude::{
    MembershipClaim, MembershipCredential, MembershipRegistry, MembershipSigningKey,
    MembershipStatement, MembershipVerificationKey, PresentationProofs,
    VerifiableEncryptionDecryptionStatement,
};
use credx::presentation::{Presentation, PresentationSchema};
use credx::statement::{
    CommitmentStatement, EqualityStatement, RangeStatement, RevocationStatement,
    SignatureStatement, VerifiableEncryptionStatement,
};
use credx::{
    create_domain_proof_generator, generate_verifiable_encryption_keys, random_string, CredxResult,
};
use indexmap::indexmap;
use maplit::{btreemap, btreeset};
use rand::thread_rng;
use rand_core::RngCore;
use regex::Regex;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::time::Instant;

fn setup() {
    let _ = env_logger::builder().is_test(true).try_init();
}

#[test]
fn presentation_1_credential_works() {
    setup();
    let res = test_presentation_1_credential_works();
    assert!(res.is_ok(), "{:?}", res);
}

fn test_presentation_1_credential_works() -> CredxResult<()> {
    const LABEL: &str = "Test Schema";
    const DESCRIPTION: &str = "This is a test presentation schema";
    const CRED_ID: &str = "91742856-6eda-45fb-a709-d22ebb5ec8a5";
    let schema_claims = [
        ClaimSchema {
            claim_type: ClaimType::Revocation,
            label: "identifier".to_string(),
            print_friendly: false,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "name".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Length {
                min: Some(3),
                max: Some(u8::MAX as usize),
            }],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "address".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Length {
                min: None,
                max: Some(u8::MAX as usize),
            }],
        },
        ClaimSchema {
            claim_type: ClaimType::Number,
            label: "age".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Range {
                min: Some(0),
                max: Some(u16::MAX as isize),
            }],
        },
    ];
    let cred_schema = CredentialSchema::new(Some(LABEL), Some(DESCRIPTION), &[], &schema_claims)?;

    let before = Instant::now();
    let (issuer_public, mut issuer) = Issuer::<BbsScheme>::new(&cred_schema);
    println!("key generation time = {:?}", before.elapsed());

    let before = std::time::Instant::now();
    let credential = issuer.sign_credential(&[
        RevocationClaim::from(CRED_ID).into(),
        HashedClaim::from("John Doe").into(),
        HashedClaim::from("P Sherman 42 Wallaby Way Sydney").into(),
        NumberClaim::from(30303).into(),
    ])?;
    println!("sign credential {:?}", before.elapsed());

    let dummy_sk = MembershipSigningKey::new(None);
    let dummy_vk = MembershipVerificationKey::from(&dummy_sk);
    let dummy_registry = MembershipRegistry::random(thread_rng());
    let dummy_membership_credential = MembershipCredential::new(
        MembershipClaim::from(&credential.credential.claims[2]).0,
        dummy_registry,
        &dummy_sk,
    );

    let sig_st = SignatureStatement {
        disclosed: btreeset! {"name".to_string()},
        id: random_string(16, rand::thread_rng()),
        issuer: issuer_public.clone(),
    };
    let acc_st = RevocationStatement {
        id: random_string(16, rand::thread_rng()),
        reference_id: sig_st.id.clone(),
        accumulator: issuer_public.revocation_registry,
        verification_key: issuer_public.revocation_verifying_key,
        claim: 0,
    };
    let comm_st = CommitmentStatement {
        id: random_string(16, thread_rng()),
        reference_id: sig_st.id.clone(),
        message_generator: create_domain_proof_generator(b"message generator"),
        blinder_generator: create_domain_proof_generator(b"blinder generator"),
        claim: 3,
    };
    let verenc_st = VerifiableEncryptionStatement {
        message_generator: G1Projective::GENERATOR,
        encryption_key: issuer_public.verifiable_encryption_key,
        id: random_string(16, rand::thread_rng()),
        reference_id: sig_st.id.clone(),
        claim: 0,
        allow_message_decryption: false,
    };
    let range_st = RangeStatement {
        id: random_string(16, thread_rng()),
        reference_id: comm_st.id.clone(),
        signature_id: sig_st.id.clone(),
        claim: 3,
        lower: Some(0),
        upper: Some(44829),
    };
    let mem_st = MembershipStatement {
        id: random_string(16, thread_rng()),
        reference_id: sig_st.id.clone(),
        accumulator: dummy_registry,
        verification_key: dummy_vk,
        claim: 2,
    };

    let mut nonce = [0u8; 16];
    thread_rng().fill_bytes(&mut nonce);

    let credentials = indexmap! { sig_st.id.clone() => credential.credential.into(), mem_st.id.clone() => dummy_membership_credential.into() };
    let presentation_schema = PresentationSchema::new(&[
        sig_st.into(),
        acc_st.into(),
        comm_st.into(),
        verenc_st.into(),
        range_st.into(),
        mem_st.into(),
    ]);
    // println!("{}", serde_json::to_string(&presentation_schema).unwrap());
    let before = Instant::now();
    let presentation = Presentation::create(&credentials, &presentation_schema, &nonce)?;
    println!("proof generation: {:?}", before.elapsed());
    presentation.verify(&presentation_schema, &nonce)?;
    let before = Instant::now();
    println!("proof verification: {:?}", before.elapsed());
    let proof_data = serde_bare::to_vec(&presentation).unwrap();
    let presentation: Presentation<BbsScheme> = serde_bare::from_slice(&proof_data).unwrap();
    println!("proof size = {}", proof_data.len());
    presentation.verify(&presentation_schema, &nonce)
}

#[test]
fn presentation_decrypt_claim_works() {
    const CRED_ID: &str = "91742856-6eda-45fb-a709-d22ebb5ec8a5";
    let schema_claims = [
        ClaimSchema {
            claim_type: ClaimType::Revocation,
            label: "identifier".to_string(),
            print_friendly: false,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "name".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Length {
                min: Some(3),
                max: Some(u8::MAX as usize),
            }],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "address".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Length {
                min: None,
                max: Some(u8::MAX as usize),
            }],
        },
        ClaimSchema {
            claim_type: ClaimType::Number,
            label: "age".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Range {
                min: Some(0),
                max: None,
            }],
        },
    ];
    let cred_schema = CredentialSchema::new(Some("Test"), Some(""), &[], &schema_claims).unwrap();
    let (issuer_public, mut issuer) = Issuer::<BbsScheme>::new(&cred_schema);
    let credential = issuer
        .sign_credential(&[
            RevocationClaim::from(CRED_ID).into(),
            HashedClaim::from("John Doe").into(),
            HashedClaim::from("P Sherman 42 Wallaby Way Sydney").into(),
            NumberClaim::from(19800101).into(),
        ])
        .unwrap();

    let sig_st = SignatureStatement {
        disclosed: BTreeSet::new(),
        id: random_string(16, thread_rng()),
        issuer: issuer_public.clone(),
    };
    let acc_st = RevocationStatement {
        id: random_string(16, thread_rng()),
        reference_id: sig_st.id.clone(),
        accumulator: issuer_public.revocation_registry,
        verification_key: issuer_public.revocation_verifying_key,
        claim: 0,
    };
    let verenc_st = VerifiableEncryptionDecryptionStatement {
        message_generator: G1Projective::GENERATOR,
        encryption_key: issuer_public.verifiable_encryption_key,
        id: random_string(16, thread_rng()),
        reference_id: sig_st.id.clone(),
        claim: 1,
    };

    let verenc_id = verenc_st.id.clone();
    let mut nonce = [0u8; 16];
    thread_rng().fill_bytes(&mut nonce);

    let credentials = indexmap! { sig_st.id.clone() => credential.credential.into() };

    let presentation_schema =
        PresentationSchema::new(&[sig_st.into(), acc_st.into(), verenc_st.into()]);

    let presentation = Presentation::create(&credentials, &presentation_schema, &nonce).unwrap();
    presentation.verify(&presentation_schema, &nonce).unwrap();
    let proof_data = serde_bare::to_vec(&presentation).unwrap();
    let presentation: Presentation<BbsScheme> = serde_bare::from_slice(&proof_data).unwrap();
    presentation.verify(&presentation_schema, &nonce).unwrap();

    if let PresentationProofs::VerifiableEncryptionDecryption(verenc) =
        &presentation.proofs[&verenc_id]
    {
        let decrypted_name = verenc
            .decrypt_and_verify(&issuer.verifiable_decryption_key)
            .unwrap();
        assert_eq!(decrypted_name.to_bytes(), b"John Doe");
    } else {
        assert!(false, "expected VerifiableEncryptionDecryption");
    }
}

#[test]
fn presentation_decrypt_scalar_claim() {
    const CRED_ID: &str = "91742856-6eda-45fb-a709-d22ebb5ec8a5";
    let schema_claims = [
        ClaimSchema {
            claim_type: ClaimType::Revocation,
            label: "identifier".to_string(),
            print_friendly: false,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Scalar,
            label: "name".to_string(),
            print_friendly: true,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "address".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Length {
                min: None,
                max: Some(u8::MAX as usize),
            }],
        },
        ClaimSchema {
            claim_type: ClaimType::Number,
            label: "phone-number".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Range {
                min: Some(0),
                max: None,
            }],
        },
    ];
    let cred_schema = CredentialSchema::new(Some("Test"), Some(""), &[], &schema_claims).unwrap();
    let (issuer_public, mut issuer) = Issuer::<BbsScheme>::new(&cred_schema);
    let credential = issuer
        .sign_credential(&[
            RevocationClaim::from(CRED_ID).into(),
            ScalarClaim::encode_str("John Doe").unwrap().into(),
            HashedClaim::from("P Sherman 42 Wallaby Way Sydney").into(),
            NumberClaim::from(8018881111i64).into(),
        ])
        .unwrap();

    let sig_st = SignatureStatement {
        disclosed: BTreeSet::new(),
        id: random_string(16, thread_rng()),
        issuer: issuer_public.clone(),
    };
    let acc_st = RevocationStatement {
        id: random_string(16, thread_rng()),
        reference_id: sig_st.id.clone(),
        accumulator: issuer_public.revocation_registry,
        verification_key: issuer_public.revocation_verifying_key,
        claim: 0,
    };
    let verenc_st1 = VerifiableEncryptionStatement {
        message_generator: G1Projective::GENERATOR,
        encryption_key: issuer_public.verifiable_encryption_key,
        id: random_string(16, thread_rng()),
        reference_id: sig_st.id.clone(),
        claim: 1,
        allow_message_decryption: true,
    };
    let verenc_st2 = VerifiableEncryptionStatement {
        message_generator: G1Projective::GENERATOR,
        encryption_key: issuer_public.verifiable_encryption_key,
        id: random_string(16, thread_rng()),
        reference_id: sig_st.id.clone(),
        claim: 3,
        allow_message_decryption: true,
    };

    let verenc1_id = verenc_st1.id.clone();
    let verenc2_id = verenc_st2.id.clone();
    let mut nonce = [0u8; 16];
    thread_rng().fill_bytes(&mut nonce);

    let credentials = indexmap! { sig_st.id.clone() => credential.credential.into() };

    let presentation_schema = PresentationSchema::new(&[
        sig_st.into(),
        acc_st.into(),
        verenc_st1.into(),
        verenc_st2.into(),
    ]);

    let presentation = Presentation::create(&credentials, &presentation_schema, &nonce).unwrap();
    presentation.verify(&presentation_schema, &nonce).unwrap();
    let proof_data = serde_bare::to_vec(&presentation).unwrap();
    let presentation: Presentation<BbsScheme> = serde_bare::from_slice(&proof_data).unwrap();
    presentation.verify(&presentation_schema, &nonce).unwrap();

    if let PresentationProofs::VerifiableEncryption(verenc) = &presentation.proofs[&verenc1_id] {
        // This works because the name is less than 32 bytes
        let decrypted_name_scalar = verenc
            .decrypt_scalar(&issuer.verifiable_decryption_key)
            .unwrap();
        let decrypted_name = ScalarClaim::from(decrypted_name_scalar)
            .decode_to_str()
            .unwrap();
        assert_eq!(decrypted_name.as_str(), "John Doe");
    } else {
        assert!(false, "expected VerifiableEncryptionDecryption");
    }

    if let PresentationProofs::VerifiableEncryption(verenc) = &presentation.proofs[&verenc2_id] {
        // This works because the phone number is a less than 32 bytes
        let decrypted_phone_scalar = verenc
            .decrypt_scalar(&issuer.verifiable_decryption_key)
            .unwrap();
        let decrypted_phone = NumberClaim::from(decrypted_phone_scalar);
        assert_eq!(decrypted_phone.value, 8018881111);
    } else {
        assert!(false, "expected VerifiableEncryptionDecryption");
    }
}

#[test]
fn presentation_with_domain_proof() {
    const LABEL: &str = "Test Schema";
    const DESCRIPTION: &str = "This is a test presentation schema";
    const CRED_ID: &str = "91742856-6eda-45fb-a709-d22ebb5ec8a5";
    let schema_claims = [
        ClaimSchema {
            claim_type: ClaimType::Revocation,
            label: "identifier".to_string(),
            print_friendly: false,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "name".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Length {
                min: Some(3),
                max: Some(u8::MAX as usize),
            }],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "address".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Length {
                min: None,
                max: Some(u8::MAX as usize),
            }],
        },
        ClaimSchema {
            claim_type: ClaimType::Number,
            label: "age".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Range {
                min: Some(0),
                max: Some(u16::MAX as isize),
            }],
        },
    ];
    let cred_schema =
        CredentialSchema::new(Some(LABEL), Some(DESCRIPTION), &[], &schema_claims).unwrap();

    let before = Instant::now();
    let (issuer_public, mut issuer) = Issuer::<BbsScheme>::new(&cred_schema);
    println!("key generation time = {:?}", before.elapsed());

    let before = std::time::Instant::now();
    let credential = issuer
        .sign_credential(&[
            RevocationClaim::from(CRED_ID).into(),
            HashedClaim::from("John Doe").into(),
            HashedClaim::from("P Sherman 42 Wallaby Way Sydney").into(),
            NumberClaim::from(30303).into(),
        ])
        .unwrap();
    println!("sign credential {:?}", before.elapsed());

    let dummy_sk = MembershipSigningKey::new(None);
    let dummy_vk = MembershipVerificationKey::from(&dummy_sk);
    let dummy_registry = MembershipRegistry::random(thread_rng());
    let dummy_membership_credential = MembershipCredential::new(
        MembershipClaim::from(&credential.credential.claims[2]).0,
        dummy_registry,
        &dummy_sk,
    );

    let (verifier_domain_specific_encryption_key, verifier_domain_specific_decryption_key) =
        generate_verifiable_encryption_keys(thread_rng());

    let sig_st = SignatureStatement {
        disclosed: btreeset! {"name".to_string()},
        id: random_string(16, rand::thread_rng()),
        issuer: issuer_public.clone(),
    };
    let acc_st = RevocationStatement {
        id: random_string(16, rand::thread_rng()),
        reference_id: sig_st.id.clone(),
        accumulator: issuer_public.revocation_registry,
        verification_key: issuer_public.revocation_verifying_key,
        claim: 0,
    };
    let comm_st = CommitmentStatement {
        id: random_string(16, thread_rng()),
        reference_id: sig_st.id.clone(),
        message_generator: create_domain_proof_generator(b"message generator"),
        blinder_generator: create_domain_proof_generator(b"blinder generator"),
        claim: 3,
    };
    let verenc_st = VerifiableEncryptionStatement {
        message_generator: create_domain_proof_generator(b"verifier specific message generator"),
        encryption_key: verifier_domain_specific_encryption_key,
        id: random_string(16, rand::thread_rng()),
        reference_id: sig_st.id.clone(),
        claim: 0,
        allow_message_decryption: false,
    };
    let verenc_st_id = verenc_st.id.clone();
    let range_st = RangeStatement {
        id: random_string(16, thread_rng()),
        reference_id: comm_st.id.clone(),
        signature_id: sig_st.id.clone(),
        claim: 3,
        lower: Some(0),
        upper: Some(44829),
    };
    let mem_st = MembershipStatement {
        id: random_string(16, thread_rng()),
        reference_id: sig_st.id.clone(),
        accumulator: dummy_registry,
        verification_key: dummy_vk,
        claim: 2,
    };

    let mut nonce = [0u8; 16];
    thread_rng().fill_bytes(&mut nonce);

    let credentials = indexmap! { sig_st.id.clone() => credential.credential.into(), mem_st.id.clone() => dummy_membership_credential.into() };
    let presentation_schema = PresentationSchema::new(&[
        sig_st.into(),
        acc_st.into(),
        comm_st.into(),
        verenc_st.into(),
        range_st.into(),
        mem_st.into(),
    ]);
    let presentation = Presentation::create(&credentials, &presentation_schema, &nonce).unwrap();
    presentation.verify(&presentation_schema, &nonce).unwrap();
    let proof1 =
        if let PresentationProofs::VerifiableEncryption(v) = &presentation.proofs[&verenc_st_id] {
            v.clone()
        } else {
            panic!("Expected VerifiableEncryption proof");
        };

    thread_rng().fill_bytes(&mut nonce);
    let presentation = Presentation::create(&credentials, &presentation_schema, &nonce).unwrap();
    presentation.verify(&presentation_schema, &nonce).unwrap();

    let proof2 =
        if let PresentationProofs::VerifiableEncryption(v) = &presentation.proofs[&verenc_st_id] {
            v.clone()
        } else {
            panic!("Expected VerifiableEncryption proof");
        };

    assert_ne!(proof1.blinder_proof, proof2.blinder_proof);
    assert_ne!(proof1.c1, proof2.c1);
    assert_ne!(proof1.c2, proof2.c2);
    let value1 = proof1.decrypt(&verifier_domain_specific_decryption_key);
    let value2 = proof2.decrypt(&verifier_domain_specific_decryption_key);
    assert_eq!(value1, value2);
}

#[ignore]
#[test]
fn presentation_1_credential_alter_revealed_message_fails() {
    let res = test_presentation_1_credential_alter_revealed_message_fails();
    assert!(res.is_ok(), "{:?}", res);
}

fn test_presentation_1_credential_alter_revealed_message_fails() -> CredxResult<()> {
    const LABEL: &str = "Test Schema";
    const DESCRIPTION: &str = "This is a test presentation schema";
    const CRED_ID: &str = "91742856-6eda-45fb-a709-d22ebb5ec8a5";
    let schema_claims = [
        ClaimSchema {
            claim_type: ClaimType::Revocation,
            label: "identifier".to_string(),
            print_friendly: false,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "name".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Length {
                min: Some(3),
                max: Some(u8::MAX as usize),
            }],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "address".to_string(),
            print_friendly: true,
            validators: vec![
                ClaimValidator::Length {
                    min: None,
                    max: Some(u8::MAX as usize),
                },
                ClaimValidator::Regex(Regex::new(r#"[\w\s]+"#).unwrap()),
                ClaimValidator::AnyOne(vec![
                    NumberClaim::from(0).into(),
                    NumberClaim::from(2).into(),
                    NumberClaim::from(4).into(),
                    NumberClaim::from(6).into(),
                    NumberClaim::from(8).into(),
                    NumberClaim::from(10).into(),
                ]),
            ],
        },
        ClaimSchema {
            claim_type: ClaimType::Number,
            label: "age".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Range {
                min: Some(0),
                max: Some(u32::MAX as isize),
            }],
        },
    ];
    let cred_schema = CredentialSchema::new(Some(LABEL), Some(DESCRIPTION), &[], &schema_claims)?;

    println!("{}", serde_json::to_string(&cred_schema).unwrap());

    let (issuer_public, mut issuer) = Issuer::<BbsScheme>::new(&cred_schema);

    let credential = issuer.sign_credential(&[
        RevocationClaim::from(CRED_ID).into(),
        HashedClaim::from("John Doe").into(),
        HashedClaim::from("P Sherman 42 Wallaby Way Sydney").into(),
        NumberClaim::from(30303).into(),
    ])?;

    let sig_st_id = random_string(16, rand::thread_rng());
    let sig_st = SignatureStatement {
        disclosed: btreeset! {"name".to_string()},
        id: sig_st_id.clone(),
        issuer: issuer_public.clone(),
    };
    let acc_st = RevocationStatement {
        id: random_string(16, rand::thread_rng()),
        reference_id: sig_st.id.clone(),
        accumulator: issuer_public.revocation_registry,
        verification_key: issuer_public.revocation_verifying_key,
        claim: 0,
    };
    let comm_st = CommitmentStatement {
        id: random_string(16, rand::thread_rng()),
        reference_id: sig_st.id.clone(),
        message_generator: G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(
            b"message generator",
            b"BLS12381G1_XMD:SHA-256_SSWU_RO_",
        ),
        blinder_generator: G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(
            b"blinder generator",
            b"BLS12381G1_XMD:SHA-256_SSWU_RO_",
        ),
        claim: 3,
    };
    let verenc_st = VerifiableEncryptionStatement {
        message_generator: G1Projective::GENERATOR,
        encryption_key: issuer_public.verifiable_encryption_key,
        id: random_string(16, rand::thread_rng()),
        reference_id: sig_st.id.clone(),
        claim: 0,
        allow_message_decryption: false,
    };
    let range_st = RangeStatement {
        id: random_string(16, rand::thread_rng()),
        reference_id: comm_st.id.clone(),
        signature_id: sig_st.id.clone(),
        claim: 3,
        lower: Some(0),
        upper: Some(44829),
    };

    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);

    let credentials = indexmap! { sig_st.id.clone() => credential.credential.into() };
    let presentation_schema = PresentationSchema::new(&[
        sig_st.into(),
        acc_st.into(),
        comm_st.into(),
        verenc_st.into(),
        range_st.into(),
    ]);
    let mut presentation = Presentation::create(&credentials, &presentation_schema, &nonce)?;

    let disclosed_claim = presentation
        .disclosed_messages
        .get_mut(&sig_st_id)
        .unwrap()
        .get_mut("name")
        .unwrap();
    *disclosed_claim = HashedClaim::from("Jane Doe").into();

    presentation.verify(&presentation_schema, &nonce)
}

macro_rules! gen_blind_sign_tests {
    ($($module:ident, $scheme:ty);+ $(;)?) => {
        $(
            mod $module {
                use super::*;

                fn swap_commitment(
                    good: &BlindCredentialRequest<$scheme>,
                    other: &BlindCredentialRequest<$scheme>,
                ) -> BlindCredentialRequest<$scheme> {
                    let mut tampered = good.clone();
                    tampered.blind_signature_context.commitment =
                        other.blind_signature_context.commitment;
                    tampered
                }

                #[test]
                fn blind_sign_request() {
                    setup();
                    let res = test_blind_sign_request_generic::<$scheme, _>(false, swap_commitment);
                    assert!(res.is_ok(), "{:?}", res);
                }

                #[test]
                fn blind_sign_request_tamper_fails() {
                    setup();
                    let res = test_blind_sign_request_generic::<$scheme, _>(true, swap_commitment);
                    assert!(
                        matches!(res, Err(Error::InvalidSigningOperation)),
                        "{:?}",
                        res
                    );
                }
            }
        )+
    };
}

gen_blind_sign_tests!(
    bbs, BbsScheme;
    ps,  PsScheme;
);

fn test_blind_sign_request_generic<S, F>(tamper: bool, mutate_request: F) -> CredxResult<()>
where
    S: ShortGroupSignatureScheme,
    F: Fn(&BlindCredentialRequest<S>, &BlindCredentialRequest<S>) -> BlindCredentialRequest<S>,
{
    const LABEL: &str = "Test Schema";
    const DESCRIPTION: &str = "This is a test presentation schema";
    let schema_claims = [
        ClaimSchema {
            claim_type: ClaimType::Revocation,
            label: "identifier".to_string(),
            print_friendly: false,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Scalar,
            label: "link_secret".to_string(),
            print_friendly: false,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "name".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Length {
                min: Some(3),
                max: Some(u8::MAX as usize),
            }],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "address".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Length {
                min: None,
                max: Some(u8::MAX as usize),
            }],
        },
        ClaimSchema {
            claim_type: ClaimType::Number,
            label: "age".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Range {
                min: Some(0),
                max: Some(u16::MAX as isize),
            }],
        },
    ];
    let cred_schema = CredentialSchema::new(
        Some(LABEL),
        Some(DESCRIPTION),
        &["link_secret"],
        &schema_claims,
    )?;

    let (issuer_public_1, mut issuer_1) = Issuer::<S>::new(&cred_schema);
    let (issuer_public_2, mut issuer_2) = Issuer::<S>::new(&cred_schema);

    let blind_claims_1 = btreemap! { "link_secret".to_string() => ScalarClaim::from(Scalar::random(rand_core::OsRng)).into() };
    let blind_claims_2 = btreemap! { "link_secret".to_string() => ScalarClaim::from(Scalar::random(rand_core::OsRng)).into() };

    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);

    if tamper {
        // Use two different link_secret values to get distinct commitments.
        let (request_good, _) = BlindCredentialRequest::new(&issuer_public_1, &blind_claims_1)?;
        let (request_other, _) = BlindCredentialRequest::new(&issuer_public_1, &blind_claims_2)?;
        let request_tampered = mutate_request(&request_good, &request_other);

        // Attempt to sign a credential using the tampered request
        const CRED_ID_1: &str = "91742856-6eda-45fb-a709-d22ebb5ec8a5";
        let claims_map = btreemap! {
            "identifier".to_string() => RevocationClaim::from(CRED_ID_1).into(),
            "name".to_string()        => HashedClaim::from("John Doe").into(),
            "address".to_string()     => HashedClaim::from("P Sherman 42 Wallaby Way Sydney").into(),
            "age".to_string()         => NumberClaim::from(30303).into(),
        };

        return issuer_1
            .blind_sign_credential(&request_tampered, &claims_map)
            .map(|_| ())
            .map_err(|e| e);
    }

    // equal link_secret equality claims

    let res = check_link_secret_equality(
        &issuer_public_1,
        &mut issuer_1,
        &issuer_public_2,
        &mut issuer_2,
        &blind_claims_1,
        &blind_claims_1, // <-- same blind claim for both credentials
        nonce,
    );
    if let Ok((presentation, pres_schema)) = res {
        presentation.verify(&pres_schema, &nonce)?;
    } else {
        return Err(Error::General(
            "presentation.verify should succeed on equal link secrets",
        ));
    }

    // link secrets with different values should not "pass"

    let res = check_link_secret_equality(
        &issuer_public_1,
        &mut issuer_1,
        &issuer_public_2,
        &mut issuer_2,
        &blind_claims_1,
        &blind_claims_2, // <-- different blind claims
        nonce,
    );
    if let Err(Error::InvalidClaimData("equality statement - claims are not all the same")) = res {
        // presentation.create will not succeed with unequal equality claims
        Ok(())
    } else {
        Err(Error::General(
            "Presentation::create should have failed on non equal link secrets",
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn check_link_secret_equality<S: ShortGroupSignatureScheme>(
    issuer_public_1: &IssuerPublic<S>,
    issuer_1: &mut Issuer<S>,
    issuer_public_2: &IssuerPublic<S>,
    issuer_2: &mut Issuer<S>,
    blind_claims_1: &BTreeMap<String, ClaimData>,
    blind_claims_2: &BTreeMap<String, ClaimData>,
    nonce: [u8; 16],
) -> CredxResult<(Presentation<S>, PresentationSchema<S>)> {
    // use the same link_secret to value mapping here
    let (request_1, blinder_1) = BlindCredentialRequest::new(issuer_public_1, blind_claims_1)?;
    let (request_2, blinder_2) = BlindCredentialRequest::new(issuer_public_2, blind_claims_2)?;

    const CRED_ID_1: &str = "91742856-6eda-45fb-a709-d22ebb5ec8a5";
    const CRED_ID_2: &str = "91742856-6eee-45fb-a709-d22eee5ec8a5";

    let blind_bundle_1 = issuer_1.blind_sign_credential(
        &request_1,
        &btreemap! {
            "identifier".to_string() => RevocationClaim::from(CRED_ID_1).into(),
            "name".to_string() => HashedClaim::from("John Doe").into(),
            "address".to_string() => HashedClaim::from("P Sherman 42 Wallaby Way Sydney").into(),
            "age".to_string() => NumberClaim::from(30303).into(),
        },
    )?;
    let blind_bundle_2 = issuer_2.blind_sign_credential(
        &request_2,
        &btreemap! {
            "identifier".to_string() => RevocationClaim::from(CRED_ID_2).into(),
            "name".to_string() => HashedClaim::from("Jane Doe").into(),
            "address".to_string() => HashedClaim::from("Sydney").into(),
            "age".to_string() => NumberClaim::from(30304).into(),
        },
    )?;

    let credential_1 = blind_bundle_1.to_unblinded(blind_claims_1, blinder_1)?;
    let credential_2 = blind_bundle_2.to_unblinded(blind_claims_2, blinder_2)?;

    let sig_st_1 = SignatureStatement {
        disclosed: btreeset! {},
        id: "1".to_string(),
        issuer: issuer_public_1.clone(),
    };
    let sig_st_2 = SignatureStatement {
        disclosed: btreeset! {},
        id: "2".to_string(),
        issuer: issuer_public_2.clone(),
    };

    let credentials = indexmap! {
        sig_st_1.id.clone() => credential_1.credential.into(),
        sig_st_2.id.clone() => credential_2.credential.into()
    };

    let pres_sch_id = random_string(16, rand::thread_rng());

    let eq_st = EqualityStatement {
        id: random_string(16, rand::thread_rng()),
        ref_id_claim_index: indexmap! {
            sig_st_1.id.clone() => 1,
            sig_st_2.id.clone() => 1,
        },
    };
    let pres_sch_1 = PresentationSchema::new_with_id(
        &[
            sig_st_1.clone().into(),
            sig_st_2.clone().into(),
            eq_st.clone().into(),
        ],
        &pres_sch_id,
    );

    let presentation = Presentation::create(&credentials, &pres_sch_1, &nonce)?;

    // Prover and verifier each use PresentationSchema generated independently.
    // 'pres_sch_2' to be used by verifier.
    let pres_sch_2 = PresentationSchema::new_with_id(
        &[sig_st_1.into(), sig_st_2.into(), eq_st.into()],
        &pres_sch_id,
    );

    Ok((presentation, pres_sch_2))
}
