mod commitment;
mod create;
mod credential;
mod equality;
mod membership;
mod proof;
mod range;
mod revocation;
mod schema;
mod signature;
mod verifiable_encryption;
mod verifiable_encryption_decryption;
mod verify;

pub use commitment::*;
pub use credential::*;
pub use equality::*;
pub use membership::*;
pub use proof::*;
pub use range::*;
pub use revocation::*;
pub use schema::*;
pub use signature::*;
pub use verifiable_encryption::*;
pub use verifiable_encryption_decryption::*;

use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use crate::knox::short_group_sig_core::{HiddenMessage, ProofMessage};
use crate::verifier::*;
use crate::{claim::ClaimData, error::Error, statement::Statements, utils::*, CredxResult};
use blsful::inner_types::{G1Affine, G2Affine, Scalar};
use blsful::{Bls12381G2Impl, PublicKey, SecretKey};
use elliptic_curve::{ff::Field, group::prime::PrimeCurveAffine};
use indexmap::{IndexMap, IndexSet};
use merlin::Transcript;
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};
use uint_zigzag::Uint;

/// Implementers can build proofs for presentations
pub trait PresentationBuilder<S: ShortGroupSignatureScheme> {
    /// Finalize proofs
    fn gen_proof(self, challenge: Scalar) -> PresentationProofs<S>;
}

/// Encapsulates the builders for later conversion to proofs
pub(crate) enum PresentationBuilders<'a, S: ShortGroupSignatureScheme> {
    Signature(Box<SignatureBuilder<'a, S>>),
    Revocation(Box<RevocationProofBuilder<'a>>),
    Equality(Box<EqualityBuilder<'a>>),
    Commitment(Box<CommitmentBuilder<'a>>),
    VerifiableEncryption(Box<VerifiableEncryptionBuilder<'a>>),
    Range(Box<RangeBuilder<'a>>),
    Membership(Box<MembershipProofBuilder<'a>>),
    VerifiableEncryptionDecryption(Box<VerifiableEncryptionDecryptionBuilder<'a>>),
}

impl<S: ShortGroupSignatureScheme> PresentationBuilders<'_, S> {
    /// Convert to proofs
    pub fn gen_proof(self, challenge: Scalar) -> PresentationProofs<S> {
        match self {
            Self::Signature(s) => s.gen_proof(challenge),
            Self::Equality(e) => e.gen_proof(challenge),
            Self::Commitment(c) => c.gen_proof(challenge),
            Self::Revocation(a) => a.gen_proof(challenge),
            Self::VerifiableEncryption(v) => v.gen_proof(challenge),
            Self::Range(r) => r.gen_proof(challenge),
            Self::Membership(m) => m.gen_proof(challenge),
            Self::VerifiableEncryptionDecryption(v) => v.gen_proof(challenge),
        }
    }
}

impl<'a, S: ShortGroupSignatureScheme> From<SignatureBuilder<'a, S>>
    for PresentationBuilders<'a, S>
{
    fn from(sig: SignatureBuilder<'a, S>) -> Self {
        Self::Signature(Box::new(sig))
    }
}

impl<'a, S: ShortGroupSignatureScheme> From<RevocationProofBuilder<'a>>
    for PresentationBuilders<'a, S>
{
    fn from(acc: RevocationProofBuilder<'a>) -> Self {
        Self::Revocation(Box::new(acc))
    }
}

impl<'a, S: ShortGroupSignatureScheme> From<EqualityBuilder<'a>> for PresentationBuilders<'a, S> {
    fn from(eq: EqualityBuilder<'a>) -> Self {
        Self::Equality(Box::new(eq))
    }
}

impl<'a, S: ShortGroupSignatureScheme> From<CommitmentBuilder<'a>> for PresentationBuilders<'a, S> {
    fn from(com: CommitmentBuilder<'a>) -> Self {
        Self::Commitment(Box::new(com))
    }
}

impl<'a, S: ShortGroupSignatureScheme> From<VerifiableEncryptionBuilder<'a>>
    for PresentationBuilders<'a, S>
{
    fn from(ve: VerifiableEncryptionBuilder<'a>) -> Self {
        Self::VerifiableEncryption(Box::new(ve))
    }
}

impl<'a, S: ShortGroupSignatureScheme> From<RangeBuilder<'a>> for PresentationBuilders<'a, S> {
    fn from(rg: RangeBuilder<'a>) -> Self {
        Self::Range(Box::new(rg))
    }
}

impl<'a, S: ShortGroupSignatureScheme> From<MembershipProofBuilder<'a>>
    for PresentationBuilders<'a, S>
{
    fn from(value: MembershipProofBuilder<'a>) -> Self {
        Self::Membership(Box::new(value))
    }
}

impl<'a, S: ShortGroupSignatureScheme> From<VerifiableEncryptionDecryptionBuilder<'a>>
    for PresentationBuilders<'a, S>
{
    fn from(value: VerifiableEncryptionDecryptionBuilder<'a>) -> Self {
        Self::VerifiableEncryptionDecryption(Box::new(value))
    }
}

/// Defines the proofs for a verifier
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Presentation<S: ShortGroupSignatureScheme> {
    /// The proofs
    #[serde(
        serialize_with = "serialize_indexmap",
        deserialize_with = "deserialize_indexmap",
        bound(serialize = "PresentationProofs<S>: Serialize"),
        bound(deserialize = "PresentationProofs<S>: Deserialize<'de>")
    )]
    pub proofs: IndexMap<String, PresentationProofs<S>>,
    /// The fiat-shamir hash
    pub challenge: Scalar,
    /// The disclosed messages
    #[serde(
        serialize_with = "serialize_indexmap_nested",
        deserialize_with = "deserialize_indexmap_nested"
    )]
    pub disclosed_messages: IndexMap<String, IndexMap<String, ClaimData>>,
}

impl<S: ShortGroupSignatureScheme> Presentation<S> {
    #[allow(clippy::type_complexity)]
    fn split_statements(
        schema: &PresentationSchema<S>,
    ) -> (
        IndexMap<&String, &Statements<S>>,
        IndexMap<&String, &Statements<S>>,
    ) {
        let mut signature_statements: IndexMap<&String, &Statements<S>> = IndexMap::new();
        let mut predicate_statements: IndexMap<&String, &Statements<S>> = IndexMap::new();

        for (id, statement) in &schema.statements {
            if let Statements::Signature(_) = statement {
                signature_statements.insert(id, statement);
            } else {
                predicate_statements.insert(id, statement);
            }
        }
        (signature_statements, predicate_statements)
    }

    fn add_curve_parameters_challenge_contribution(transcript: &mut Transcript) {
        transcript.append_message(b"curve name", b"BLS12-381");
        transcript.append_message(
            b"curve G1 generator",
            G1Affine::generator().to_compressed().as_slice(),
        );
        transcript.append_message(
            b"curve G2 generator",
            G2Affine::generator().to_compressed().as_slice(),
        );
        transcript.append_message(
            b"subgroup size",
            &[
                0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1,
                0xd8, 0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x01,
            ],
        );
        transcript.append_message(
            b"field modulus",
            &[
                0x1a, 0x01, 0x11, 0xea, 0x39, 0x7f, 0xe6, 0x9a, 0x4b, 0x1b, 0xa7, 0xb6, 0x43, 0x4b,
                0xac, 0xd7, 0x64, 0x77, 0x4b, 0x84, 0xf3, 0x85, 0x12, 0xbf, 0x67, 0x30, 0xd2, 0xa0,
                0xf6, 0xb0, 0xf6, 0x24, 0x1e, 0xab, 0xff, 0xfe, 0xb1, 0x53, 0xff, 0xff, 0xb9, 0xfe,
                0xff, 0xff, 0xff, 0xff, 0xaa, 0xab,
            ],
        );
    }

    fn add_disclosed_messages_challenge_contribution(
        id: &String,
        dm: &IndexMap<String, ClaimData>,
        transcript: &mut Transcript,
    ) {
        transcript.append_message(b"disclosed messages from statement ", id.as_bytes());
        transcript.append_message(b"disclosed messages length", &Uint::from(dm.len()).to_vec());
        for (i, (label, claim)) in dm.iter().enumerate() {
            transcript.append_message(b"disclosed message label", label.as_bytes());
            transcript.append_message(b"disclosed message index", &Uint::from(i).to_vec());
            transcript.append_message(b"disclosed message value", &claim.to_bytes());
            transcript.append_message(
                b"disclosed message scalar",
                &claim.to_scalar().to_be_bytes(),
            );
        }
    }

    #[allow(clippy::type_complexity)]
    /// Map the claims to the respective types
    fn get_message_types<'a>(
        credentials: &IndexMap<String, PresentationCredential<S>>,
        signature_statements: &'a IndexMap<&String, &Statements<S>>,
        predicate_statements: &'a IndexMap<&String, &Statements<S>>,
        mut rng: impl RngCore + CryptoRng,
    ) -> CredxResult<IndexMap<&'a String, Vec<(ClaimData, ProofMessage<Scalar>)>>> {
        let mut shared_proof_msg_indices: IndexMap<&String, Vec<bool>> = IndexMap::new();

        for (id, cred) in credentials {
            if let PresentationCredential::Signature(c) = cred {
                shared_proof_msg_indices.insert(id, vec![false; c.claims.len()]);
            }
        }

        let mut same_proof_messages = Vec::new();

        let mut proof_messages: IndexMap<&String, Vec<(ClaimData, ProofMessage<Scalar>)>> =
            IndexMap::new();

        // If a claim is used in a statement, it is a shared message between the signature
        // and the statement. Equality statements are shared across signatures
        for statement in predicate_statements.values() {
            let reference_ids = statement.reference_ids();
            if reference_ids.len() > 1 {
                same_proof_messages.push((*statement).clone());
            }

            for ref_id in &reference_ids {
                match shared_proof_msg_indices.get_mut(ref_id) {
                    None => {
                        // Does this statement reference another statement instead of a signature
                        if !predicate_statements.contains_key(ref_id) {
                            // If not, then error
                            return Err(Error::InvalidPresentationData("a referenced predicate statement '{}' does not exist in the presentation schema".to_string()));
                        }
                        continue;
                    }
                    Some(indexer) => {
                        let claim_index = statement.get_claim_index(ref_id);
                        match indexer.get_mut(claim_index) {
                            None => {
                                return Err(Error::InvalidPresentationData(format!(
                                    "can't find claim_index '{}' in statement '{}'",
                                    claim_index, ref_id
                                )))
                            }
                            Some(v) => *v = true,
                        }
                    }
                }
            }
        }

        for (id, sig) in signature_statements {
            let signature = if let PresentationCredential::Signature(signature) = &credentials[*id]
            {
                signature
            } else {
                continue;
            };
            let mut proof_claims = Vec::with_capacity(signature.claims.len());

            for (index, claim) in signature.claims.iter().enumerate() {
                let claim_value = claim.to_scalar();

                // If the claim is not disclosed and used in a statement,
                // it must use a shared blinder, otherwise its proof specific
                if let Statements::Signature(ss) = sig {
                    let claim_label = ss.issuer.schema.claim_indices.get_index(index).unwrap();
                    if ss.disclosed.contains(claim_label) {
                        proof_claims.push((claim.clone(), ProofMessage::Revealed(claim_value)));
                    } else if shared_proof_msg_indices[id][index] {
                        let blinder = Scalar::random(&mut rng);
                        proof_claims.push((
                            claim.clone(),
                            ProofMessage::Hidden(HiddenMessage::ExternalBlinding(
                                claim_value,
                                blinder,
                            )),
                        ));
                    } else {
                        proof_claims.push((
                            claim.clone(),
                            ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(claim_value)),
                        ));
                    }
                }
            }
            proof_messages.insert(*id, proof_claims);
        }

        for statement in &same_proof_messages {
            let ref_ids = statement.reference_ids();
            let id1 = &ref_ids[0];
            for id2 in ref_ids.iter().skip(1) {
                let ix2 = statement.get_claim_index(id2);
                let ix1 = statement.get_claim_index(id1);
                let map1 = proof_messages.get(id1).unwrap().clone();
                let map2 = proof_messages.get_mut(id2).unwrap();
                // NOTE: other unexpected combinations could be checked too,
                // e.g., one ProofSpecificBlinding, one ExternalBlinding
                if matches!(map1[ix1].1, ProofMessage::Revealed(_))
                    || matches!(map2[ix2].1, ProofMessage::Revealed(_))
                {
                    return Err(Error::InvalidClaimData(
                        "revealed claim cannot be used with equality proof",
                    ));
                }
                map2[ix2].0 = map1[ix1].0.clone();
                map2[ix2].1 = map1[ix1].1;
            }
        }

        Ok(proof_messages)
    }

    pub fn decrypt_and_create_governance_proof(
        &self,
        stmt_id: String,
        encryption_key: &PublicKey<Bls12381G2Impl>,
        decryption_key: &SecretKey<Bls12381G2Impl>,
    ) -> CredxResult<GovernanceVerificationProof> {
        if let Some(PresentationProofs::VerifiableEncryption(verenc)) = self.proofs.get(&stmt_id) {
            return verenc.create_governance_verification_proof(
                stmt_id,
                encryption_key,
                decryption_key,
            );
        }
        return Err(crate::error::Error::General(
            "Statement {stmt_id} has no VerifiableEncryption proof",
        ));
    }
}
