use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use crate::prelude::Ciphertext;
use crate::presentation::{ByteProof, PresentationBuilder, PresentationProofs};
use crate::statement::VerifiableEncryptionStatement;
use crate::CredxResult;
use blsful::inner_types::{G1Projective, Scalar};
use blsful::{Bls12381G2Impl, PublicKey, SecretKey};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use elliptic_curve::ff::Field;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Verifiable encryption builder
pub(crate) struct VerifiableEncryptionBuilder<'a> {
    pub(crate) c1: G1Projective,
    pub(crate) c2: G1Projective,
    pub(crate) statement: &'a VerifiableEncryptionStatement<G1Projective>,
    pub(crate) b: Scalar,
    pub(crate) r: Scalar,
    pub(crate) decryptable_builder: Option<VerifiableEncryptionDecryptableBuilder>,
}

impl<S: ShortGroupSignatureScheme> PresentationBuilder<S> for VerifiableEncryptionBuilder<'_> {
    fn gen_proof(self, challenge: Scalar) -> PresentationProofs<S> {
        let blinder_proof = self.r + challenge * self.b;
        let decryptable_scalar_proof = self
            .decryptable_builder
            .map(|b| b.gen_proof(self.statement, challenge));
        VerifiableEncryptionProof {
            id: self.statement.id.clone(),
            c1: self.c1,
            c2: self.c2,
            blinder_proof,
            decryptable_scalar_proof,
        }
        .into()
    }
}

impl<'a> VerifiableEncryptionBuilder<'a> {
    /// Create a new verifiable encryption builder
    pub fn commit(
        statement: &'a VerifiableEncryptionStatement<G1Projective>,
        message: Scalar,
        b: Scalar,
        mut rng: impl RngCore + CryptoRng,
        transcript: &mut Transcript,
    ) -> CredxResult<Self> {
        let r = Scalar::random(&mut rng);

        // See comments above verify_governance_proof_if_present in
        // src/verifier/verifiable_encryption.rs
        // GOV-PROOF-EXPLANATION-3
        // c1 = g^b
        // c2 = g^m.p^b
        let c1 = G1Projective::GENERATOR * b;
        let c2 = statement.message_generator * message + statement.encryption_key.0 * b;

        let r1 = G1Projective::GENERATOR * r;
        let r2 = statement.message_generator * b + statement.encryption_key.0 * r;

        transcript.append_message(b"", statement.id.as_bytes());
        transcript.append_message(b"c1", c1.to_compressed().as_slice());
        transcript.append_message(b"c2", c2.to_compressed().as_slice());
        transcript.append_message(b"r1", r1.to_compressed().as_slice());
        transcript.append_message(b"r2", r2.to_compressed().as_slice());

        let decryptable_builder = if statement.allow_message_decryption {
            Some(VerifiableEncryptionDecryptableBuilder::commit(
                statement, message, b, rng, transcript,
            ))
        } else {
            None
        };

        Ok(Self {
            c1,
            c2,
            statement,
            b,
            r,
            decryptable_builder,
        })
    }
}

pub(crate) struct VerifiableEncryptionDecryptableBuilder {
    pub(crate) message_bytes: [u8; 32],
    pub(crate) byte_blinders: [Scalar; 32],
    pub(crate) blinder_blinders: [Scalar; 32],
    pub(crate) byte_ciphertext: Ciphertext,
}

impl VerifiableEncryptionDecryptableBuilder {
    pub fn commit(
        statement: &VerifiableEncryptionStatement<G1Projective>,
        message: Scalar,
        blinder: Scalar,
        mut rng: impl RngCore + CryptoRng,
        transcript: &mut Transcript,
    ) -> Self {
        let message_bytes = message.to_be_bytes();
        let mut byte_ciphertext = Ciphertext::default();
        let mut byte_blinders = [Scalar::ZERO; 32];
        let mut blinder_blinders = [Scalar::ZERO; 32];

        let shift = Scalar::from(256u16);
        let mut sum = Scalar::ZERO;
        let mut power = 31;
        for i in 0..31 {
            let b = Scalar::random(&mut rng);
            sum += b * shift.pow([power as u64]);
            byte_blinders[i] = b;
            blinder_blinders[i] = Scalar::random(&mut rng);

            byte_ciphertext.c1[i] = G1Projective::GENERATOR * b;
            byte_ciphertext.c2[i] = statement.message_generator * Scalar::from(message_bytes[i])
                + statement.encryption_key.0 * b;
            power -= 1;
        }
        byte_blinders[31] = blinder - sum;
        blinder_blinders[31] = Scalar::random(&mut rng);
        byte_ciphertext.c1[31] = G1Projective::GENERATOR * byte_blinders[31];
        byte_ciphertext.c2[31] = statement.message_generator * Scalar::from(message_bytes[31])
            + statement.encryption_key.0 * byte_blinders[31];

        for i in 0..message_bytes.len() {
            transcript.append_u64(
                b"verifiable_encryption_decryptable_message_byte_index",
                i as u64,
            );
            transcript.append_message(
                b"byte_proof_c1",
                byte_ciphertext.c1[i].to_compressed().as_slice(),
            );
            transcript.append_message(
                b"byte_proof_c2",
                byte_ciphertext.c2[i].to_compressed().as_slice(),
            );
            let inner_r1 = G1Projective::GENERATOR * blinder_blinders[i];
            let inner_r2 = statement.message_generator * byte_blinders[i]
                + statement.encryption_key.0 * blinder_blinders[i];

            transcript.append_message(b"byte_proof_r1", inner_r1.to_compressed().as_slice());
            transcript.append_message(b"byte_proof_r2", inner_r2.to_compressed().as_slice());
        }
        Self {
            message_bytes,
            byte_blinders,
            blinder_blinders,
            byte_ciphertext,
        }
    }

    pub fn gen_proof(
        self,
        statement: &VerifiableEncryptionStatement<G1Projective>,
        challenge: Scalar,
    ) -> DecryptableScalarProof {
        let bp_gens = BulletproofGens::new(8, self.message_bytes.len());
        let pedersen_gen = PedersenGens {
            B: statement.message_generator,
            B_blinding: statement.encryption_key.0,
        };

        let mut transcript = Transcript::new(b"PresentationEncryptionDecryption byte range proof");
        transcript.append_message(b"challenge", &challenge.to_be_bytes());
        let key_segments = self
            .message_bytes
            .iter()
            .map(|b| *b as u64)
            .collect::<Vec<_>>();
        let (range_proof, _) = RangeProof::prove_multiple(
            &bp_gens,
            &pedersen_gen,
            &mut transcript,
            &key_segments,
            &self.byte_blinders,
            8,
        )
        .expect("range proof to work");
        let mut byte_proofs = [ByteProof::default(); 32];
        for ((byte_proof, byte_blinder), (message_byte, blinder_blinder)) in byte_proofs
            .iter_mut()
            .zip(self.byte_blinders.iter())
            .zip(self.message_bytes.iter().zip(self.blinder_blinders.iter()))
        {
            *byte_proof = ByteProof {
                message: byte_blinder + challenge * Scalar::from(*message_byte),
                blinder: blinder_blinder + challenge * byte_blinder,
            };
        }
        DecryptableScalarProof {
            byte_proofs,
            range_proof,
            byte_ciphertext: self.byte_ciphertext,
        }
    }
}

/// A verifiable encryption proof
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiableEncryptionProof {
    /// The statement identifier
    pub id: String,
    /// The C1 El-Gamal component
    pub c1: G1Projective,
    /// The C2 El-Gamal component
    pub c2: G1Projective,
    /// The schnorr blinder proof
    pub blinder_proof: Scalar,
    /// The decryptable scalar proof if message decryption is allowed
    pub decryptable_scalar_proof: Option<DecryptableScalarProof>,
}

impl VerifiableEncryptionProof {
    /// Generate a governance verification proof for this verifiable encryption proof
    /// This method creates a zero-knowledge proof that enables third-party GovernanceBody
    /// verification of decryption correctness without accessing the secret key.
    ///
    /// # Arguments
    /// * `statement` - The verifiable encryption statement used to create this proof
    /// * `decryption_key` - The secret key used for decryption
    pub fn create_governance_verification_proof(
        &self,
        statement_id: String,
        encryption_key: &PublicKey<Bls12381G2Impl>,
        decryption_key: &SecretKey<Bls12381G2Impl>,
    ) -> CredxResult<GovernanceVerificationProof> {
        let decrypted_scalar = self
            .decrypt_scalar(decryption_key)
            .ok_or(crate::error::Error::General("Failed to decrypt scalar"))?;

        // See comments above verify_governance_proof_if_present in
        // src/verifier/verifiable_encryption.rs
        // GOV-PROOF-EXPLANATION-1
        // M = g^m
        let mcap = G1Projective::GENERATOR * decrypted_scalar;

        // GOV-PROOF-EXPLANATION-4
        let w = Scalar::random(&mut rand_core::OsRng);
        let a = G1Projective::GENERATOR * w;
        let b = self.c1 * w;

        let mut transcript = Transcript::new(b"verifiable_decryption_challenge");

        // Add all public values to transcript for challenge generation
        Self::add_governance_transcript_values(&mut transcript, self, encryption_key, &mcap, &a, &b);

        // Challenge phase
        let mut challenge_bytes = [0u8; 64];
        transcript.challenge_bytes(b"challenge", &mut challenge_bytes);
        let c = Scalar::from_bytes_wide(&challenge_bytes);

        // GOV-PROOF-EXPLANATION-5
        // Response phase
        let s = w + c * decryption_key.0;

        let proof = ChaumPedersenProof { a, b, s };

        Ok(GovernanceVerificationProof {
            stmt_id: statement_id.clone(),
            decrypted_scalar,
            proof,
        })
    }

    /// Helper function to add the common transcript values for governance proofs
    /// This ensures the transcript is built in the same way in both proof generation and verification
    fn add_governance_transcript_values(
        transcript: &mut Transcript,
        proof: &VerifiableEncryptionProof,
        encryption_key: &PublicKey<Bls12381G2Impl>,
        mcap: &G1Projective,
        a: &G1Projective,
        b: &G1Projective,
    ) {
        transcript.append_message(b"g", G1Projective::GENERATOR.to_compressed().as_slice());
        transcript.append_message(b"c1", proof.c1.to_compressed().as_slice());
        transcript.append_message(b"pk", encryption_key.0.to_compressed().as_slice());
        transcript.append_message(b"c2", proof.c2.to_compressed().as_slice());
        transcript.append_message(b"M", mcap.to_compressed().as_slice());
        transcript.append_message(b"a", a.to_compressed().as_slice());
        transcript.append_message(b"b", b.to_compressed().as_slice());
    }

    /// Unmask the committed message. The value will be in the exponent
    /// of the group element.
    pub fn decrypt(&self, key: &SecretKey<Bls12381G2Impl>) -> G1Projective {
        self.c2 - self.c1 * key.0
    }

    pub fn decrypt_scalar(&self, key: &SecretKey<Bls12381G2Impl>) -> Option<Scalar> {
        use rayon::prelude::*;

        if let Some(decryptable_proof) = self.decryptable_scalar_proof.as_ref() {
            let mut scalar_be_bytes = [0u8; 32];
            scalar_be_bytes
                .par_iter_mut()
                .enumerate()
                .for_each(|(i, b)| {
                    let vi = decryptable_proof.byte_ciphertext.c2[i]
                        - decryptable_proof.byte_ciphertext.c1[i] * key.0;

                    for ki in 0u8..=255 {
                        let si = Scalar::from(ki);
                        if vi == G1Projective::GENERATOR * si {
                            *b = ki;
                            return;
                        }
                    }
                });
            let value = Option::<Scalar>::from(Scalar::from_be_bytes(&scalar_be_bytes))?;
            if self.c2 - self.c1 * key.0 == G1Projective::GENERATOR * value {
                return Some(value);
            }
        }
        None
    }
}

/// A decryptable scalar proof
///
/// This proof is only available if the statement allows message decryption
/// but allows the scalar to be decrypted in a verifiable way.
///
/// Useful if the scalar represents a meaningful value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptableScalarProof {
    /// The byte proofs
    pub byte_proofs: [ByteProof; 32],
    /// The range proof
    pub range_proof: RangeProof,
    /// The byte ciphertext
    pub byte_ciphertext: Ciphertext,
}

/// Chaum-Pedersen proof structure for verifying correct decryption
// This implements the standard Chaum-Pedersen protocol for proving knowledge of x such that:
// 1. pk = g^x (where pk = encryption_key.0)
// 2. c2/M = c1^x where M = g^m (where c1 and c2 are commitments made by the proof
//    of correct encryption, and m is the unencrypted scalar value
// See comments above verify_governance_proof_if_present in
// src/verifier/verifiable_encryption.rs for details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaumPedersenProof {
    pub a: G1Projective,
    pub b: G1Projective,
    pub s: Scalar,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceVerificationProof {
    /// Statement ID for VerifiableEncryptionProof
    pub stmt_id: String,
    /// The decrypted value to be proved correct
    pub decrypted_scalar: Scalar,
    /// The Chaum-Pedersen proof that demonstrates knowledge of the secret key and correct decryption
    pub proof: ChaumPedersenProof,
}

impl GovernanceVerificationProof {
    /// Get the decrypted scalar value
    pub fn get_decrypted_scalar(&self) -> Scalar {
        self.decrypted_scalar
    }

    /// Tamper with the decrypted value (for testing)
    pub fn tamper_decrypted_value(&mut self) {
        self.decrypted_scalar += Scalar::ONE;
    }

    /// Tamper with the Chaum-Pedersen proof response (for testing)
    pub fn tamper_chaum_pedersen_response(&mut self) {
        self.proof.s += Scalar::ONE;
    }
}
