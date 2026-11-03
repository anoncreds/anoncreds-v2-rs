use crate::error::Error;
use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use crate::presentation::{
    GovernanceVerificationProof, Presentation, PresentationProofs::*, VerifiableEncryptionProof,
};
use crate::statement::VerifiableEncryptionStatement;
use crate::verifier::ProofVerifier;
use crate::CredxResult;
use blsful::inner_types::{G1Projective, Scalar};
use blsful::{Bls12381G2Impl, PublicKey};
use bulletproofs::{BulletproofGens, PedersenGens};
use elliptic_curve::group::Curve;
use merlin::Transcript;

pub struct VerifiableEncryptionVerifier<'a, 'b> {
    pub statement: &'a VerifiableEncryptionStatement<G1Projective>,
    pub proof: &'b VerifiableEncryptionProof,
    pub message_proof: Scalar,
}

impl ProofVerifier for VerifiableEncryptionVerifier<'_, '_> {
    fn add_challenge_contribution(
        &self,
        challenge: Scalar,
        transcript: &mut Transcript,
    ) -> CredxResult<()> {
        let challenge = -challenge;
        let r1 = self.proof.c1 * challenge + G1Projective::GENERATOR * self.proof.blinder_proof;
        let r2 = self.proof.c2 * challenge
            + self.statement.message_generator * self.message_proof
            + self.statement.encryption_key.0 * self.proof.blinder_proof;

        transcript.append_message(b"", self.statement.id.as_bytes());
        transcript.append_message(b"c1", self.proof.c1.to_affine().to_compressed().as_slice());
        transcript.append_message(b"c2", self.proof.c2.to_affine().to_compressed().as_slice());
        transcript.append_message(b"r1", r1.to_affine().to_compressed().as_slice());
        transcript.append_message(b"r2", r2.to_affine().to_compressed().as_slice());

        if let Some(decryptable_proof) = self.proof.decryptable_scalar_proof.as_ref() {
            for i in 0..decryptable_proof.byte_proofs.len() {
                transcript.append_u64(
                    b"verifiable_encryption_decryptable_message_byte_index",
                    i as u64,
                );

                transcript.append_message(
                    b"byte_proof_c1",
                    decryptable_proof.byte_ciphertext.c1[i]
                        .to_compressed()
                        .as_slice(),
                );
                transcript.append_message(
                    b"byte_proof_c2",
                    decryptable_proof.byte_ciphertext.c2[i]
                        .to_compressed()
                        .as_slice(),
                );
                let inner_r1 = decryptable_proof.byte_ciphertext.c1[i] * challenge
                    + G1Projective::GENERATOR * decryptable_proof.byte_proofs[i].blinder;
                let inner_r2 = decryptable_proof.byte_ciphertext.c2[i] * challenge
                    + self.statement.encryption_key.0 * decryptable_proof.byte_proofs[i].blinder
                    + self.statement.message_generator * decryptable_proof.byte_proofs[i].message;

                transcript.append_message(b"byte_proof_r1", inner_r1.to_compressed().as_slice());
                transcript.append_message(b"byte_proof_r2", inner_r2.to_compressed().as_slice());
            }
        }

        Ok(())
    }

    fn verify(&self, challenge: Scalar) -> CredxResult<()> {
        if let Some(decryptable_proof) = self.proof.decryptable_scalar_proof.as_ref() {
            let bp_gens = BulletproofGens::new(8, decryptable_proof.byte_proofs.len());
            let pedersen_gen = PedersenGens {
                B: self.statement.message_generator,
                B_blinding: self.statement.encryption_key.0,
            };

            let mut transcript =
                Transcript::new(b"PresentationEncryptionDecryption byte range proof");
            transcript.append_message(b"challenge", &challenge.to_be_bytes());
            // Prove each byte is in the range [0, 255]
            decryptable_proof
                .range_proof
                .verify_multiple(
                    &bp_gens,
                    &pedersen_gen,
                    &mut transcript,
                    &decryptable_proof.byte_ciphertext.c2,
                    8,
                )
                .map_err(|_| Error::General("Range proof verification failed"))?;

            let shift = Scalar::from(256u16);
            let mut sum = G1Projective::IDENTITY;

            for c2 in &decryptable_proof.byte_ciphertext.c2 {
                sum *= shift;
                sum += c2;
            }

            if sum != self.proof.c2 {
                return Err(Error::General(
                    "Sum of byte ciphertexts does not match the ciphertext",
                ));
            }
        }
        Ok(())
    }
}

/* ---------------------------------------------

The following explains how Chaum Pedersen proofs are constructed and verified to enable the Prover
(decryptor of verifiably encrypted message) to prove to the Verifier (Governance Body) that the
decrypted scalar was indeed decrypted correctly using the secret decryption key associated with the
public encryption key, and shows the equations relating what the Verifier can compute without
knowing the secret decryption key to confirm that the Prover does know it and the decrypted value is
the one that was originally encrypted.  The explanation includes searchable references labeled like
GOV-PROOF-EXPLANATION-n to relevant code.

Variables

m: decrypted message (scalar)
g: public generator
p: public encryption key
k: secret decryption key

(1) p = g^k            ; how public encryption key is derived from
                       ; secret decryption key

M (called mcap in code): computed by Prover (GOV-PROOF-EXPLANATION-1) and Verifier
(GOV-PROOF-EXPLANATION-2) as:

(2) M = g^m

In proof of verifiable encryption (GOV-PROOF-EXPLANATION-3), Prover chooses random blinder b and
commits:

(3) c1 = g^b
(4) c2 = g^m.p^b

This implies

(5) p^b = c2/g^m

For governance proof (GOV-PROOF-EXPLANATION-4), Prover chooses random scalar w and commits:

(6) a = g^w
(7) b = c1^w

For challenge c based on transcript with above values, Prover computes (GOV-PROOF-EXPLANATION-5)

(8) s = w + ck

and creates ChaumPedersenProof {a, b, s}.

To verify that the Prover (for the Governance Proof) knows the secret decryption key k and that the
decrypted scalar is the value committed to in c2, the Verifier (Governance Body) checks the
following two equations.  In each case, we substitute the Prover's calculation (8) for the s
component of the Chaum Pedersen proof and show that the equation holds.

First verified equation: g^s = a.p^c

g^s = g^(w+ck)           ; (8)
    = g^w.(g^k)^c
    = a  .(g^k)^c        ; (6)
    = a  .p^c            ; (1)

Second verified equation: c1^s = b.(c2/M)^c

c1^s = c1^(w+ck)         ; (8)
     = c1^w . (c1^k)^c
     = c1^w . (g^(bk))^c ; (3)
     = c1^w . (g^(kb))^c ; (3)
     = c1^w . (g^k^b)^c
     = c1^w . (p^b)^c    ; (1)
     = c1^w . (c2/g^m)^c ; (5)
     = c1^w . (c2/M)^c   ; (2)
     = b    . (c2/M)^c   ; (7)

------------------------------------------------ */

pub fn verify_governance_proof<S: ShortGroupSignatureScheme>(
    encryption_key: &PublicKey<Bls12381G2Impl>,
    presentation: &Presentation<S>,
    gov_proof: &GovernanceVerificationProof,
) -> CredxResult<()> {
    // Get VerifiableEncryption proof
    let proof =
        match presentation.proofs.get(&gov_proof.stmt_id) {
            None => {
                return Err(Error::General(
                    "Governance verification failed - proof not found",
                ))
            }
            Some(VerifiableEncryption(veproof)) => veproof,
            Some(_) => return Err(Error::General(
                "Governance verification failed - proof found is not a VerifiableEncryption proof",
            )),
        };

    // GOV-PROOF-EXPLANATION-2: M = g^m
    let mcap = G1Projective::GENERATOR * gov_proof.decrypted_scalar;

    // Recreate the transcript for challenge generation (exact same as in proof generation)
    let mut transcript = Transcript::new(b"verifiable_decryption_challenge");

    // Add all public values to transcript for challenge generation (same order as in generation)
    add_governance_transcript_values(
        &mut transcript,
        proof,
        &encryption_key,
        &mcap,
        &gov_proof.proof.a,
        &gov_proof.proof.b,
    );

    let mut challenge_bytes = [0u8; 64];
    transcript.challenge_bytes(b"challenge", &mut challenge_bytes);
    let c = Scalar::from_bytes_wide(&challenge_bytes);

    // Verify the Chaum-Pedersen proof
    let s = gov_proof.proof.s;

    // Setup for first equation: g^s = a * pk^c
    let left1 = G1Projective::GENERATOR * s;
    let right1 = gov_proof.proof.a + encryption_key.0 * c;

    // Setup for second equation: C1^s = b * (C2/M)^c
    let left2 = proof.c1 * s;
    let right2 = gov_proof.proof.b + (proof.c2 - mcap) * c;

    // Verify the equations
    if left1 != right1 {
        return Err(Error::General(
            "Governance verification failed - first equation",
        ));
    }
    if left2 != right2 {
        return Err(Error::General(
            "Governance verification failed - second equation",
        ));
    }
    Ok(())
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
