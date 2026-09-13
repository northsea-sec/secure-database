//! Zero-knowledge proof helpers powered by Halo2 (Pasta curves).
//!
//! Halo2 proofs attest that sensitive computations
//! were executed correctly without disclosing private data. This module
//! contains reusable provers and verifiers for several circuits that underpin
//! Tor relay compliance, audit log integrity, and remote execution attestation.

use crate::{DatabaseError, DbResult, DEFAULT_ZK_SECURITY};
use chrono::{DateTime, Utc};
use ff::PrimeField;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    pasta::{EqAffine, Fp},
    plonk::{self, Circuit, ConstraintSystem, Error as PlonkError, SingleVerifier},
    poly::{commitment::Params, Rotation},
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use once_cell::sync::Lazy;
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    convert::TryInto,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

const PARAM_SEED: u64 = 0x4252_5554; // "BRUT" in ASCII.
const PROTOCOL_ID: &str = "halo2-scalar-equality-v1";
const CIRCUIT_ID_SCALAR: &str = "scalar_equality";
const CIRCUIT_ID_RELAY_AUDIT: &str = "relay_audit_v1";
const CIRCUIT_ID_LOG_INTEGRITY: &str = "log_chain_integrity_v1";
const CIRCUIT_ID_EXECUTION: &str = "execution_attestation_v1";

/// Compact proof bundle ready for database persistence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkProofBundle {
    pub proof_id: Uuid,
    pub user_id: Uuid,
    pub protocol: String,
    pub circuit: String,
    pub circuit_security: u32,
    pub expected_hash: String,
    pub public_inputs: JsonValue,
    pub proof: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

/// Description of the context that must be satisfied when verifying a proof.
#[derive(Clone, Debug)]
pub enum ZkVerificationContext {
    ScalarDigest {
        expected_digest: Vec<u8>,
    },
    RelayAudit {
        expected_commitment: Vec<u8>,
        guard_count: u32,
        exit_count: u32,
    },
    LogIntegrity {
        expected_commitment: Vec<u8>,
        sequence_number: u64,
    },
    Execution {
        expected_commitment: Vec<u8>,
    },
}

/// Verification request used when validating stored proofs.
#[derive(Clone, Debug)]
pub struct ZkProofVerification {
    pub proof_id: Uuid,
    pub user_id: Uuid,
    pub context: ZkVerificationContext,
}

impl ZkProofVerification {
    pub fn scalar_digest(proof_id: Uuid, user_id: Uuid, expected_digest: Vec<u8>) -> Self {
        Self {
            proof_id,
            user_id,
            context: ZkVerificationContext::ScalarDigest { expected_digest },
        }
    }

    pub fn relay_audit(
        proof_id: Uuid,
        user_id: Uuid,
        expected_commitment: Vec<u8>,
        guard_count: u32,
        exit_count: u32,
    ) -> Self {
        Self {
            proof_id,
            user_id,
            context: ZkVerificationContext::RelayAudit {
                expected_commitment,
                guard_count,
                exit_count,
            },
        }
    }

    pub fn log_integrity(
        proof_id: Uuid,
        user_id: Uuid,
        expected_commitment: Vec<u8>,
        sequence_number: u64,
    ) -> Self {
        Self {
            proof_id,
            user_id,
            context: ZkVerificationContext::LogIntegrity {
                expected_commitment,
                sequence_number,
            },
        }
    }

    pub fn execution(proof_id: Uuid, user_id: Uuid, expected_commitment: Vec<u8>) -> Self {
        Self {
            proof_id,
            user_id,
            context: ZkVerificationContext::Execution {
                expected_commitment,
            },
        }
    }

    pub fn context(&self) -> &ZkVerificationContext {
        &self.context
    }
}

/// Deterministic Halo2 prover for supported circuits.
#[derive(Clone, Debug)]
pub struct ZkProver {
    k: u32,
}

impl Default for ZkProver {
    fn default() -> Self {
        Self {
            k: DEFAULT_ZK_SECURITY,
        }
    }
}

impl ZkProver {
    /// Build a prover with the supplied security parameter (`k`).
    pub fn new(k: u32) -> Self {
        Self { k }
    }

    /// Generate a proof that the caller's private digest matches the expected digest.
    pub fn prove_digest_equality(
        &self,
        user_id: Uuid,
        private_digest: &[u8],
        expected_digest: &[u8],
    ) -> DbResult<ZkProofBundle> {
        let private = normalise_digest(private_digest);
        let expected = normalise_digest(expected_digest);
        let expected_hash = hash_expected_digest(&expected);

        let private_scalar = digest_to_scalar(&private)?;
        let expected_scalar = digest_to_scalar(&expected)?;

        let params = shared_params(self.k);
        let circuit = ScalarEqualityCircuit {
            private_value: Value::known(private_scalar),
        };

        let vk = plonk::keygen_vk(&params, &ScalarEqualityCircuit::default())?;
        let pk = plonk::keygen_pk(&params, vk.clone(), &ScalarEqualityCircuit::default())?;

        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
        let mut rng = deterministic_rng(self.k);
        let instance_column = vec![vec![expected_scalar]];
        let instance_refs: Vec<&[Fp]> = instance_column.iter().map(|col| col.as_slice()).collect();
        plonk::create_proof(
            &params,
            &pk,
            &[circuit.clone()],
            &[&instance_refs[..]],
            &mut rng,
            &mut transcript,
        )?;
        let proof = transcript.finalize();

        let bundle = ZkProofBundle {
            proof_id: Uuid::new_v4(),
            user_id,
            protocol: PROTOCOL_ID.to_string(),
            circuit: CIRCUIT_ID_SCALAR.to_string(),
            circuit_security: self.k,
            expected_hash,
            public_inputs: json!({
                "expected_digest": hex::encode(expected),
            }),
            proof,
            created_at: Utc::now(),
        };

        Ok(bundle)
    }

    /// Produce a proof that Tor relay consensus metadata matches the published commitment.
    pub fn prove_relay_audit(
        &self,
        user_id: Uuid,
        consensus_digest: &[u8],
        guard_count: u32,
        exit_count: u32,
    ) -> DbResult<ZkProofBundle> {
        let consensus_normalised = normalise_digest(consensus_digest);
        let consensus_scalar = digest_to_scalar(&consensus_normalised)?;
        let guard_scalar = Fp::from(guard_count as u64);
        let exit_scalar = Fp::from(exit_count as u64);
        let commitment_bytes = derive_relay_commitment(consensus_digest, guard_count, exit_count)?;
        let expected_scalar = scalar_from_bytes(&commitment_bytes)?;
        let expected_hash = hash_expected_digest(&commitment_bytes);

        let params = shared_params(self.k);
        let circuit = RelayAuditCircuit {
            consensus_value: Value::known(consensus_scalar),
            guard_value: Value::known(guard_scalar),
            exit_value: Value::known(exit_scalar),
        };

        let vk = plonk::keygen_vk(&params, &RelayAuditCircuit::default())?;
        let pk = plonk::keygen_pk(&params, vk.clone(), &RelayAuditCircuit::default())?;

        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
        let mut rng = deterministic_rng(self.k);
        let instance_columns = vec![vec![expected_scalar], vec![guard_scalar], vec![exit_scalar]];
        let instance_refs: Vec<&[Fp]> = instance_columns.iter().map(|col| col.as_slice()).collect();
        plonk::create_proof(
            &params,
            &pk,
            &[circuit.clone()],
            &[&instance_refs[..]],
            &mut rng,
            &mut transcript,
        )?;
        let proof = transcript.finalize();

        let bundle = ZkProofBundle {
            proof_id: Uuid::new_v4(),
            user_id,
            protocol: PROTOCOL_ID.to_string(),
            circuit: CIRCUIT_ID_RELAY_AUDIT.to_string(),
            circuit_security: self.k,
            expected_hash,
            public_inputs: json!({
                "guard_count": guard_count,
                "exit_count": exit_count,
                "commitment": hex::encode(commitment_bytes),
            }),
            proof,
            created_at: Utc::now(),
        };

        Ok(bundle)
    }

    /// Prove that audit log chaining preserves integrity up to the supplied sequence number.
    pub fn prove_log_chain_integrity(
        &self,
        user_id: Uuid,
        previous_hash: &[u8],
        entry_hash: &[u8],
        sequence_number: u64,
    ) -> DbResult<ZkProofBundle> {
        let previous = normalise_digest(previous_hash);
        let entry = normalise_digest(entry_hash);
        let previous_scalar = digest_to_scalar(&previous)?;
        let entry_scalar = digest_to_scalar(&entry)?;
        let sequence_scalar = Fp::from(sequence_number);

        let commitment_bytes =
            derive_log_chain_commitment(previous_hash, entry_hash, sequence_number)?;
        let expected_scalar = scalar_from_bytes(&commitment_bytes)?;
        let expected_hash = hash_expected_digest(&commitment_bytes);

        let params = shared_params(self.k);
        let circuit = LogIntegrityCircuit {
            previous_value: Value::known(previous_scalar),
            entry_value: Value::known(entry_scalar),
        };

        let vk = plonk::keygen_vk(&params, &LogIntegrityCircuit::default())?;
        let pk = plonk::keygen_pk(&params, vk.clone(), &LogIntegrityCircuit::default())?;

        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
        let mut rng = deterministic_rng(self.k);
        let instance_columns = vec![vec![expected_scalar], vec![sequence_scalar]];
        let instance_refs: Vec<&[Fp]> = instance_columns.iter().map(|col| col.as_slice()).collect();
        plonk::create_proof(
            &params,
            &pk,
            &[circuit.clone()],
            &[&instance_refs[..]],
            &mut rng,
            &mut transcript,
        )?;
        let proof = transcript.finalize();

        let bundle = ZkProofBundle {
            proof_id: Uuid::new_v4(),
            user_id,
            protocol: PROTOCOL_ID.to_string(),
            circuit: CIRCUIT_ID_LOG_INTEGRITY.to_string(),
            circuit_security: self.k,
            expected_hash,
            public_inputs: json!({
                "sequence": sequence_number,
                "commitment": hex::encode(commitment_bytes),
                "previous_hash": hex::encode(previous),
                "entry_hash": hex::encode(entry),
            }),
            proof,
            created_at: Utc::now(),
        };

        Ok(bundle)
    }

    /// Prove that a remote execution produced the committed result/telemetry bundle.
    pub fn prove_execution_attestation(
        &self,
        user_id: Uuid,
        input_hash: &[u8],
        output_hash: &[u8],
        telemetry_hash: &[u8],
    ) -> DbResult<ZkProofBundle> {
        let input = normalise_digest(input_hash);
        let output = normalise_digest(output_hash);
        let telemetry = normalise_digest(telemetry_hash);

        let input_scalar = digest_to_scalar(&input)?;
        let output_scalar = digest_to_scalar(&output)?;
        let telemetry_scalar = digest_to_scalar(&telemetry)?;

        let commitment_bytes =
            derive_execution_commitment(input_hash, output_hash, telemetry_hash)?;
        let expected_scalar = scalar_from_bytes(&commitment_bytes)?;
        let expected_hash = hash_expected_digest(&commitment_bytes);

        let params = shared_params(self.k);
        let circuit = ExecutionCircuit {
            input_value: Value::known(input_scalar),
            output_value: Value::known(output_scalar),
            telemetry_value: Value::known(telemetry_scalar),
        };

        let vk = plonk::keygen_vk(&params, &ExecutionCircuit::default())?;
        let pk = plonk::keygen_pk(&params, vk.clone(), &ExecutionCircuit::default())?;

        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
        let mut rng = deterministic_rng(self.k);
        let instance_columns = vec![vec![expected_scalar]];
        let instance_refs: Vec<&[Fp]> = instance_columns.iter().map(|col| col.as_slice()).collect();
        plonk::create_proof(
            &params,
            &pk,
            &[circuit.clone()],
            &[&instance_refs[..]],
            &mut rng,
            &mut transcript,
        )?;
        let proof = transcript.finalize();

        let bundle = ZkProofBundle {
            proof_id: Uuid::new_v4(),
            user_id,
            protocol: PROTOCOL_ID.to_string(),
            circuit: CIRCUIT_ID_EXECUTION.to_string(),
            circuit_security: self.k,
            expected_hash,
            public_inputs: json!({
                "commitment": hex::encode(commitment_bytes),
                "input_hash": hex::encode(input),
                "output_hash": hex::encode(output),
                "telemetry_hash": hex::encode(telemetry),
            }),
            proof,
            created_at: Utc::now(),
        };

        Ok(bundle)
    }
}

/// Verify a stored proof with the supplied context.
pub fn verify_proof(bundle: &ZkProofBundle, context: &ZkVerificationContext) -> DbResult<()> {
    ensure_protocol(bundle)?;
    match context {
        ZkVerificationContext::ScalarDigest { expected_digest } => {
            ensure_circuit(bundle, CIRCUIT_ID_SCALAR)?;
            ensure_expected_hash(bundle, expected_digest)?;
            verify_scalar_equality(bundle, expected_digest)
        }
        ZkVerificationContext::RelayAudit {
            expected_commitment,
            guard_count,
            exit_count,
        } => verify_relay_audit(bundle, expected_commitment, *guard_count, *exit_count),
        ZkVerificationContext::LogIntegrity {
            expected_commitment,
            sequence_number,
        } => verify_log_integrity(bundle, expected_commitment, *sequence_number),
        ZkVerificationContext::Execution {
            expected_commitment,
        } => verify_execution_attestation(bundle, expected_commitment),
    }
}

/// Verify a stored equality proof against the supplied expected digest.
pub fn verify_scalar_equality(bundle: &ZkProofBundle, expected_digest: &[u8]) -> DbResult<()> {
    if bundle.protocol.as_str() != PROTOCOL_ID || bundle.circuit.as_str() != CIRCUIT_ID_SCALAR {
        return Err(DatabaseError::ZeroKnowledge(
            "unsupported proof bundle".into(),
        ));
    }

    let expected = normalise_digest(expected_digest);
    let expected_hash = hash_expected_digest(&expected);
    if bundle.expected_hash != expected_hash {
        return Err(DatabaseError::Integrity(
            "expected digest does not match stored commitment".into(),
        ));
    }

    let params = shared_params(bundle.circuit_security);
    let vk = plonk::keygen_vk(&params, &ScalarEqualityCircuit::default())?;
    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(bundle.proof.as_slice());
    let expected_scalar = digest_to_scalar(&expected)?;

    let instance_column = vec![vec![expected_scalar]];
    let instance_refs: Vec<&[Fp]> = instance_column.iter().map(|col| col.as_slice()).collect();

    plonk::verify_proof(
        &params,
        &vk,
        strategy,
        &[&instance_refs[..]],
        &mut transcript,
    )
    .map_err(DatabaseError::from)
}

fn verify_relay_audit(
    bundle: &ZkProofBundle,
    expected_commitment: &[u8],
    guard_count: u32,
    exit_count: u32,
) -> DbResult<()> {
    ensure_circuit(bundle, CIRCUIT_ID_RELAY_AUDIT)?;
    ensure_expected_hash(bundle, expected_commitment)?;
    ensure_relay_inputs(
        &bundle.public_inputs,
        guard_count,
        exit_count,
        expected_commitment,
    )?;

    let params = shared_params(bundle.circuit_security);
    let vk = plonk::keygen_vk(&params, &RelayAuditCircuit::default())?;
    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(bundle.proof.as_slice());

    let expected_scalar = scalar_from_bytes(expected_commitment)?;
    let guard_scalar = Fp::from(guard_count as u64);
    let exit_scalar = Fp::from(exit_count as u64);

    let instance_columns = vec![vec![expected_scalar], vec![guard_scalar], vec![exit_scalar]];
    let instance_refs: Vec<&[Fp]> = instance_columns.iter().map(|col| col.as_slice()).collect();

    plonk::verify_proof(
        &params,
        &vk,
        strategy,
        &[&instance_refs[..]],
        &mut transcript,
    )
    .map_err(DatabaseError::from)
}

fn verify_log_integrity(
    bundle: &ZkProofBundle,
    expected_commitment: &[u8],
    sequence_number: u64,
) -> DbResult<()> {
    ensure_circuit(bundle, CIRCUIT_ID_LOG_INTEGRITY)?;
    ensure_expected_hash(bundle, expected_commitment)?;
    ensure_log_inputs(&bundle.public_inputs, sequence_number, expected_commitment)?;

    let params = shared_params(bundle.circuit_security);
    let vk = plonk::keygen_vk(&params, &LogIntegrityCircuit::default())?;
    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(bundle.proof.as_slice());

    let expected_scalar = scalar_from_bytes(expected_commitment)?;
    let sequence_scalar = Fp::from(sequence_number);

    let instance_columns = vec![vec![expected_scalar], vec![sequence_scalar]];
    let instance_refs: Vec<&[Fp]> = instance_columns.iter().map(|col| col.as_slice()).collect();

    plonk::verify_proof(
        &params,
        &vk,
        strategy,
        &[&instance_refs[..]],
        &mut transcript,
    )
    .map_err(DatabaseError::from)
}

fn verify_execution_attestation(
    bundle: &ZkProofBundle,
    expected_commitment: &[u8],
) -> DbResult<()> {
    ensure_circuit(bundle, CIRCUIT_ID_EXECUTION)?;
    ensure_expected_hash(bundle, expected_commitment)?;
    ensure_execution_inputs(&bundle.public_inputs, expected_commitment)?;

    let params = shared_params(bundle.circuit_security);
    let vk = plonk::keygen_vk(&params, &ExecutionCircuit::default())?;
    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(bundle.proof.as_slice());

    let expected_scalar = scalar_from_bytes(expected_commitment)?;
    let instance_columns = vec![vec![expected_scalar]];
    let instance_refs: Vec<&[Fp]> = instance_columns.iter().map(|col| col.as_slice()).collect();

    plonk::verify_proof(
        &params,
        &vk,
        strategy,
        &[&instance_refs[..]],
        &mut transcript,
    )
    .map_err(DatabaseError::from)
}

#[derive(Clone, Default)]
struct ScalarEqualityCircuit {
    private_value: Value<Fp>,
}

impl Circuit<Fp> for ScalarEqualityCircuit {
    type Config = (plonk::Column<plonk::Advice>, plonk::Column<plonk::Instance>);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let value = meta.advice_column();
        let expected = meta.instance_column();
        meta.enable_equality(value);
        meta.enable_equality(expected);

        meta.create_gate("value equals expected", |meta| {
            let v = meta.query_advice(value, Rotation::cur());
            let e = meta.query_instance(expected, Rotation::cur());
            vec![v - e]
        });

        (value, expected)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), PlonkError> {
        let (value_col, instance_col) = config;
        let cell = layouter.assign_region(
            || "assign private value",
            |mut region| region.assign_advice(|| "private", value_col, 0, || self.private_value),
        )?;
        layouter.constrain_instance(cell.cell(), instance_col, 0)?;
        Ok(())
    }
}

#[derive(Clone, Default)]
struct RelayAuditCircuit {
    consensus_value: Value<Fp>,
    guard_value: Value<Fp>,
    exit_value: Value<Fp>,
}

impl Circuit<Fp> for RelayAuditCircuit {
    type Config = (
        plonk::Column<plonk::Advice>,
        plonk::Column<plonk::Advice>,
        plonk::Column<plonk::Advice>,
        plonk::Column<plonk::Instance>,
        plonk::Column<plonk::Instance>,
        plonk::Column<plonk::Instance>,
    );
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let consensus = meta.advice_column();
        let guard = meta.advice_column();
        let exit = meta.advice_column();
        let expected = meta.instance_column();
        let guard_public = meta.instance_column();
        let exit_public = meta.instance_column();

        meta.enable_equality(consensus);
        meta.enable_equality(guard);
        meta.enable_equality(exit);

        meta.create_gate("relay audit commitment", |meta| {
            let consensus_v = meta.query_advice(consensus, Rotation::cur());
            let guard_v = meta.query_advice(guard, Rotation::cur());
            let exit_v = meta.query_advice(exit, Rotation::cur());
            let expected_v = meta.query_instance(expected, Rotation::cur());
            let guard_public_v = meta.query_instance(guard_public, Rotation::cur());
            let exit_public_v = meta.query_instance(exit_public, Rotation::cur());

            vec![
                guard_v.clone() - guard_public_v,
                exit_v.clone() - exit_public_v,
                consensus_v + guard_v + exit_v - expected_v,
            ]
        });

        (consensus, guard, exit, expected, guard_public, exit_public)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), PlonkError> {
        let (consensus_col, guard_col, exit_col, _, _, _) = config;
        layouter.assign_region(
            || "assign relay values",
            |mut region| {
                region.assign_advice(|| "consensus", consensus_col, 0, || self.consensus_value)?;
                region.assign_advice(|| "guard", guard_col, 0, || self.guard_value)?;
                region.assign_advice(|| "exit", exit_col, 0, || self.exit_value)?;
                Ok(())
            },
        )?;
        Ok(())
    }
}

#[derive(Clone, Default)]
struct LogIntegrityCircuit {
    previous_value: Value<Fp>,
    entry_value: Value<Fp>,
}

impl Circuit<Fp> for LogIntegrityCircuit {
    type Config = (
        plonk::Column<plonk::Advice>,
        plonk::Column<plonk::Advice>,
        plonk::Column<plonk::Instance>,
        plonk::Column<plonk::Instance>,
    );
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let previous = meta.advice_column();
        let entry = meta.advice_column();
        let expected = meta.instance_column();
        let sequence = meta.instance_column();

        meta.enable_equality(previous);
        meta.enable_equality(entry);

        meta.create_gate("log chain integrity", |meta| {
            let previous_v = meta.query_advice(previous, Rotation::cur());
            let entry_v = meta.query_advice(entry, Rotation::cur());
            let expected_v = meta.query_instance(expected, Rotation::cur());
            let sequence_v = meta.query_instance(sequence, Rotation::cur());
            vec![entry_v * sequence_v + previous_v - expected_v]
        });

        (previous, entry, expected, sequence)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), PlonkError> {
        let (previous_col, entry_col, _, _) = config;
        layouter.assign_region(
            || "assign log values",
            |mut region| {
                region.assign_advice(|| "previous", previous_col, 0, || self.previous_value)?;
                region.assign_advice(|| "entry", entry_col, 0, || self.entry_value)?;
                Ok(())
            },
        )?;
        Ok(())
    }
}

#[derive(Clone, Default)]
struct ExecutionCircuit {
    input_value: Value<Fp>,
    output_value: Value<Fp>,
    telemetry_value: Value<Fp>,
}

impl Circuit<Fp> for ExecutionCircuit {
    type Config = (
        plonk::Column<plonk::Advice>,
        plonk::Column<plonk::Advice>,
        plonk::Column<plonk::Advice>,
        plonk::Column<plonk::Instance>,
    );
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let input = meta.advice_column();
        let output = meta.advice_column();
        let telemetry = meta.advice_column();
        let expected = meta.instance_column();

        meta.enable_equality(input);
        meta.enable_equality(output);
        meta.enable_equality(telemetry);

        meta.create_gate("execution attestation", |meta| {
            let input_v = meta.query_advice(input, Rotation::cur());
            let output_v = meta.query_advice(output, Rotation::cur());
            let telemetry_v = meta.query_advice(telemetry, Rotation::cur());
            let expected_v = meta.query_instance(expected, Rotation::cur());
            vec![input_v + output_v + telemetry_v - expected_v]
        });

        (input, output, telemetry, expected)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), PlonkError> {
        let (input_col, output_col, telemetry_col, _) = config;
        layouter.assign_region(
            || "assign execution hashes",
            |mut region| {
                region.assign_advice(|| "input", input_col, 0, || self.input_value)?;
                region.assign_advice(|| "output", output_col, 0, || self.output_value)?;
                region.assign_advice(|| "telemetry", telemetry_col, 0, || self.telemetry_value)?;
                Ok(())
            },
        )?;
        Ok(())
    }
}

fn deterministic_rng(k: u32) -> StdRng {
    StdRng::seed_from_u64(PARAM_SEED ^ (k as u64))
}

fn shared_params(k: u32) -> Arc<Params<EqAffine>> {
    static CACHE: Lazy<Mutex<HashMap<u32, Arc<Params<EqAffine>>>>> =
        Lazy::new(|| Mutex::new(HashMap::new()));
    let mut guard = CACHE.lock().expect("params cache poisoned");
    guard
        .entry(k)
        .or_insert_with(|| Arc::new(Params::<EqAffine>::new(k)))
        .clone()
}

fn ensure_protocol(bundle: &ZkProofBundle) -> DbResult<()> {
    if bundle.protocol.as_str() == PROTOCOL_ID {
        Ok(())
    } else {
        Err(DatabaseError::ZeroKnowledge(format!(
            "unsupported protocol '{}': expected {}",
            bundle.protocol, PROTOCOL_ID
        )))
    }
}

fn ensure_circuit(bundle: &ZkProofBundle, expected: &str) -> DbResult<()> {
    if bundle.circuit.as_str() == expected {
        Ok(())
    } else {
        Err(DatabaseError::ZeroKnowledge(format!(
            "unexpected circuit '{}', expected {}",
            bundle.circuit, expected
        )))
    }
}

fn ensure_expected_hash(bundle: &ZkProofBundle, expected_bytes: &[u8]) -> DbResult<()> {
    let expected_hash = hash_expected_digest(expected_bytes);
    if bundle.expected_hash == expected_hash {
        Ok(())
    } else {
        Err(DatabaseError::Integrity(
            "expected commitment does not match stored hash".into(),
        ))
    }
}

fn ensure_relay_inputs(
    inputs: &JsonValue,
    guard_count: u32,
    exit_count: u32,
    expected_commitment: &[u8],
) -> DbResult<()> {
    let obj = inputs
        .as_object()
        .ok_or_else(|| DatabaseError::ZeroKnowledge("relay proof missing public inputs".into()))?;
    let guard = obj
        .get("guard_count")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| DatabaseError::ZeroKnowledge("relay proof missing guard_count".into()))?;
    let exit = obj
        .get("exit_count")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| DatabaseError::ZeroKnowledge("relay proof missing exit_count".into()))?;
    let commitment_hex = obj
        .get("commitment")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DatabaseError::ZeroKnowledge("relay proof missing commitment".into()))?;

    if guard != guard_count as u64 || exit != exit_count as u64 {
        return Err(DatabaseError::Integrity(
            "relay proof public counts do not match verification context".into(),
        ));
    }

    if hex::encode(expected_commitment) != commitment_hex {
        return Err(DatabaseError::Integrity(
            "relay proof commitment mismatch".into(),
        ));
    }
    Ok(())
}

fn ensure_log_inputs(
    inputs: &JsonValue,
    sequence_number: u64,
    expected_commitment: &[u8],
) -> DbResult<()> {
    let obj = inputs
        .as_object()
        .ok_or_else(|| DatabaseError::ZeroKnowledge("log proof missing public inputs".into()))?;
    let sequence = obj
        .get("sequence")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| DatabaseError::ZeroKnowledge("log proof missing sequence".into()))?;
    let commitment_hex = obj
        .get("commitment")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DatabaseError::ZeroKnowledge("log proof missing commitment".into()))?;

    if sequence != sequence_number {
        return Err(DatabaseError::Integrity(
            "log proof sequence does not match verification context".into(),
        ));
    }
    if hex::encode(expected_commitment) != commitment_hex {
        return Err(DatabaseError::Integrity(
            "log proof commitment mismatch".into(),
        ));
    }

    Ok(())
}

fn ensure_execution_inputs(inputs: &JsonValue, expected_commitment: &[u8]) -> DbResult<()> {
    let obj = inputs.as_object().ok_or_else(|| {
        DatabaseError::ZeroKnowledge("execution proof missing public inputs".into())
    })?;
    let commitment_hex = obj
        .get("commitment")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DatabaseError::ZeroKnowledge("execution proof missing commitment".into()))?;

    if hex::encode(expected_commitment) != commitment_hex {
        return Err(DatabaseError::Integrity(
            "execution proof commitment mismatch".into(),
        ));
    }

    Ok(())
}

fn normalise_digest(digest: &[u8]) -> Vec<u8> {
    if digest.len() == 32 {
        digest.to_vec()
    } else {
        Sha256::digest(digest).to_vec()
    }
}

pub fn hash_expected_digest(digest: &[u8]) -> String {
    hex::encode(Sha256::digest(digest))
}

fn digest_to_scalar(bytes: &[u8]) -> DbResult<Fp> {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    let limbs = [
        u64::from_le_bytes(arr[0..8].try_into().unwrap()),
        u64::from_le_bytes(arr[8..16].try_into().unwrap()),
        u64::from_le_bytes(arr[16..24].try_into().unwrap()),
        u64::from_le_bytes(arr[24..32].try_into().unwrap()),
    ];
    Ok(Fp::from_raw(limbs))
}

fn scalar_from_bytes(bytes: &[u8]) -> DbResult<Fp> {
    if bytes.len() != 32 {
        return Err(DatabaseError::ZeroKnowledge(
            "proof commitment must be 32 bytes".into(),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Option::from(Fp::from_repr(arr))
        .ok_or_else(|| DatabaseError::ZeroKnowledge("invalid field encoding".into()))
}

fn scalar_to_bytes(scalar: Fp) -> [u8; 32] {
    scalar.to_repr()
}

/// Commitment helper for relay audit proofs.
pub fn derive_relay_commitment(
    consensus_digest: &[u8],
    guard_count: u32,
    exit_count: u32,
) -> DbResult<[u8; 32]> {
    let consensus = digest_to_scalar(&normalise_digest(consensus_digest))?;
    let guard = Fp::from(guard_count as u64);
    let exit = Fp::from(exit_count as u64);
    let combined = consensus + guard + exit;
    Ok(scalar_to_bytes(combined))
}

/// Commitment helper for audit log integrity proofs.
pub fn derive_log_chain_commitment(
    previous_hash: &[u8],
    entry_hash: &[u8],
    sequence_number: u64,
) -> DbResult<[u8; 32]> {
    let previous = digest_to_scalar(&normalise_digest(previous_hash))?;
    let entry = digest_to_scalar(&normalise_digest(entry_hash))?;
    let sequence = Fp::from(sequence_number);
    let combined = previous + entry * sequence;
    Ok(scalar_to_bytes(combined))
}

/// Commitment helper for execution attestation proofs.
pub fn derive_execution_commitment(
    input_hash: &[u8],
    output_hash: &[u8],
    telemetry_hash: &[u8],
) -> DbResult<[u8; 32]> {
    let input = digest_to_scalar(&normalise_digest(input_hash))?;
    let output = digest_to_scalar(&normalise_digest(output_hash))?;
    let telemetry = digest_to_scalar(&normalise_digest(telemetry_hash))?;
    let combined = input + output + telemetry;
    Ok(scalar_to_bytes(combined))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_commitment_matches_manual_formula() {
        let bytes = derive_relay_commitment(b"consensus-root", 5, 7).expect("relay commitment");
        let consensus = digest_to_scalar(&normalise_digest(b"consensus-root")).expect("scalar");
        let manual = consensus + Fp::from(5u64) + Fp::from(7u64);
        assert_eq!(scalar_to_bytes(manual), bytes);
    }

    #[test]
    fn log_commitment_matches_manual_formula() {
        let bytes = derive_log_chain_commitment(b"prev", b"entry", 42).expect("log commitment");
        let previous = digest_to_scalar(&normalise_digest(b"prev")).expect("scalar");
        let entry = digest_to_scalar(&normalise_digest(b"entry")).expect("scalar");
        let manual = previous + entry * Fp::from(42u64);
        assert_eq!(scalar_to_bytes(manual), bytes);
    }

    #[test]
    fn execution_commitment_matches_manual_formula() {
        let bytes = derive_execution_commitment(b"input", b"output", b"telemetry")
            .expect("exec commitment");
        let input = digest_to_scalar(&normalise_digest(b"input")).expect("scalar");
        let output = digest_to_scalar(&normalise_digest(b"output")).expect("scalar");
        let telemetry = digest_to_scalar(&normalise_digest(b"telemetry")).expect("scalar");
        let manual = input + output + telemetry;
        assert_eq!(scalar_to_bytes(manual), bytes);
    }
}
