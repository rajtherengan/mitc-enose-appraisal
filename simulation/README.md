# MITC policy-validation simulation

Software simulation of the MITC acceptance predicate (Eqs. 2-3 of the paper).
It validates the policy logic only. It does not test hardware isolation, the ADC path, or side channels.

## Run

    pip install cryptography
    N=1000 python3 run_experiment.py

Outputs: `results.json` / `results.csv` (per-case accept/reject counts, rejecting condition, appraisal latency),
`ablation.json` (each rejecting condition disabled in turn), and primitive timings in `results.json -> environment`.

## What is real and what is simulated

Real: every Ed25519 signature and verification (manufacturer certificate, attestation evidence, device
signature sigma) and every SHA-256 digest is computed with pyca/cryptography. The verifier's policy state
(Delta, Phi, Gamma, Pi, Lambda, version high-water marks, counter, issued nonces) is real and is updated on accept.

Simulated: the manufacturer CA, the attestation service, and the device are ordinary software keys in one
process. "Attestation" is an Ed25519 signature by a software attestation key over (D, F, H(pk_D)); there is no
hardware root of trust, TEE quote, or measured boot. F is the SHA-256 of a firmware identifier string. The
sensor reading is 8 random resistance values plus fixed temperature and humidity; the inference result is fixed.

## Procedure

For each case and each of N repetitions, a fresh world is built: a new device key, certificate and
attestation; a policy with Delta_D, Phi_D, Gamma_D, Pi and Lambda; and one accepted priming transaction
(calibration A v8) so that version and counter high-water marks exist. The case function then builds one
valid transaction and applies exactly one change (or, for the two valid cases, none). Only the verifier
call `appraise()` is timed (time.perf_counter_ns); key generation, signing, and transaction building are not.
Appraisal includes JSON parsing of certificate and attestation bodies, up to three Ed25519 verifications,
one SHA-256 of pk_D, canonical encoding of E and y, set look-ups, and the state update on accept.
200 untimed appraisals run first as a warm-up. Median and nearest-rank 95th percentile are over the N timings.
Conditions are checked in the order of Eq. (3) and the first failure is reported; appraisal time therefore
depends on how far a transaction gets (a Bind failure skips the third verification).

Ablation: for each rejected case, 200 fresh transactions are appraised with the first rejecting condition
disabled. It shows whether another condition still rejects; it does not show that any check is sufficient
or indispensable on its own.

Latency depends on the machine; see `environment` in results.json. `previous_run_v1/results_v1.csv` holds the table from
the earlier code version (before the delta-in-Delta_D check), kept for the record only.

## Scope of the results

The 1,000 repetitions per case are independently generated instances of the same attack pattern (fresh keys,
certificates, attestation, policy, nonces, and readings), not distinct attack techniques. The cases are
representative single-element policy violations under controlled assumptions; they do not establish resistance
to combined or adaptive attacks, compromised trusted code, hardware-level manipulation, or side channels.
