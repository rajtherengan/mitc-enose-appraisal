# MITC: review data and policy simulation

Supplementary material for the paper *Trusted Execution for Sensor-Based Health Diagnostics:
A Scoping Review and Attestation Appraisal Profile* (under double-blind review).

## Contents

- `review/review_workbook.xlsx`: PRISMA-ScR review data. Search log (8 OpenAlex queries, run 2026-10-12),
  eligibility criteria and the 2026-10-12 amendment, screening decisions for all 435 records,
  charting of the 55 included studies (32 read in full, 23 from abstracts), the seven MITC evidence
  elements per study, and PRISMA flow counts computed by formula.
- `simulation/`: Python simulation of the MITC acceptance predicate (Eqs. 2-3), with the results
  reported in Table IV. See `simulation/README.md` for what is real and what is simulated, the
  procedure, and the scope of the results.

## Reproduce Table IV

    cd simulation
    python3 -m venv .venv && source .venv/bin/activate
    pip install cryptography
    N=1000 python3 run_experiment.py

Accept/reject outcomes are deterministic; latencies depend on the machine.

## License

Code (`simulation/*.py`): MIT. Data (`review/`, `simulation/*.json`, `*.csv`, `*.txt`): CC BY 4.0.
