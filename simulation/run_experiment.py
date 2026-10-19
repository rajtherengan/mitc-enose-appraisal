"""Runs the MITC policy-validation experiment and writes results.json / results.csv."""
import copy, json, os, time, statistics, platform, csv, secrets
import mitc_policy as m

N = int(os.environ.get("N", 1000))           # transactions per test case
mfr, att = m.Manufacturer(), m.AttestationService()
FW_OK, FW_BAD = b"enose-fw-1.4.2", b"enose-fw-1.4.2-patched"
ACQ_OK  = {"adc_bits": 12, "fs_hz": 10, "heater_mV": 4500, "gain": 2}
ACQ_BAD = {"adc_bits": 12, "fs_hz": 10, "heater_mV": 3900, "gain": 2}
CAL8 = {"id": "cal-A-v8", "lineage": "A", "v": 8}; CAL5 = {"id": "cal-A-v5", "lineage": "A", "v": 5}
CAL_REV = {"id": "cal-A-v9r", "lineage": "A", "v": 9}; CAL_B2 = {"id": "cal-B-v2", "lineage": "B", "v": 2}
MOD3 = {"id": "model-3", "lineage": "M", "v": 3}; MOD4 = {"id": "model-4", "lineage": "M", "v": 4}

def world():
    dev = m.Device("enose-0001", FW_OK, mfr, att, ACQ_OK)
    P = m.Policy(mfr_pk=mfr.pk, att_pk=att.pk)
    P.Delta[dev.D] = {m.DOMAIN}; P.Phi[dev.D] = {m.H(FW_OK)}; P.Gamma[dev.D] = {m.H(m.canon(ACQ_OK))}
    P.Pi |= {(dev.D, CAL8["id"], MOD3["id"]), (dev.D, CAL5["id"], MOD3["id"]),
             (dev.D, CAL_REV["id"], MOD3["id"]), (dev.D, CAL_B2["id"], MOD3["id"])}
    P.Lam |= {CAL_REV["id"]}
    return dev, P

def nonce(P):
    n = secrets.token_hex(16); P.issued.add(n); return n

def reading(): return {"R_ohm": [secrets.randbelow(10**6) for _ in range(8)], "T_C": 34.1, "RH": 0.93}
RESULT = {"class": "screen-negative", "score": 0.12}

def valid_tx(dev, P, cal=CAL8, mod=MOD3):
    return dev.transaction(reading(), cal, mod, nonce(P), RESULT)

def prime(dev, P):        # establish state: accept v8 once so v8 is the lineage high-water mark
    ok, why = m.appraise(P, valid_tx(dev, P)); assert ok, why

CASES = []
def case(name, expected, what):
    def deco(f): CASES.append((name, expected, what, f)); return f
    return deco

@case("Valid reading, calibration, model", True, "Baseline correctness")
def t_valid(dev, P): return valid_tx(dev, P)

@case("Approved calibration in a separate lineage (B, v2 < A v8)", True, "Lineage-scoped version checks")
def t_lineage(dev, P): return valid_tx(dev, P, cal=CAL_B2)

@case("Replay of an accepted transaction", False, "Freshness and replay protection")
def t_replay(dev, P):
    tx = valid_tx(dev, P); ok, _ = m.appraise(P, tx); assert ok; return tx

@case("Unissued or reused nonce", False, "Freshness")
def t_nonce(dev, P): return dev.transaction(reading(), CAL8, MOD3, secrets.token_hex(16), RESULT)

@case("Revoked calibration", False, "Calibration authorization")
def t_revoked(dev, P): return valid_tx(dev, P, cal=CAL_REV)

@case("Calibration rollback (v5 after v8, same lineage)", False, "Rollback resistance")
def t_rollback(dev, P): return valid_tx(dev, P, cal=CAL5)

@case("Incompatible model version", False, "Model compatibility")
def t_model(dev, P): return valid_tx(dev, P, mod=MOD4)

@case("Unapproved acquisition configuration (signed)", False, "Configuration authorization")
def t_acq(dev, P):
    dev.A = ACQ_BAD; tx = valid_tx(dev, P); dev.A = ACQ_OK; return tx

@case("Acquisition configuration altered after signing", False, "Configuration integrity")
def t_acq_tamper(dev, P):
    tx = valid_tx(dev, P); tx["E"] = dict(tx["E"], A=m.H(m.canon(ACQ_BAD))); return tx

@case("Reading digest altered after signing", False, "Reading integrity")
def t_reading(dev, P):
    tx = valid_tx(dev, P); tx["E"] = dict(tx["E"], HR=m.H(b"spoofed")); return tx

@case("Inference output altered after signing", False, "Result integrity")
def t_output(dev, P):
    tx = valid_tx(dev, P); tx["y"] = {"class": "screen-positive", "score": 0.97}; return tx

@case("Unauthorized firmware (attested honestly)", False, "Firmware authorization")
def t_fw(dev, P):
    bad = m.Device(dev.D, FW_BAD, mfr, att, ACQ_OK); bad.counter = dev.counter + 10**6
    return bad.transaction(reading(), CAL8, MOD3, nonce(P), RESULT)

@case("Certified key not bound to attested firmware", False, "Key-to-attestation binding")
def t_bind(dev, P):
    rogue = m.Device(dev.D, FW_OK, mfr, att, ACQ_OK)     # second certified key for D ...
    rogue.attest = dev.attest                             # ... presenting the genuine device's attestation
    rogue.counter = dev.counter + 10**6
    return rogue.transaction(reading(), CAL8, MOD3, nonce(P), RESULT)

@case("Domain label altered after signing", False, "Context-label integrity")
def t_domain_tamper(dev, P):
    tx = valid_tx(dev, P); tx["delta"] = m.OTHER.decode(); return tx

@case("Correctly signed in a disallowed context", False, "Context authorization")
def t_domain_ctx(dev, P):     # genuine device, valid signature, but under the telemetry context
    return dev.transaction(reading(), CAL8, MOD3, nonce(P), RESULT, domain=m.OTHER)

@case("Delayed out-of-order valid transaction (strict counter)", False, "Documented trade-off: false rejection")
def t_ooo(dev, P):
    late = valid_tx(dev, P); newer = valid_tx(dev, P)
    ok, _ = m.appraise(P, newer); assert ok; return late

def warmup(n=200):
    """Untimed appraisals so that the first timed case is not penalised by cold caches."""
    for _ in range(n):
        dev, P = world(); prime(dev, P); m.appraise(P, valid_tx(dev, P))

def run():
    warmup()
    rows = []
    for name, expected, what, f in CASES:
        accepted, reasons, lat = 0, {}, []
        for _ in range(N):
            dev, P = world(); prime(dev, P)
            tx = f(dev, P)                                   # generation is not timed
            t0 = time.perf_counter_ns(); ok, why = m.appraise(P, tx); t1 = time.perf_counter_ns()
            lat.append((t1 - t0) / 1e3)
            accepted += ok
            if why: reasons[why] = reasons.get(why, 0) + 1
        rows.append({"case": name, "property": what, "expected": "accept" if expected else "reject",
                     "n": N, "accepted": accepted, "rejected": N - accepted,
                     "as_expected": (accepted == N) if expected else (accepted == 0),
                     "rejecting_condition": ", ".join(f"{k} ({v})" for k, v in reasons.items()) or "-",
                     "median_us": round(statistics.median(lat), 1),
                     "p95_us": round(sorted(lat)[int(0.95 * len(lat)) - 1], 1)})   # nearest-rank 95th percentile
    return rows

def ablation(n=200):
    """Disable the condition that rejected each attack; report whether the attack is then accepted."""
    out = []
    for name, expected, what, f in CASES:
        if expected: continue
        first = None
        for _ in range(n):
            dev, P = world(); prime(dev, P); tx = f(dev, P)
            P0 = copy.deepcopy(P); ok, why = m.appraise(P0, tx); first = why
            ok2, why2 = m.appraise(copy.deepcopy(P), tx, disabled=frozenset([why]))
            out.append((name, why, ok2, why2))
        acc = sum(1 for o in out if o[0] == name and o[2])
        nxt = sorted({o[3] for o in out if o[0] == name and not o[2]} - {None})
        yield {"case": name, "disabled_condition": first, "n": n, "accepted_when_disabled": acc,
               "next_catching_condition": ", ".join(nxt) or "-"}

def microbench(n=None):
    """Median cost of the primitives inside appraise(), to explain the appraisal time."""
    n = n or N
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.generate(); pk = sk.public_key(); msg = b"x" * 400; sig = sk.sign(msg)
    def med(fn):
        t = []
        for _ in range(n):
            t0 = time.perf_counter_ns(); fn(); t.append((time.perf_counter_ns() - t0) / 1e3)
        return round(statistics.median(t), 1)
    dev, P = world(); prime(dev, P)
    return {"ed25519_verify_us": med(lambda: pk.verify(sig, msg)),
            "ed25519_sign_us": med(lambda: sk.sign(msg)),
            "sha256_400B_us": med(lambda: m.H(msg)),
            "device_transaction_us": med(lambda: valid_tx(dev, P))}

if __name__ == "__main__":
    rows = run()
    abl = list(ablation())
    json.dump(abl, open("ablation.json", "w"), indent=1)
    for a in abl: print("ABL", a)
    env = {"python": platform.python_version(), "cpu": platform.processor() or "x86_64",
           "cryptography": __import__("cryptography").__version__, "N_per_case": N,
           "date": time.strftime("%Y-%m-%d"), **microbench()}
    json.dump({"environment": env, "results": rows}, open("results.json", "w"), indent=1)
    with open("results.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    for r in rows:
        print(f'{r["case"][:55]:55s} exp={r["expected"]:6s} acc={r["accepted"]:4d}/{r["n"]} ok={r["as_expected"]} '
              f'cond={r["rejecting_condition"][:28]:28s} med={r["median_us"]}us p95={r["p95_us"]}us')
    print(env)
