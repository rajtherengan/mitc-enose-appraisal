"""MITC acceptance-predicate evaluator (software simulation of Eq. (2)-(3)).

Validates the LOGICAL behaviour of the MITC appraisal policy only. It does not
model hardware isolation, a secure ADC path, side channels, or a real TEE: the
"device" and "attestation service" below are simulated with ordinary software keys.

Cryptography: Ed25519 signatures (device key, manufacturer CA, attestation key),
SHA-256 digests. Library: pyca/cryptography.
"""
import hashlib, json, os, time, statistics, copy, platform
from dataclasses import dataclass, field
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

DOMAIN = b"MITC-v1|e-nose-breath|appraisal"          # delta in Eq. (2): the diagnostic context
OTHER  = b"MITC-v1|env-telemetry|appraisal"          # another context the same device key may sign in

def H(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def raw(pk) -> bytes:
    return pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

# ---------------------------------------------------------------- authorities
class Manufacturer:                                    # issues device certificates (Cert)
    def __init__(self):
        self.sk = Ed25519PrivateKey.generate(); self.pk = self.sk.public_key()
    def certify(self, device_id, pk_dev):
        body = canon({"D": device_id, "pk": raw(pk_dev).hex()})
        return {"body": body, "sig": self.sk.sign(body)}

class AttestationService:                              # simulated root of trust (Att, Bind)
    def __init__(self):
        self.sk = Ed25519PrivateKey.generate(); self.pk = self.sk.public_key()
    def attest(self, device_id, firmware_meas, pk_dev):
        # evidence binds the signing key to the device and the measured code context
        body = canon({"D": device_id, "F": firmware_meas, "pk_hash": H(raw(pk_dev))})
        return {"body": body, "sig": self.sk.sign(body)}

# ---------------------------------------------------------------- device (inside B)
class Device:
    def __init__(self, device_id, firmware, mfr, att, acq_cfg):
        self.D = device_id; self.F = H(firmware)
        self.sk = Ed25519PrivateKey.generate(); self.pk = self.sk.public_key()
        self.cert = mfr.certify(device_id, self.pk)
        self.attest = att.attest(device_id, self.F, self.pk)
        self.counter = 0; self.A = acq_cfg
    def transaction(self, reading, cal, model, nonce, result, domain=DOMAIN):
        self.counter += 1
        E = {"D": self.D, "F": self.F, "A": H(canon(self.A)), "C": cal, "M": model,
             "N": nonce, "HR": H(canon(reading))}
        msg = domain + canon(E) + bytes.fromhex(H(canon(result))) + self.counter.to_bytes(8, "big")
        return {"delta": domain.decode(), "E": E, "y": result, "c": self.counter, "sigma": self.sk.sign(msg),
                "pk": raw(self.pk).hex(), "cert": self.cert, "att": self.attest}

# ---------------------------------------------------------------- verifier (Eq. 3)
@dataclass
class Policy:
    mfr_pk: object; att_pk: object
    Delta: dict = field(default_factory=dict)      # D -> authorized signing contexts (delta in Delta_D)
    Phi: dict = field(default_factory=dict)        # D -> authorized firmware measurements
    Gamma: dict = field(default_factory=dict)      # D -> approved acquisition-config digests
    Pi: set = field(default_factory=set)           # approved (D, calibration id, model id)
    Lam: set = field(default_factory=set)          # revoked calibration/model ids
    vmax_C: dict = field(default_factory=dict)     # (D, lineage) -> highest accepted calibration version
    vmax_M: dict = field(default_factory=dict)     # (D, lineage) -> highest accepted model version
    cmax: dict = field(default_factory=dict)       # D -> highest accepted counter
    issued: set = field(default_factory=set)       # outstanding verifier nonces

def _ok(pk, sig, body):
    try: pk.verify(sig, body); return True
    except InvalidSignature: return False

def appraise(P: Policy, tx, disabled=frozenset()):
    """Returns (accept: bool, failed_condition: str|None). Conditions evaluated in Eq. (3) order."""
    E, y, c = tx["E"], tx["y"], tx["c"]; D = E["D"]
    pkD = Ed25519PublicKey.from_public_bytes(bytes.fromhex(tx["pk"]))
    cert = json.loads(tx["cert"]["body"]); att = json.loads(tx["att"]["body"])
    if "Cert" not in disabled and not (_ok(P.mfr_pk, tx["cert"]["sig"], tx["cert"]["body"]) and cert["D"] == D and cert["pk"] == tx["pk"]):
        return False, "Cert"
    if "Att" not in disabled and not _ok(P.att_pk, tx["att"]["sig"], tx["att"]["body"]):
        return False, "Att"
    if "Bind" not in disabled and not (att["pk_hash"] == H(bytes.fromhex(tx["pk"])) and att["D"] == D and att["F"] == E["F"]):
        return False, "Bind"
    delta = tx["delta"].encode()
    msg = delta + canon(E) + bytes.fromhex(H(canon(y))) + c.to_bytes(8, "big")
    if "Vf" not in disabled and not _ok(pkD, tx["sigma"], msg):
        return False, "Vf"
    if "delta in Delta" not in disabled and delta not in P.Delta.get(D, set()):
        return False, "delta in Delta"
    if "Fresh" not in disabled and E["N"] not in P.issued:
        return False, "Fresh"
    if "F in Phi" not in disabled and E["F"] not in P.Phi.get(D, set()):
        return False, "F in Phi"
    if "A in Gamma" not in disabled and E["A"] not in P.Gamma.get(D, set()):
        return False, "A in Gamma"
    cal, mod = E["C"], E["M"]
    if "(D,C,M) in Pi" not in disabled and (D, cal["id"], mod["id"]) not in P.Pi:
        return False, "(D,C,M) in Pi"
    if "not revoked" not in disabled and (cal["id"] in P.Lam or mod["id"] in P.Lam):
        return False, "not revoked"
    if "version >= max" not in disabled and (cal["v"] < P.vmax_C.get((D, cal["lineage"]), 0) or mod["v"] < P.vmax_M.get((D, mod["lineage"]), 0)):
        return False, "version >= max"
    if "counter > max" not in disabled and c <= P.cmax.get(D, 0):
        return False, "counter > max"
    # accept: atomically update durable replay/version state
    P.issued.discard(E["N"]); P.cmax[D] = c
    P.vmax_C[(D, cal["lineage"])] = max(cal["v"], P.vmax_C.get((D, cal["lineage"]), 0))
    P.vmax_M[(D, mod["lineage"])] = max(mod["v"], P.vmax_M.get((D, mod["lineage"]), 0))
    return True, None
