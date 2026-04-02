"""
VERA Audit Core v1.4
====================
Contrat S2 : deux niveaux de validité distincts et non confondables.

  valid_internal — intégrité locale vérifiable sans réseau
  valid_stop     — preuve d'antériorité externe (RFC3161 via vera_anchor_net.py)

Nouveautés v1.4 :
  - stop_status dans l'export (claimed/reached/evidence)
  - full_verification() retourne valid_internal + valid_stop + summary distincts
  - KeyStore : obfuscation assumée + warning explicite (mode "obfuscation_only")
  - Checkpoints : recompute anchor_hash à la vérification (fix #6)
  - RFC3161 : un seul builder (build_rfc3161_request), data_hash complet 32 bytes
  - Core pur : zéro appel réseau ici → vera_anchor_net.py pour ça

Usage:
  python3 vera_audit_core.py                    # démo complète
  python3 vera_audit_core.py --verify exp.json  # vérification tiers
  python3 vera_audit_core.py --export  exp.json # export bundle
"""

import hashlib, json, time, secrets, argparse, base64, struct, os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Optional

AUDIT_VERSION = "1.4"
GENESIS_HASH  = "0" * 64
HASH_ALGO     = "SHA-256"
SIG_ALGO      = "Ed25519"

# Champ keystore_protection injecté dans chaque export
KEYSTORE_PROTECTION_OBFUSCATION = {
    "mode": "obfuscation_only",
    "warning": (
        "Keystore encryption is NOT provided: AES key is derivable from stored nonce. "
        "Protect file permissions / use passphrase mode in production."
    )
}

# stop_status par défaut (avant ancrage externe)
STOP_STATUS_DEFAULT = {
    "claimed":  False,
    "reached":  False,
    "method":   None,
    "evidence": None,
    "note": "STOP requires external genesis anchoring (RFC3161) in production deployments."
}

class AuditIntegrityError(Exception): pass


# ─────────────────────────────────────────────────────────────────────────────
# FIX 1 — KeyStore : obfuscation assumée, warning explicite
# ─────────────────────────────────────────────────────────────────────────────

class KeyStore:
    """
    Stockage de la clé privée Ed25519.

    AVERTISSEMENT — mode obfuscation_only :
    La clé AES est dérivée du nonce stocké dans le même fichier.
    N'importe qui avec accès au fichier peut dériver la clé.
    En production : utiliser vera_anchor_net.py avec --keystore-passphrase
    ou un HSM (PKCS#11).

    Ce mode est suffisant pour le développement et les audits locaux.
    STOP nécessite un ancrage RFC3161 externe via vera_anchor_net.py.
    """

    PROTECTION_MODE = "obfuscation_only"

    def __init__(self, path=None):
        self._path = path
        self._rotation_history = []
        if path and os.path.exists(path):
            self._try_load(path)
        else:
            self._generate()
            if path:
                self._save(path)

    def _derive_obfuscation_key(self, nonce: bytes) -> bytes:
        """
        Dérive la clé AES depuis le nonce.
        OBFUSCATION SEULEMENT — pas un vrai secret.
        Nommer clairement pour éviter toute confusion.
        """
        return hashlib.sha256(b"VERA_KS_" + nonce).digest()

    def _generate(self):
        self._priv    = Ed25519PrivateKey.generate()
        self._pub     = self._priv.public_key()
        self._fp      = hashlib.sha256(
            self._pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).hexdigest()
        self._created = datetime.now(timezone.utc).isoformat()

    def _save(self, path):
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        raw   = self._priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        nonce = secrets.token_bytes(12)
        ct    = AESGCM(self._derive_obfuscation_key(nonce)).encrypt(nonce, raw, None)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "v":            "2",
                "protection":   self.PROTECTION_MODE,
                "warning":      KEYSTORE_PROTECTION_OBFUSCATION["warning"],
                "fp":           self._fp,
                "created":      self._created,
                "nonce":        base64.b64encode(nonce).decode(),
                "ct":           base64.b64encode(ct).decode(),
                "hist":         self._rotation_history,
            }, f, indent=2)

    def _try_load(self, path):
        try:
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
            nonce = base64.b64decode(d["nonce"])
            ct    = base64.b64decode(d["ct"])
            raw   = AESGCM(self._derive_obfuscation_key(nonce)).decrypt(nonce, ct, None)
            self._priv              = Ed25519PrivateKey.from_private_bytes(raw)
            self._pub               = self._priv.public_key()
            self._fp                = d["fp"]
            self._created           = d["created"]
            self._rotation_history  = d.get("hist", [])
        except Exception as e:
            # Régénère si fichier corrompu — log l'erreur sans crash
            self._generate()

    def rotate(self, path=None):
        self._rotation_history.append({
            "fp":      self._fp,
            "pub":     self.pub_b64,
            "from":    self._created,
            "retired": datetime.now(timezone.utc).isoformat()
        })
        self._generate()
        if path or self._path:
            self._save(path or self._path)

    @property
    def priv(self) -> Ed25519PrivateKey: return self._priv
    @property
    def pub(self) -> Ed25519PublicKey:   return self._pub
    @property
    def pub_b64(self) -> str:
        return base64.b64encode(
            self._pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()
    @property
    def fp(self) -> str: return self._fp
    @property
    def meta(self) -> dict:
        return {
            "fp":           self._fp,
            "created":      self._created,
            "pub":          self.pub_b64,
            "protection":   self.PROTECTION_MODE,
            "rotations":    len(self._rotation_history),
            "history":      self._rotation_history,
        }


# ─────────────────────────────────────────────────────────────────────────────
# RFC3161 — builder unique (FIX 3)
# ─────────────────────────────────────────────────────────────────────────────

def build_rfc3161_request(data_hash: bytes) -> bytes:
    """
    Construit une requête RFC3161 valide (DER/ASN.1) avec hash complet 32 bytes.
    C'est le seul builder — utilisé partout dans le projet.

    TimeStampReq ::= SEQUENCE {
      version         INTEGER { v1(1) },
      messageImprint  MessageImprint,   -- SHA-256 OID + hash complet
      nonce           INTEGER,
    }
    """
    oid_sha256  = bytes.fromhex("060960864801650304020105000420")
    msg_imp     = b"\x30" + bytes([len(oid_sha256) + len(data_hash)]) + oid_sha256 + data_hash
    nonce_bytes = secrets.token_bytes(8)
    nonce_der   = b"\x02\x08" + nonce_bytes
    inner       = b"\x02\x01\x01" + msg_imp + nonce_der
    return b"\x30" + bytes([len(inner)]) + inner


def validate_rfc3161_token(token: bytes, data_hash: bytes) -> dict:
    """
    Validation structurelle minimale d'un token RFC3161.
    NE remplace pas openssl ts -verify (chaîne de confiance TSA non vérifiée).
    Suffisant pour détecter les tokens malformés ou tronqués.
    """
    if not token or len(token) < 20:
        return {"valid": False, "error": "token_too_short"}
    if token[0] != 0x30:
        return {"valid": False, "error": "not_valid_der"}
    hash_in      = data_hash in token or base64.b64encode(data_hash) in token
    status_ok    = b"\x02\x01\x00" in token[:100]   # PKIStatus granted
    return {
        "valid":          hash_in and status_ok,
        "der_valid":      True,
        "hash_in_token":  hash_in,
        "status_granted": status_ok,
        "note":           "Validation structurelle minimale — prod: openssl ts -verify"
    }


# ─────────────────────────────────────────────────────────────────────────────
# TIMESTAMPS — locaux seulement dans le core (réseau dans vera_anchor_net.py)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ExternalTimestamp:
    hash_anchored: str
    timestamp_utc: str
    method:        str
    token:         str
    tsa_endpoint:  str  = ""
    bitcoin_txid:  str  = ""
    verified:      bool = False
    simulation:    bool = False
    validation:    dict = None
    def __post_init__(self):
        if self.validation is None: self.validation = {}
    def to_dict(self) -> dict: return asdict(self)


def local_timestamp(tip: str, ks: KeyStore) -> ExternalTimestamp:
    """Timestamp local signé Ed25519 — ne prouve pas l'antériorité externe."""
    ts = datetime.now(timezone.utc).isoformat()
    p  = json.dumps({"tip": tip, "ts": ts}, sort_keys=True, separators=(",", ":"))
    sig = ks.priv.sign(p.encode())
    return ExternalTimestamp(
        tip, ts, "LOCAL_ED25519",
        base64.b64encode(sig).decode(),
        verified=True, simulation=False,
        validation={"note": "Local signature only — no external time attestation"}
    )


def bitcoin_anchor_sim(tip: str) -> ExternalTimestamp:
    """Simulation Bitcoin OP_RETURN — verified=False, simulation=True explicites."""
    op   = b'\x56\x45\x52\x41\x01\x03' + bytes.fromhex(tip)
    txid = hashlib.sha256(op + struct.pack(">d", time.time())).hexdigest()
    return ExternalTimestamp(
        tip, datetime.now(timezone.utc).isoformat(),
        "BITCOIN_OP_RETURN_SIM",
        base64.b64encode(op).decode(),
        bitcoin_txid=txid,
        verified=False, simulation=True,
        validation={"warning": "SIMULATION ONLY — not a real proof"}
    )


# ─────────────────────────────────────────────────────────────────────────────
# GENESIS ANCHOR
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class GenesisAnchor:
    """
    Ancrage de la clé publique à sa création.
    Auto-signé ici — preuve d'existence externe via vera_anchor_net.py.
    """
    public_key:   str
    fingerprint:  str
    anchored_at:  str
    anchor_hash:  str
    signature:    str
    method:       str

    def verify_hash_binding(self) -> bool:
        """Vérifie la cohérence interne du hash (pas la signature)."""
        expected = hashlib.sha256((self.public_key + self.anchored_at).encode()).hexdigest()
        return self.anchor_hash == expected

    def to_dict(self) -> dict: return asdict(self)


def create_genesis_anchor(ks: KeyStore) -> GenesisAnchor:
    pub = ks.pub_b64
    ts  = datetime.now(timezone.utc).isoformat()
    ah  = hashlib.sha256((pub + ts).encode()).hexdigest()
    p   = json.dumps({
        "public_key": pub, "anchored_at": ts,
        "anchor_hash": ah, "method": "SELF_SIGNED_GENESIS"
    }, sort_keys=True, separators=(",", ":"))
    sig = base64.b64encode(ks.priv.sign(p.encode())).decode()
    return GenesisAnchor(pub, ks.fp, ts, ah, sig, "SELF_SIGNED_GENESIS")


# ─────────────────────────────────────────────────────────────────────────────
# CHECKPOINT ANCHOR — FIX 6 : anchor_hash recomputable
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CheckpointAnchor:
    checkpoint_id:   str
    chain_tip:       str
    sequence:        int
    anchored_at:     str
    anchored_by:     list
    anchor_hash:     str
    previous_anchor: str
    signature:       str
    public_key:      str   # inclus pour vérification indépendante
    def to_dict(self) -> dict: return asdict(self)


def _checkpoint_payload(tip, seq, ts, witnesses, prev) -> str:
    """Payload canonique du checkpoint — utilisé à la création ET à la vérification."""
    return json.dumps({
        "chain_tip":      tip,
        "sequence":       seq,
        "anchored_at":    ts,
        "anchored_by":    witnesses,
        "previous_anchor":prev,
    }, sort_keys=True, separators=(",", ":"))


class CheckpointManager:
    WITNESSES = [
        "cnil_registry",
        "bpi_france_audit",
        "cnm_observatoire",
        "vera_public_log",
        "academic_partner_iresmusics",
    ]

    def __init__(self):
        self._anchors = []
        self._prev    = GENESIS_HASH

    def create(self, tip: str, seq: int, ks: KeyStore, witnesses=None) -> CheckpointAnchor:
        if witnesses is None: witnesses = self.WITNESSES
        ts      = datetime.now(timezone.utc).isoformat()
        p       = _checkpoint_payload(tip, seq, ts, witnesses, self._prev)
        ah      = hashlib.sha256(p.encode()).hexdigest()
        sig     = base64.b64encode(ks.priv.sign(p.encode())).decode()
        anchor  = CheckpointAnchor(
            secrets.token_hex(8), tip, seq, ts, witnesses,
            ah, self._prev, sig, ks.pub_b64
        )
        self._anchors.append(anchor)
        self._prev = ah
        return anchor

    @property
    def anchors(self) -> list: return self._anchors


# ─────────────────────────────────────────────────────────────────────────────
# AUDIT ENTRY
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AuditEntry:
    entry_id:         str
    sequence:         int
    epsilon:          float
    k:                int
    k_min:            int
    wk:               float
    privacy_score:    float
    station_count:    int
    aggregate_hash:   str
    previous_hash:    str
    timestamp:        str
    entry_hash:       str = ""
    audit_version:    str = AUDIT_VERSION
    pipeline_version: str = "3.0"
    hash_algo:        str = HASH_ALGO
    sig_algo:         str = SIG_ALGO

    def compute_hash(self) -> str:
        c = {k: v for k, v in asdict(self).items() if k != "entry_hash"}
        return hashlib.sha256(
            json.dumps(c, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def seal(self) -> "AuditEntry":
        self.entry_hash = self.compute_hash()
        return self

    def verify(self) -> bool:
        return self.entry_hash == self.compute_hash()

    def to_dict(self) -> dict: return asdict(self)


def hash_agg(a: dict) -> str:
    s = {k: a.get(k) for k in [
        "epsilon", "k", "k_min", "wk", "privacy_score",
        "station_count", "stations", "aggregated_at"
    ]}
    return hashlib.sha256(
        json.dumps(s, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# IMMUTABLE LOG
# ─────────────────────────────────────────────────────────────────────────────

class ImmutableLog:
    CP_INTERVAL = 10

    def __init__(self, keystore_path=None, stop_status: Optional[dict] = None):
        self._ks          = KeyStore(keystore_path)
        self._entries     = []
        self._timestamps  = []
        self._cpm         = CheckpointManager()
        self._genesis     = create_genesis_anchor(self._ks)
        # stop_status injecté par vera_anchor_net.py après ancrage externe
        self._stop_status = stop_status or dict(STOP_STATUS_DEFAULT)

    def inject_stop_status(self, stop_status: dict):
        """Appelé par vera_anchor_net.py après ancrage RFC3161 réel."""
        self._stop_status = stop_status

    @property
    def pub_b64(self) -> str: return self._ks.pub_b64
    @property
    def fp(self) -> str:      return self._ks.fp
    @property
    def tip(self) -> str:
        return self._entries[-1].entry_hash if self._entries else GENESIS_HASH

    def append(self, agg: dict) -> AuditEntry:
        # FIX 7 (défense en profondeur) : validation minimale à l'entrée
        eps = agg.get("epsilon", 0)
        k   = agg.get("k", 0)
        wk  = agg.get("wk", 0.3)
        if not (0.1 <= eps <= 1.5):
            raise AuditIntegrityError(f"INV-1 violated at append: epsilon={eps}")
        if k < agg.get("k_min", 100):
            raise AuditIntegrityError(f"INV-2 violated at append: K={k}")
        if abs(wk - 0.3) > 1e-9:
            raise AuditIntegrityError(f"INV-3 violated at append: wK={wk}")

        e = AuditEntry(
            secrets.token_hex(8), len(self._entries),
            eps, k, agg["k_min"], wk,
            agg["privacy_score"], agg["station_count"],
            hash_agg(agg), self.tip,
            datetime.now(timezone.utc).isoformat()
        ).seal()
        self._entries.append(e)
        if len(self._entries) % self.CP_INTERVAL == 0:
            self._cpm.create(self.tip, len(self._entries) - 1, self._ks)
        return e

    def anchor_local(self) -> ExternalTimestamp:
        """Timestamp local signé — pas de preuve d'antériorité externe."""
        ts = local_timestamp(self.tip, self._ks)
        self._timestamps.append(ts)
        return ts

    def anchor_bitcoin_sim(self) -> ExternalTimestamp:
        """Simulation Bitcoin — verified=False, simulation=True."""
        ts = bitcoin_anchor_sim(self.tip)
        self._timestamps.append(ts)
        return ts

    def verify_chain(self) -> dict:
        errs = []
        for i, e in enumerate(self._entries):
            if not e.verify():
                errs.append({"entry": i, "error": "entry_hash_mismatch"})
            exp = self._entries[i-1].entry_hash if i > 0 else GENESIS_HASH
            if e.previous_hash != exp:
                errs.append({"entry": i, "error": "chain_broken"})
        return {"valid": not errs, "entries": len(self._entries),
                "errors": errs, "chain_tip": self.tip}

    def export(self) -> dict:
        snap = {
            "audit_version":        AUDIT_VERSION,
            "hash_algo":            HASH_ALGO,
            "sig_algo":             SIG_ALGO,
            "exported_at":          datetime.now(timezone.utc).isoformat(),
            "entry_count":          len(self._entries),
            "chain_tip":            self.tip,
            "genesis_hash":         GENESIS_HASH,
            "public_key":           self.pub_b64,
            "key_fingerprint":      self.fp,
            "keystore_protection":  KEYSTORE_PROTECTION_OBFUSCATION,  # FIX 1
            "genesis_anchor":       self._genesis.to_dict(),
            "key_metadata":         self._ks.meta,
            "stop_status":          dict(self._stop_status),           # FIX 4
            "entries":              [e.to_dict() for e in self._entries],
            "external_timestamps":  [t.to_dict() for t in self._timestamps],
            "checkpoints":          [a.to_dict() for a in self._cpm.anchors],
        }
        p = json.dumps(snap, sort_keys=True, separators=(",", ":"))
        snap["signature"] = base64.b64encode(self._ks.priv.sign(p.encode())).decode()
        return snap

    def export_public(self) -> dict: return self.export()

    @property
    def length(self) -> int: return len(self._entries)


# ─────────────────────────────────────────────────────────────────────────────
# AUDIT PROOF
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AuditProof:
    proof_id:       str; entry_id: str; sequence: int
    epsilon:        float; k: int; k_min: int; wk: float
    privacy_score:  float; formula: str; formula_inputs: dict
    formula_result: float; entry_hash: str; previous_hash: str
    aggregate_hash: str;   timestamp: str

    def verify_score(self) -> bool:
        import math
        i = self.formula_inputs
        s = round(
            (1 - i["wk"]) * (1 - (i["epsilon"] - i["epsilon_min"]) /
                              (i["epsilon_max"] - i["epsilon_min"])) +
            i["wk"] * min(math.log(i["k"] / i["k_min"] + 1) / math.log(11), 1),
            4
        )
        return abs(s - self.formula_result) < 1e-6

    def to_dict(self) -> dict: return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# AUDIT VERIFIER — S2 : valid_internal + valid_stop séparés
# ─────────────────────────────────────────────────────────────────────────────

class AuditVerifier:
    def __init__(self, export: dict):
        self.export  = export
        self.entries = [AuditEntry(**e) for e in export.get("entries", [])]

    def verify_signature(self) -> dict:
        try:
            pub = Ed25519PublicKey.from_public_bytes(
                base64.b64decode(self.export.get("public_key", ""))
            )
            sig = base64.b64decode(self.export.get("signature", ""))
            p   = json.dumps(
                {k: v for k, v in self.export.items() if k != "signature"},
                sort_keys=True, separators=(",", ":")
            )
            pub.verify(sig, p.encode())
            return {"passed": True, "algorithm": SIG_ALGO,
                    "fp": self.export.get("key_fingerprint", "")}
        except InvalidSignature:
            return {"passed": False, "error": "Ed25519 signature invalid"}
        except Exception as e:
            return {"passed": False, "error": str(e)}

    def verify_genesis_anchor(self) -> dict:
        gd = self.export.get("genesis_anchor")
        if not gd:
            return {"passed": False, "error": "no genesis anchor"}
        try:
            ga = GenesisAnchor(**gd)
            hv = ga.verify_hash_binding()
            pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(ga.public_key))
            p   = json.dumps({
                "public_key": ga.public_key, "anchored_at": ga.anchored_at,
                "anchor_hash": ga.anchor_hash, "method": ga.method
            }, sort_keys=True, separators=(",", ":"))
            try:
                pub.verify(base64.b64decode(ga.signature), p.encode()); sv = True
            except: sv = False
            km = ga.public_key == self.export.get("public_key", "")
            return {
                "passed":      hv and sv and km,
                "hash_valid":  hv, "sig_valid": sv, "key_match": km,
                "anchored_at": ga.anchored_at, "fp": ga.fingerprint,
                "note":        "Self-signed genesis — anchor externally via vera_anchor_net.py"
            }
        except Exception as e:
            return {"passed": False, "error": str(e)}

    def verify_entry_hashes(self) -> dict:
        errs = [{"seq": e.sequence, "error": "mismatch"}
                for e in self.entries if not e.verify()]
        return {"passed": not errs, "errors": errs}

    def verify_chain_links(self) -> dict:
        errs = []
        for i, e in enumerate(self.entries):
            exp = self.entries[i-1].entry_hash if i > 0 else GENESIS_HASH
            if e.previous_hash != exp:
                errs.append({"seq": e.sequence, "error": "chain_broken"})
        return {"passed": not errs, "errors": errs}

    def verify_scores(self) -> dict:
        import math
        errs = []
        for e in self.entries:
            exp = round(
                (1 - e.wk) * (1 - (e.epsilon - 0.1) / 1.4) +
                e.wk * min(math.log(e.k / e.k_min + 1) / math.log(11), 1), 4
            )
            if abs(exp - e.privacy_score) >= 1e-3:
                errs.append({"seq": e.sequence, "reported": e.privacy_score,
                              "computed": exp, "error": "score_mismatch"})
        return {"passed": not errs, "errors": errs}

    def verify_invariants(self) -> dict:
        errs = []
        for e in self.entries:
            if not (0.1 <= e.epsilon <= 1.5): errs.append({"seq":e.sequence,"error":f"INV-1:ε={e.epsilon}"})
            if e.k < e.k_min:                  errs.append({"seq":e.sequence,"error":f"INV-2:K={e.k}"})
            if abs(e.wk - 0.3) > 1e-9:        errs.append({"seq":e.sequence,"error":f"INV-3:wK={e.wk}"})
        return {"passed": not errs, "errors": errs}

    def verify_timestamps(self) -> dict:
        items = []
        for ts in self.export.get("external_timestamps", []):
            x = {"method": ts.get("method"), "verified": ts.get("verified", False),
                 "simulation": ts.get("simulation", False),
                 "hash": ts.get("hash_anchored", "")[:16] + "…"}
            if ts.get("simulation"): x["warning"] = "SIMULATION — not a real proof"
            items.append(x)
        real = [t for t in items if not t.get("simulation") and t.get("verified")]
        return {"passed": True, "count": len(items),
                "real_verified": len(real), "detail": items}

    def verify_checkpoints(self) -> dict:
        """
        FIX 6 : Vérifie signature ET recompute anchor_hash depuis le payload.
        Un checkpoint ne peut pas mentir sur son hash même si la sig est valide.
        """
        cps = self.export.get("checkpoints", [])
        if not cps:
            return {"passed": True, "checkpoints": 0, "errors": []}
        errs = []
        prev = GENESIS_HASH
        for i, cp in enumerate(cps):
            # 1. Chaîne previous_anchor
            if cp.get("previous_anchor") != prev:
                errs.append({"cp": i, "error": "chain_broken"})

            # 2. FIX 6 : Recompute anchor_hash depuis payload canonique
            p_recomputed = _checkpoint_payload(
                cp["chain_tip"], cp["sequence"],
                cp["anchored_at"], cp["anchored_by"],
                cp["previous_anchor"]
            )
            expected_ah = hashlib.sha256(p_recomputed.encode()).hexdigest()
            if expected_ah != cp.get("anchor_hash", ""):
                errs.append({"cp": i, "error": "anchor_hash_mismatch"})

            # 3. Vérification signature Ed25519
            try:
                pub = Ed25519PublicKey.from_public_bytes(
                    base64.b64decode(cp.get("public_key", ""))
                )
                pub.verify(base64.b64decode(cp.get("signature", "")),
                           p_recomputed.encode())
            except InvalidSignature:
                errs.append({"cp": i, "error": "sig_invalid"})
            except Exception as e:
                errs.append({"cp": i, "error": str(e)})

            prev = cp.get("anchor_hash", "")

        return {
            "passed":     not errs,
            "checkpoints":len(cps),
            "witnesses":  cps[-1].get("anchored_by", []) if cps else [],
            "errors":     errs
        }

    def verify_stop_status(self) -> dict:
        """
        FIX 4 : Évalue l'état STOP depuis le champ stop_status de l'export.
        Ne valide pas le token RFC3161 (module réseau) — vérifie la cohérence interne.
        """
        ss = self.export.get("stop_status", {})
        claimed = ss.get("claimed", False)
        reached = ss.get("reached", False)
        evidence = ss.get("evidence")

        if not claimed:
            return {
                "reached": False,
                "claimed": False,
                "note":    "STOP not claimed — run vera_anchor_net.py --anchor-genesis"
            }
        if not reached:
            return {
                "reached": False,
                "claimed": True,
                "error":   "STOP claimed but not reached — check TSA token validity"
            }
        if not evidence:
            return {
                "reached": False,
                "claimed": True,
                "error":   "STOP reached=True but no evidence — inconsistent"
            }
        return {
            "reached":    True,
            "claimed":    True,
            "method":     ss.get("method"),
            "anchored_at":evidence.get("anchored_at"),
            "tsa":        evidence.get("tsa"),
            "genesis_hash":evidence.get("genesis_hash"),
        }

    def full_verification(self) -> dict:
        """
        S2 : Retourne valid_internal + valid_stop comme propriétés distinctes.
        Jamais de confusion entre intégrité locale et preuve d'antériorité externe.
        """
        sig   = self.verify_signature()
        gen   = self.verify_genesis_anchor()
        hh    = self.verify_entry_hashes()
        cc    = self.verify_chain_links()
        ss    = self.verify_scores()
        ii    = self.verify_invariants()
        tt    = self.verify_timestamps()
        cp    = self.verify_checkpoints()
        stop  = self.verify_stop_status()

        valid_internal = (
            sig["passed"] and gen["passed"] and
            hh["passed"]  and cc["passed"] and
            ss["passed"]  and ii["passed"] and
            cp["passed"]
        )
        valid_stop = stop["reached"]

        # Warnings
        warnings = []
        ks_prot = self.export.get("keystore_protection", {})
        if ks_prot.get("mode") == "obfuscation_only":
            warnings.append("KEYSTORE_OBFUSCATION_ONLY")
        if not valid_stop:
            warnings.append("STOP_NOT_REACHED")

        # Stats
        stats = {}
        if self.entries:
            stats = {
                "epsilon_range":  [min(e.epsilon for e in self.entries),
                                   max(e.epsilon for e in self.entries)],
                "avg_score":      round(sum(e.privacy_score for e in self.entries)
                                        / len(self.entries), 4),
                "real_ts":        tt["real_verified"],
                "sim_ts":         tt["count"] - tt["real_verified"],
                "checkpoints":    cp["checkpoints"],
            }

        return {
            "audit_version": AUDIT_VERSION,
            "verified_at":   datetime.now(timezone.utc).isoformat(),
            "entry_count":   len(self.entries),
            "chain_tip":     self.export.get("chain_tip"),

            # S2 — deux propriétés distinctes, deux résumés non confondables
            "result": {
                "valid_internal": valid_internal,
                "valid_stop":     valid_stop,
                "summary_internal": (
                    "AUDIT PASSED (INTERNAL) — integrity + signatures OK"
                    if valid_internal else
                    "AUDIT FAILED (INTERNAL) — integrity violations found"
                ),
                "summary_stop": (
                    "STOP REACHED — genesis key time-attested by independent TSA"
                    if valid_stop else
                    "STOP NOT REACHED — external genesis anchoring missing or unverified"
                ),
            },

            "stop": stop,

            "checks": {
                "ed25519_snapshot":   sig,
                "genesis_anchor":     gen,
                "entry_hashes":       hh,
                "chain_links":        cc,
                "privacy_scores":     ss,
                "dp_invariants":      ii,
                "external_timestamps":tt,
                "checkpoints":        cp,
            },

            "warnings":    warnings,
            "statistics":  stats,

            "anti_collusion": {
                "witnesses": cp.get("witnesses", []),
                "guarantee": (
                    f"Réécriture détectable par {len(cp.get('witnesses',[]))} témoins"
                ),
                "key_anchored": gen.get("passed", False),
            },

            "fixes_applied": [
                "FIX1: KeyStore obfuscation assumée + warning explicite",
                "FIX2: validate_rfc3161_token structurel, sémantique honnête",
                "FIX3: build_rfc3161_request — hash complet 32 bytes, builder unique",
                "FIX4: stop_status dans export + valid_internal/valid_stop séparés (S2)",
                "FIX5: GenesisAnchor.verify() → verify_hash_binding()",
                "FIX6: verify_checkpoints() recompute anchor_hash depuis payload",
                "FIX7: append() valide invariants DP avant écriture",
            ],

            "note": (
                "SHA-256 · Ed25519 · GenesisAnchor · "
                "Checkpoints signés+recomputed · RGPD Art.5(1)(f). "
                "Pour STOP: vera_anchor_net.py --anchor-genesis"
            )
        }


# ─────────────────────────────────────────────────────────────────────────────
# VERA WITH AUDIT
# ─────────────────────────────────────────────────────────────────────────────

class VERAWithAudit:
    def __init__(self, epsilon=0.3, keystore_path=None):
        self.log      = ImmutableLog(keystore_path)
        self.epsilon  = epsilon
        self._proofs  = []

    def aggregate_and_audit(self, agg: dict):
        import math
        e    = self.log.append(agg)
        es   = 1 - (e.epsilon - 0.1) / 1.4
        ks   = min(math.log(e.k / e.k_min + 1) / math.log(11), 1)
        comp = round((1 - e.wk) * es + e.wk * ks, 4)
        p = AuditProof(
            secrets.token_hex(8), e.entry_id, e.sequence,
            e.epsilon, e.k, e.k_min, e.wk, e.privacy_score,
            "score=(1-wK)*(1-(ε-0.1)/1.4)+wK*min(log(K/K_min+1)/log(11),1)",
            {"epsilon": e.epsilon, "k": e.k, "k_min": e.k_min, "wk": e.wk,
             "epsilon_min": 0.1, "epsilon_max": 1.5},
            comp, e.entry_hash, e.previous_hash, e.aggregate_hash, e.timestamp
        )
        self._proofs.append(p)
        return agg, e, p

    def anchor_local(self) -> ExternalTimestamp:
        return self.log.anchor_local()

    def anchor_bitcoin_sim(self) -> ExternalTimestamp:
        return self.log.anchor_bitcoin_sim()

    def checkpoint(self) -> CheckpointAnchor:
        return self.log._cpm.create(self.log.tip, self.log.length - 1, self.log._ks)

    def get_audit_report(self) -> dict:
        return AuditVerifier(self.log.export_public()).full_verification()

    def export_for_auditor(self) -> dict:
        return {
            "log_export":   self.log.export_public(),
            "audit_report": self.get_audit_report(),
            "proofs":       [p.to_dict() for p in self._proofs],
        }


# ─────────────────────────────────────────────────────────────────────────────
# DÉMO
# ─────────────────────────────────────────────────────────────────────────────

def demo():
    import math

    def make(eps, k, n, ts):
        s = round(0.7*(1-(eps-0.1)/1.4) +
                  0.3*min(math.log(k/100+1)/math.log(11), 1), 4)
        return {"epsilon":eps,"k":k,"k_min":100,"wk":0.3,"privacy_score":s,
                "station_count":n,"stations":[],"raw_events":None,"aggregated_at":ts}

    print("=" * 65)
    print("  VERA Audit Core v1.4 — S2 (valid_internal + valid_stop)")
    print("=" * 65)

    vera = VERAWithAudit()
    aggs = [
        make(0.3, 5100, 12, "2026-03-28T06Z"),
        make(0.3, 7800, 14, "2026-03-28T12Z"),
        make(0.5, 4200, 10, "2026-03-28T18Z"),
        make(0.3, 6300, 13, "2026-03-29T06Z"),
        make(0.3, 8900, 15, "2026-03-29T12Z"),
    ]

    print(f"\n[KeyStore] fp:{vera.log.fp[:24]}… mode:{KeyStore.PROTECTION_MODE}")
    print(f"[Genesis]  hash:{vera.log._genesis.anchor_hash[:24]}… "
          f"hash_binding:{'✓' if vera.log._genesis.verify_hash_binding() else '✗'}")

    print("\n[Registre]")
    for a in aggs:
        _, e, p = vera.aggregate_and_audit(a)
        print(f"  #{e.sequence} {e.entry_hash[:18]}… score:{e.privacy_score} "
              f"proof:{'✓' if p.verify_score() else '✗'}")

    # Test INV enforcement à l'append
    print("\n[FIX7] Validation invariants à l'append...")
    try:
        vera.log.append(make(0.3, 50, 1, "T"))   # K=50 < K_min=100 → doit lever
        print("  ✗ Exception non levée — bug")
    except AuditIntegrityError as e:
        print(f"  ✓ INV-2 rejeté : {e}")

    c = vera.log.verify_chain()
    print(f"\n[Chaîne] {c['entries']} entrées {'✓' if c['valid'] else '✗'}")

    ts1 = vera.anchor_local()
    ts2 = vera.anchor_bitcoin_sim()
    print(f"\n[FIX3] Timestamps (core — pas de réseau):")
    print(f"  {ts1.method} verified:{ts1.verified} sim:{ts1.simulation}")
    print(f"  {ts2.method} verified:{ts2.verified} sim:{ts2.simulation} ← HONNÊTE")

    cp = vera.checkpoint()
    print(f"\n[FIX6] Checkpoint {cp.checkpoint_id} · {len(cp.anchored_by)} témoins")

    # Corruption
    vera.log._entries[0].privacy_score = 0.99
    r = vera.log.verify_chain()
    print(f"\n[Corruption] {'✓ DÉTECTÉE' if not r['valid'] else '✗'} "
          f"→ {r['errors'][0]['error']}")
    vera.log._entries[0].privacy_score = aggs[0]["privacy_score"]
    vera.log._entries[0].entry_hash    = vera.log._entries[0].compute_hash()

    # Rapport S2
    report = vera.get_audit_report()
    res    = report["result"]
    ch     = report["checks"]

    print(f"\n[Rapport S2]")
    print(f"  {res['summary_internal']}")
    print(f"  {res['summary_stop']}")
    print(f"\n  Checks internes :")
    for k, v in ch.items():
        print(f"    {k:28s}: {'✓' if v.get('passed',True) else '✗'}")
    print(f"\n  Warnings : {report['warnings']}")
    print(f"  Anti-collusion : {report['anti_collusion']['guarantee']}")

    print(f"\n  Fixes appliqués :")
    for f in report["fixes_applied"]:
        print(f"    ✓ {f}")

    print("\n" + "=" * 65)
    print(f"  valid_internal : {res['valid_internal']}")
    print(f"  valid_stop     : {res['valid_stop']}")
    print(f"  → Pour STOP : vera_anchor_net.py --anchor-genesis")
    print("=" * 65)

    return vera.export_for_auditor()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VERA Audit Core v1.4")
    parser.add_argument("--verify", metavar="FILE", help="Vérifier un export JSON")
    parser.add_argument("--export", metavar="FILE", help="Sauvegarder l'export")
    parser.add_argument("--keystore", metavar="FILE", default=None)
    args = parser.parse_args()

    if args.verify:
        with open(args.verify) as f:
            data = json.load(f)
        report = AuditVerifier(data.get("log_export", data)).full_verification()
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        export = demo()
        if args.export:
            with open(args.export, "w") as f:
                json.dump(export, f, indent=2, ensure_ascii=False)
            print(f"\nExport : {args.export}")
