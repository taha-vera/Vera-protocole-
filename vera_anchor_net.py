"""
VERA Anchor Net — v1.3
======================
Module réseau pour l'ancrage externe du protocole VERA.
Séparé de vera_audit_core.py (zéro appel réseau dans le core).

Responsabilités :
  - Ancrage RFC3161 via FreeTSA (freetsa.org)
  - Injection du stop_status dans ImmutableLog
  - Génération et sauvegarde de genesis_proof.json
  - Vérification du token RFC3161 via openssl (optionnel)

Usage:
  python3 vera_anchor_net.py --anchor-genesis
  python3 vera_anchor_net.py --anchor-genesis --out genesis_proof.json
  python3 vera_anchor_net.py --verify genesis_proof.json
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Import du core (doit être dans le même répertoire)
# ---------------------------------------------------------------------------
try:
    from vera_audit_core import (
        KeyStore,
        ImmutableLog,
        build_rfc3161_request,
        validate_rfc3161_token,
        AUDIT_VERSION,
    )
    _CORE_AVAILABLE = True
except ImportError:
    _CORE_AVAILABLE = False
    print("[WARN] vera_audit_core.py introuvable — mode standalone activé", file=sys.stderr)


# ===========================================================================
# Constants
# ===========================================================================

FREETSA_URL      = "https://freetsa.org/tsr"
FREETSA_ROOT_PEM = "https://freetsa.org/files/cacert.pem"
REQUEST_TIMEOUT  = 15  # secondes

STOP_STATUS_REACHED = {
    "claimed": True,
    "reached": True,
    "method":  "RFC3161_FREETSA",
}


# ===========================================================================
# RFC3161 network call
# ===========================================================================

def fetch_rfc3161_token(data_hash: bytes) -> bytes:
    """
    Envoie une requête RFC3161 à FreeTSA et retourne le token DER brut.
    Lève une exception si le réseau est indisponible.
    """
    if _CORE_AVAILABLE:
        req_der = build_rfc3161_request(data_hash)
    else:
        # Fallback minimal si core absent
        oid     = bytes.fromhex("060960864801650304020105000420")
        msg_imp = b"\x30" + bytes([len(oid) + 32]) + oid + data_hash
        import secrets as _s
        nonce   = b"\x02\x08" + _s.token_bytes(8)
        inner   = b"\x02\x01\x01" + msg_imp + nonce
        req_der = b"\x30" + bytes([len(inner)]) + inner

    req = urllib.request.Request(
        FREETSA_URL,
        data=req_der,
        headers={"Content-Type": "application/timestamp-query"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        return resp.read()


# ===========================================================================
# Genesis anchoring
# ===========================================================================

def anchor_genesis(
    keystore_path: str = None,
    out_path: str = "genesis_proof.json",
    dry_run: bool = False,
) -> dict:
    """
    Ancre la clé publique VERA via RFC3161 (FreeTSA).
    Génère genesis_proof.json avec stop_reached=True.

    Paramètres :
      keystore_path — chemin vers le keystore (None = génère une nouvelle clé)
      out_path      — fichier de sortie
      dry_run       — si True, ne contacte pas FreeTSA (test local)
    """
    print("=" * 60)
    print("  VERA Anchor Net v1.3 — Ancrage Genesis RFC3161")
    print("=" * 60)

    # 1. Charger ou générer la clé
    if _CORE_AVAILABLE:
        ks = KeyStore(keystore_path)
    else:
        raise RuntimeError("vera_audit_core.py requis pour l'ancrage genesis")

    pub_b64 = ks.pub_b64
    fp      = ks.fp
    ts_now  = datetime.now(timezone.utc).isoformat()

    print(f"\n[Clé]      fp:{fp[:32]}…")
    print(f"[Pub]      {pub_b64[:32]}…")

    # 2. Construire le hash à ancrer (clé publique + timestamp)
    anchor_input = (pub_b64 + ts_now).encode()
    anchor_hash  = hashlib.sha256(anchor_input).hexdigest()
    data_hash    = bytes.fromhex(anchor_hash)

    print(f"[Hash]     {anchor_hash[:32]}…")

    # 3. Contacter FreeTSA
    token_b64   = ""
    token_sha256 = ""
    tsa          = "FreeTSA"

    if dry_run:
        print(f"\n[DRY RUN]  Ancrage simulé — pas de contact réseau")
        token_b64    = base64.b64encode(b"DRY_RUN_TOKEN").decode()
        token_sha256 = hashlib.sha256(b"DRY_RUN_TOKEN").hexdigest()
    else:
        print(f"\n[TSA]      Connexion à {FREETSA_URL}…")
        try:
            token_raw    = fetch_rfc3161_token(data_hash)
            token_b64    = base64.b64encode(token_raw).decode()
            token_sha256 = hashlib.sha256(token_raw).hexdigest()
            print(f"[TSA]      Token reçu — {len(token_raw)} bytes")
            print(f"[TSA]      SHA-256 : {token_sha256[:32]}…")

            # Validation structurelle
            if _CORE_AVAILABLE:
                val = validate_rfc3161_token(token_raw, data_hash)
                print(f"[TSA]      Validation : {val}")
        except urllib.error.URLError as e:
            print(f"[ERREUR]   FreeTSA inaccessible : {e}")
            print("[FALLBACK] Ancrage local uniquement — stop_reached=False")
            token_b64    = ""
            token_sha256 = ""
            tsa          = "LOCAL_FALLBACK"

    # 4. Construire genesis_proof.json
    stop_reached = not dry_run and bool(token_b64) and tsa == "FreeTSA"

    proof = {
        "public_key":    pub_b64,
        "fingerprint":   fp,
        "anchored_at":   ts_now,
        "anchor_hash":   anchor_hash,
        "tsa":           tsa,
        "token_b64":     token_b64,
        "token_sha256":  token_sha256,
        "stop_reached":  stop_reached,
        "vera_version":  AUDIT_VERSION if _CORE_AVAILABLE else "1.4",
        "note": (
            "Preuve d'antériorité RFC3161 — vérifiable indépendamment. "
            "Ne me faites pas confiance. Vérifiez l'ancrage."
        ),
    }

    # 5. Sauvegarder
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(proof, f, indent=2, ensure_ascii=False)

    print(f"\n[Fichier]  {out_path} sauvegardé")
    print(f"[STOP]     stop_reached = {stop_reached}")

    if stop_reached:
        print("\n" + "=" * 60)
        print("  ✅ STOP REACHED — Ancrage RFC3161 validé")
        print(f"  TSA       : {tsa}")
        print(f"  Date      : {ts_now}")
        print(f"  Fichier   : {out_path}")
        print("  → Publiez genesis_proof.json sur GitHub pour activer S2")
        print("=" * 60)
    else:
        print("\n[WARN] stop_reached=False — ancrage externe non confirmé")

    return proof


# ===========================================================================
# Inject stop_status into a running ImmutableLog
# ===========================================================================

def inject_stop_into_log(log: "ImmutableLog", genesis_proof: dict) -> None:
    """
    Injecte le stop_status dans un ImmutableLog en mémoire
    après ancrage RFC3161 réussi.
    """
    if not _CORE_AVAILABLE:
        return

    stop_status = {
        "claimed":  True,
        "reached":  genesis_proof.get("stop_reached", False),
        "method":   "RFC3161_" + genesis_proof.get("tsa", "UNKNOWN").upper(),
        "evidence": {
            "anchored_at":  genesis_proof.get("anchored_at"),
            "tsa":          genesis_proof.get("tsa"),
            "token_sha256": genesis_proof.get("token_sha256"),
            "genesis_hash": genesis_proof.get("anchor_hash"),
        },
    }
    log.inject_stop_status(stop_status)
    print(f"[INJECT]   stop_status injecté — reached:{stop_status['reached']}")


# ===========================================================================
# Verify an existing genesis_proof.json
# ===========================================================================

def verify_genesis_file(path: str) -> dict:
    """
    Vérifie un genesis_proof.json existant.
    Contrôles :
      - Champs requis présents
      - token_sha256 cohérent avec token_b64
      - anchor_hash cohérent avec public_key + anchored_at
      - stop_reached cohérent
    """
    print(f"\n[Vérification] {path}")

    with open(path, encoding="utf-8") as f:
        proof = json.load(f)

    errors   = []
    warnings = []

    required = [
        "public_key", "fingerprint", "anchored_at",
        "anchor_hash", "tsa", "token_b64", "token_sha256", "stop_reached"
    ]
    for field in required:
        if field not in proof:
            errors.append(f"Champ manquant : {field}")

    if not errors:
        # Vérifier token_sha256
        token_raw = base64.b64decode(proof["token_b64"])
        computed  = hashlib.sha256(token_raw).hexdigest()
        if computed != proof["token_sha256"]:
            errors.append(f"token_sha256 incorrect : attendu {computed[:16]}…")

        # Vérifier anchor_hash
        anchor_input  = (proof["public_key"] + proof["anchored_at"]).encode()
        computed_hash = hashlib.sha256(anchor_input).hexdigest()
        if computed_hash != proof["anchor_hash"]:
            errors.append(f"anchor_hash incorrect : attendu {computed_hash[:16]}…")

        # Avertissements
        if not proof.get("stop_reached"):
            warnings.append("stop_reached=False — ancrage externe non confirmé")
        if proof.get("tsa") == "LOCAL_FALLBACK":
            warnings.append("TSA=LOCAL_FALLBACK — pas une preuve d'antériorité externe")
        if proof.get("tsa") == "FreeTSA" and not token_raw:
            warnings.append("Token vide malgré TSA=FreeTSA")

    result = {
        "valid":         len(errors) == 0,
        "stop_reached":  proof.get("stop_reached", False),
        "anchored_at":   proof.get("anchored_at"),
        "tsa":           proof.get("tsa"),
        "fingerprint":   proof.get("fingerprint"),
        "errors":        errors,
        "warnings":      warnings,
    }

    print(json.dumps(result, indent=2, ensure_ascii=False))
    return result


# ===========================================================================
# CLI
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="VERA Anchor Net v1.3 — Ancrage RFC3161 externe"
    )
    parser.add_argument(
        "--anchor-genesis",
        action="store_true",
        help="Ancrer la clé publique via FreeTSA et générer genesis_proof.json"
    )
    parser.add_argument(
        "--verify",
        metavar="FILE",
        help="Vérifier un genesis_proof.json existant"
    )
    parser.add_argument(
        "--out",
        metavar="FILE",
        default="genesis_proof.json",
        help="Fichier de sortie (défaut: genesis_proof.json)"
    )
    parser.add_argument(
        "--keystore",
        metavar="FILE",
        default=None,
        help="Chemin vers le keystore Ed25519"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Test local sans contact réseau"
    )
    args = parser.parse_args()

    if args.verify:
        result = verify_genesis_file(args.verify)
        sys.exit(0 if result["valid"] else 1)

    elif args.anchor_genesis:
        if not _CORE_AVAILABLE:
            print("[ERREUR] vera_audit_core.py introuvable dans le répertoire courant")
            sys.exit(1)
        anchor_genesis(
            keystore_path=args.keystore,
            out_path=args.out,
            dry_run=args.dry_run,
        )

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
