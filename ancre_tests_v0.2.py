"""
ancre_tests_v0.2.py
ANCRE — Attested Noise Client Runtime Engine
Suite de tests adversariaux v0.2

Valide les 10 patches contre les vecteurs d'attaque identifiés
par le red team multi-IA (DeepSeek, GPT-4o, Mistral, IA#2, Mythos).

T01 — PKI bypass (certificat auto-signé)
T02 — Anti-replay nonce
T03 — Float hash canonique (struct.pack)
T04 — NaN/Inf injection
T05 — Device tracking Sybil
T06 — sim_mode bypass
T07 — Exception DoS (signature invalide)
T08 — Payload géant DoS
T09 — Coalition cap identité
T10 — Timestamp expiré
T11 — Timestamp futur
T12 — Kill-switch K < 100
T13 — Pipeline nominal régression
T14 — Noise scale k_actual

Auteur : SAS VERA / ANCRE
Version : 0.2
"""

import base64
import hashlib
import hmac
import json
import math
import struct
import sys
import uuid
import logging
import numpy as np
from datetime import datetime, timezone, timedelta

import cryptography.x509 as x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from cryptography import x509 as cx509
import datetime as dt

from ancre_sim_attest import MockSimCard
from ancre_patch_v0_2 import (
    AncreVerifierV2, AncreServerV2, AncreAttestation,
    SignedPayload, canonical_signal_hash, validate_signal,
    MAX_CERT_BYTES, K_MIN, W_K, EPSILON_CLIENT, EPSILON_SERVER,
)

logging.disable(logging.CRITICAL)

# ─────────────────────────────────────────────
# Framework
# ─────────────────────────────────────────────

results = []

def test(name: str, condition: bool, detail: str = ""):
    status = "✅ PASS" if condition else "❌ FAIL"
    results.append((name, condition, detail))
    print(f"{status}  {name}")
    if detail:
        print(f"       → {detail}")

def section(title: str):
    print(f"\n{'─'*55}")
    print(f"  {title}")
    print(f"{'─'*55}")

# ─────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────

def make_sim():
    """Crée un MockSimCard initialisé avec un keypair unique."""
    sim = MockSimCard(slot=1)
    sim.generate_keypair()
    return sim

def make_cert(sim):
    cert_der = sim.get_certificate()
    cert = x509.load_der_x509_certificate(cert_der)
    return cert_der, cert.serial_number

def make_attestation(sim, cert_der, cert_serial, signal,
                     nonce=None, timestamp_utc=None,
                     sim_mode="MOCK", tamper_sig=False,
                     tamper_hash=False):
    """Helper — crée une AncreAttestation valide ou tampérée."""
    nonce = nonce or str(uuid.uuid4())
    ts = timestamp_utc or datetime.now(timezone.utc).isoformat()
    sig_hash = canonical_signal_hash(signal)
    if tamper_hash:
        sig_hash = bytes(32)
    payload = SignedPayload(
        signal_hash=sig_hash,
        nonce=nonce,
        slot=1,
        sim_mode=sim_mode,
        timestamp_utc=ts,
    )
    payload_sig = sim.sign(payload.to_bytes())
    if tamper_sig:
        payload_sig = bytes(64)
    return AncreAttestation(
        noisy_value=signal,
        payload=payload,
        payload_signature=payload_sig,
        certificate_chain=cert_der,
        cert_serial=cert_serial,
    )

def make_attacker_cert(org_name: str) -> tuple[bytes, int, object]:
    """
    Génère un certificat auto-signé avec l'org donnée.
    Simule l'attaquant du T01 (PKI bypass).
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509 import random_serial_number, NameAttribute, Name
    attacker_key = Ed25519PrivateKey.generate()
    subject = issuer = Name([
        NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
    ])
    cert = (
        cx509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(attacker_key.public_key())
        .serial_number(random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=365))
        .sign(attacker_key, None)
    )
    cert_der = cert.public_bytes(Encoding.DER)
    return cert_der, cert.serial_number, attacker_key


# ─────────────────────────────────────────────
# T01 — PKI bypass par certificat auto-signé
# ─────────────────────────────────────────────

section("T01 — PKI bypass (certificat auto-signé avec O=Orange)")

def test_t01():
    # Attaquant génère cert auto-signé avec O=Orange
    fake_cert_der, fake_serial, attacker_key = make_attacker_cert("Orange")

    verifier = AncreVerifierV2(
        trusted_operator_orgs=["Orange", "SFR"],
        reject_mock=False,
    )

    signal = 0.999
    nonce = str(uuid.uuid4())
    sig_hash = canonical_signal_hash(signal)
    payload = SignedPayload(
        signal_hash=sig_hash,
        nonce=nonce,
        slot=1,
        sim_mode="IOTSAFE",
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
    )
    # Signe avec la clé de l'attaquant (pas une SIM)
    attacker_sig = attacker_key.sign(payload.to_bytes())

    att = AncreAttestation(
        noisy_value=signal,
        payload=payload,
        payload_signature=attacker_sig,
        certificate_chain=fake_cert_der,
        cert_serial=fake_serial,
    )

    valid, reason = verifier.verify(att)

    # Sans CA configurée : le verifier accepte encore (dev mode)
    # Avec CA configurée : doit rejeter
    verifier_with_ca = AncreVerifierV2(
        trusted_operator_orgs=["Orange"],
        trusted_ca_certs=[b"fake_ca"],  # CA non reconnue
        reject_mock=False,
    )
    valid_ca, reason_ca = verifier_with_ca.verify(att)

    test(
        "T01a — Cert auto-signé rejeté si CA configurée",
        not valid_ca,
        f"reason='{reason_ca}'"
    )
    test(
        "T01b — Mode dev sans CA : accepte (comportement documenté)",
        valid,
        "PKI non configurée en dev — attendu"
    )

test_t01()

# ─────────────────────────────────────────────
# T02 — Anti-replay nonce
# ─────────────────────────────────────────────

section("T02 — Anti-replay nonce")

def test_t02():
    sim = make_sim()
    cert_der, cert_serial = make_cert(sim)
    verifier = AncreVerifierV2(reject_mock=False)

    nonce = str(uuid.uuid4())
    att1 = make_attestation(sim, cert_der, cert_serial, 0.5, nonce=nonce)
    att2 = make_attestation(sim, cert_der, cert_serial, 0.5, nonce=nonce)

    v1, _ = verifier.verify(att1)
    v2, r2 = verifier.verify(att2)

    test("T02a — Première attestation acceptée", v1)
    test("T02b — Replay même nonce rejeté", not v2, r2)

    # Nonce différent = accepté
    att3 = make_attestation(sim, cert_der, cert_serial, 0.5)
    v3, _ = verifier.verify(att3)
    test("T02c — Nouveau nonce accepté", v3)

test_t02()

# ─────────────────────────────────────────────
# T03 — Hash canonique struct.pack
# ─────────────────────────────────────────────

section("T03 — Hash canonique IEEE754")

def test_t03():
    # Même float64 → même hash
    h1 = canonical_signal_hash(0.1)
    h2 = canonical_signal_hash(0.1)
    test("T03a — Déterminisme sur même valeur", h1 == h2)

    # 0.1 et 0.10000000000000001 sont le même float64
    h3 = canonical_signal_hash(0.10000000000000001)
    test("T03b — IEEE754 stable (0.1 == 0.1+eps float64)", h1 == h3)

    # Deux floats distincts → hashes distincts
    h4 = canonical_signal_hash(0.2)
    test("T03c — Floats distincts → hashes distincts", h1 != h4)

    # Vérification struct.pack format
    raw = struct.pack('>d', 0.5)
    test("T03d — struct.pack produit 8 bytes", len(raw) == 8)

test_t03()

# ─────────────────────────────────────────────
# T04 — NaN/Inf injection
# ─────────────────────────────────────────────

section("T04 — NaN/Inf/bounds guard")

def test_t04():
    sim = make_sim()
    cert_der, cert_serial = make_cert(sim)
    verifier = AncreVerifierV2(reject_mock=False)

    for bad_val, label in [
        (float('nan'), 'NaN'),
        (float('inf'), 'Inf'),
        (float('-inf'), '-Inf'),
        (1.001, '>1.0'),
        (-0.001, '<0.0'),
    ]:
        try:
            # validate_signal doit lever avant de créer l'attestation
            validate_signal(bad_val)
            test(f"T04 — {label} rejeté par validate_signal", False)
        except ValueError as e:
            test(f"T04 — {label} rejeté par validate_signal", True, str(e))

    # Limites valides
    for ok_val in [0.0, 1.0, 0.5]:
        try:
            validate_signal(ok_val)
            test(f"T04 — {ok_val} accepté", True)
        except ValueError:
            test(f"T04 — {ok_val} accepté", False)

test_t04()

# ─────────────────────────────────────────────
# T05 — Device tracking Sybil
# ─────────────────────────────────────────────

section("T05 — Device tracking Sybil (cert serial)")

def test_t05():
    sim = make_sim()
    cert_der, cert_serial = make_cert(sim)
    verifier = AncreVerifierV2(reject_mock=False, max_signals_per_device=2)

    atts = [make_attestation(sim, cert_der, cert_serial, 0.5) for _ in range(3)]
    results_v = [verifier.verify(a) for a in atts]

    test("T05a — Signal 1 accepté", results_v[0][0])
    test("T05b — Signal 2 accepté", results_v[1][0])
    test("T05c — Signal 3 rejeté (quota)", not results_v[2][0], results_v[2][1])

    # Device différent = accepté
    sim2 = make_sim()
    cert_der2, cert_serial2 = make_cert(sim2)
    att_other = make_attestation(sim2, cert_der2, cert_serial2, 0.5)
    v_other, _ = verifier.verify(att_other)
    test("T05d — Device différent accepté malgré quota du premier", v_other)

test_t05()

# ─────────────────────────────────────────────
# T06 — sim_mode bypass
# ─────────────────────────────────────────────

section("T06 — sim_mode dans payload signé (anti-bypass)")

def test_t06():
    sim = make_sim()
    cert_der, cert_serial = make_cert(sim)
    verifier = AncreVerifierV2(reject_mock=True)

    # Attaquant met sim_mode="IOTSAFE" mais la signature couvre le mode
    # → si on tamper le sim_mode après signature, la vérification échoue
    nonce = str(uuid.uuid4())
    sig_hash = canonical_signal_hash(0.5)
    payload_mock = SignedPayload(
        signal_hash=sig_hash, nonce=nonce, slot=1,
        sim_mode="MOCK",  # signé comme MOCK
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
    )
    sig = sim.sign(payload_mock.to_bytes())

    # Tamper sim_mode après signature
    payload_tampered = SignedPayload(
        signal_hash=sig_hash, nonce=nonce, slot=1,
        sim_mode="IOTSAFE",  # changé après signature
        timestamp_utc=payload_mock.timestamp_utc,
    )

    att_tampered = AncreAttestation(
        noisy_value=0.5,
        payload=payload_tampered,
        payload_signature=sig,  # signature originale (sur MOCK)
        certificate_chain=cert_der,
        cert_serial=cert_serial,
    )

    valid, reason = verifier.verify(att_tampered)
    test(
        "T06a — sim_mode tamperé détecté (signature invalide)",
        not valid,
        reason
    )

    # Mode MOCK rejeté en production
    att_mock = make_attestation(sim, cert_der, cert_serial, 0.5, sim_mode="MOCK")
    valid_mock, reason_mock = verifier.verify(att_mock)
    test("T06b — MOCK rejeté en mode production", not valid_mock, reason_mock)

test_t06()

# ─────────────────────────────────────────────
# T07 — Exception DoS (signature invalide)
# ─────────────────────────────────────────────

section("T07 — Exception handling anti-DoS")

def test_t07():
    sim = make_sim()
    cert_der, cert_serial = make_cert(sim)
    verifier = AncreVerifierV2(reject_mock=False)

    # Signature nulle
    att = make_attestation(sim, cert_der, cert_serial, 0.5, tamper_sig=True)
    try:
        valid, reason = verifier.verify(att)
        test("T07a — Signature nulle rejetée sans crash", not valid, reason)
    except Exception as e:
        test("T07a — Signature nulle rejetée sans crash", False, f"CRASH: {e}")

    # Certificat DER malformé
    att_bad = make_attestation(sim, cert_der, cert_serial, 0.5)
    att_bad.certificate_chain = b"NOT_A_VALID_DER_CERTIFICATE"
    try:
        valid, reason = verifier.verify(att_bad)
        test("T07b — Cert DER invalide rejeté sans crash", not valid, reason)
    except Exception as e:
        test("T07b — Cert DER invalide rejeté sans crash", False, f"CRASH: {e}")

    # Signature 1 byte (trop courte)
    att_short = make_attestation(sim, cert_der, cert_serial, 0.5)
    att_short.payload_signature = b"\x00"
    try:
        valid, reason = verifier.verify(att_short)
        test("T07c — Signature trop courte rejetée sans crash", not valid, reason)
    except Exception as e:
        test("T07c — Signature trop courte rejetée sans crash", False, f"CRASH: {e}")

test_t07()

# ─────────────────────────────────────────────
# T08 — Payload géant DoS
# ─────────────────────────────────────────────

section("T08 — Payload size limits anti-DoS")

def test_t08():
    sim = make_sim()
    cert_der, cert_serial = make_cert(sim)
    verifier = AncreVerifierV2(reject_mock=False)

    # Certificat exactement à la limite
    att_limit = make_attestation(sim, cert_der, cert_serial, 0.5)
    att_limit.certificate_chain = bytes(MAX_CERT_BYTES)
    valid_limit, reason_limit = verifier.verify(att_limit)
    test("T08a — Cert à la limite MAX_CERT_BYTES rejeté (DER invalide)",
         not valid_limit, reason_limit)

    # Certificat dépassant la limite
    att_big = make_attestation(sim, cert_der, cert_serial, 0.5)
    att_big.certificate_chain = bytes(MAX_CERT_BYTES + 1)
    valid_big, reason_big = verifier.verify(att_big)
    test("T08b — Cert > MAX_CERT_BYTES rejeté immédiatement", not valid_big, reason_big)

test_t08()

# ─────────────────────────────────────────────
# T09 — Coalition cap par identité device
# ─────────────────────────────────────────────

section("T09 — Coalition cap sur identité (distinct devices)")

def test_t09():
    # 120 devices distincts — chaque sim génère un keypair unique
    verifier = AncreVerifierV2(reject_mock=False, max_signals_per_device=5)
    server = AncreServerV2(verifier=verifier)

    accepted = 0
    for i in range(120):
        sim_i = make_sim()
        cert_der_i, cert_serial_i = make_cert(sim_i)
        att_i = make_attestation(
            sim_i, cert_der_i, cert_serial_i,
            float(np.random.uniform(0.1, 0.9))
        )
        ok, _ = server.receive(att_i)
        if ok:
            accepted += 1

    result = server.aggregate()

    test("T09a — K≥100 avec 120 devices distincts",
         not result["kill_switch"],
         f"K={result.get('k_actual')}")
    test("T09b — pipeline=ANCRE_v0.2",
         result.get("pipeline") == "ANCRE_v0.2")
    test("T09c — agrégat dans [0,1]",
         0.0 <= result.get("aggregate_value", -1) <= 1.0,
         f"agg={result.get('aggregate_value', 'N/A'):.4f}")

    # Coalition : 1 seul device, max_per_device=5 → K=5 < 100
    verifier2 = AncreVerifierV2(reject_mock=False, max_signals_per_device=5)
    server2 = AncreServerV2(verifier=verifier2)
    sim_attacker = make_sim()
    cert_der_a, cert_serial_a = make_cert(sim_attacker)
    for _ in range(120):
        att = make_attestation(sim_attacker, cert_der_a, cert_serial_a, 0.999)
        server2.receive(att)
    result2 = server2.aggregate()
    test("T09d — Sybil 1 device × 120 → kill-switch",
         result2["kill_switch"],
         f"K post-filtre={result2.get('k_actual', 'N/A')}")

test_t09()

# ─────────────────────────────────────────────
# T10 — Timestamp expiré
# ─────────────────────────────────────────────

section("T10 — Timestamp expiré")

def test_t10():
    sim = make_sim()
    cert_der, cert_serial = make_cert(sim)
    verifier = AncreVerifierV2(reject_mock=False, nonce_window_sec=300)

    # Timestamp 10 minutes dans le passé
    old_ts = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    att = make_attestation(sim, cert_der, cert_serial, 0.5, timestamp_utc=old_ts)
    valid, reason = verifier.verify(att)
    test("T10a — Attestation expirée rejetée", not valid, reason)

    # Timestamp récent = accepté
    att_fresh = make_attestation(sim, cert_der, cert_serial, 0.5)
    valid_fresh, _ = verifier.verify(att_fresh)
    test("T10b — Attestation récente acceptée", valid_fresh)

test_t10()

# ─────────────────────────────────────────────
# T11 — Timestamp futur
# ─────────────────────────────────────────────

section("T11 — Timestamp futur suspect")

def test_t11():
    sim = make_sim()
    cert_der, cert_serial = make_cert(sim)
    verifier = AncreVerifierV2(reject_mock=False)

    # Timestamp 5 minutes dans le futur
    future_ts = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    att = make_attestation(sim, cert_der, cert_serial, 0.5, timestamp_utc=future_ts)
    valid, reason = verifier.verify(att)
    test("T11a — Timestamp futur > 60s rejeté", not valid, reason)

test_t11()

# ─────────────────────────────────────────────
# T12 — Kill-switch K < 100
# ─────────────────────────────────────────────

section("T12 — Kill-switch K < 100")

def test_t12():
    verifier = AncreVerifierV2(reject_mock=False, max_signals_per_device=100)
    server = AncreServerV2(verifier=verifier)

    for _ in range(50):
        sim_i = make_sim()
        cert_der_i, cert_serial_i = make_cert(sim_i)
        att = make_attestation(sim_i, cert_der_i, cert_serial_i,
                               float(np.random.uniform(0.1, 0.9)))
        server.receive(att)

    result = server.aggregate()
    test("T12a — Kill-switch déclenché si K=50 < 100",
         result["kill_switch"], f"K={result.get('k_actual')}")
    test("T12b — Agrégat=0.0 sur kill-switch",
         result.get("aggregate_value") == 0.0)

test_t12()

# ─────────────────────────────────────────────
# T13 — Pipeline nominal régression
# ─────────────────────────────────────────────

section("T13 — Pipeline nominal v0.2 (régression)")

def test_t13():
    verifier = AncreVerifierV2(reject_mock=False, max_signals_per_device=100)
    server = AncreServerV2(verifier=verifier)

    for _ in range(120):
        sim_i = make_sim()
        cert_der_i, cert_serial_i = make_cert(sim_i)
        att = make_attestation(sim_i, cert_der_i, cert_serial_i,
                               float(np.clip(
                                   np.random.beta(2, 5) +
                                   np.random.laplace(0, 1.0),
                                   0.0, 1.0
                               )))
        server.receive(att)

    result = server.aggregate()
    test("T13a — kill_switch=False", not result["kill_switch"])
    test("T13b — K≥100", result.get("k_actual", 0) >= K_MIN,
         f"K={result.get('k_actual')}")
    test("T13c — ε_total=1.5",
         result.get("epsilon_total") == 1.5,
         f"ε={result.get('epsilon_total')}")
    test("T13d — agrégat ∈ [0,1]",
         0.0 <= result.get("aggregate_value", -1) <= 1.0,
         f"agg={result.get('aggregate_value', 'N/A'):.4f}")
    test("T13e — pipeline=ANCRE_v0.2",
         result.get("pipeline") == "ANCRE_v0.2")

test_t13()

# ─────────────────────────────────────────────
# T14 — Noise scale k_actual
# ─────────────────────────────────────────────

section("T14 — Noise scale calibré sur k_actual")

def test_t14():
    verifier = AncreVerifierV2(reject_mock=False, max_signals_per_device=100)
    server = AncreServerV2(verifier=verifier)

    for _ in range(150):
        sim_i = make_sim()
        cert_der_i, cert_serial_i = make_cert(sim_i)
        att = make_attestation(sim_i, cert_der_i, cert_serial_i, 0.5)
        server.receive(att)

    result = server.aggregate()
    if not result["kill_switch"]:
        k = result.get("k_actual", K_MIN)
        expected = (1.0 / k) / EPSILON_SERVER
        actual = result.get("noise_scale_actual", 0)
        test("T14a — noise_scale = 1/k_actual / ε_server",
             abs(actual - expected) < 1e-10,
             f"scale={actual:.6f} attendu={expected:.6f} K={k}")
        test("T14b — noise_scale < 1/K_MIN / ε_server (plus précis avec k>K_MIN)",
             actual < (1.0 / K_MIN) / EPSILON_SERVER,
             f"scale={actual:.6f} < {(1.0/K_MIN)/EPSILON_SERVER:.6f}")
    else:
        test("T14a — pipeline démarré", False, "kill_switch inattendu")

test_t14()

# ─────────────────────────────────────────────
# Résumé
# ─────────────────────────────────────────────

print(f"\n{'='*55}")
print("ANCRE v0.2 — RÉSUMÉ RED TEAM")
print(f"{'='*55}")

passed = sum(1 for _, ok, _ in results if ok)
failed = sum(1 for _, ok, _ in results if not ok)
total = len(results)

print(f"\nTotal  : {total}")
print(f"Pass   : {passed} ✅")
print(f"Fail   : {failed} ❌")
print(f"Score  : {passed}/{total} ({100*passed//total}%)")

if failed:
    print(f"\nFails :")
    for name, ok, detail in results:
        if not ok:
            print(f"  ❌ {name}")
            if detail:
                print(f"     → {detail}")

print(f"\n{'='*55}")
sys.exit(0 if failed == 0 else 1)
