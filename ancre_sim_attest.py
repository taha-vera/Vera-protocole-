"""
ancre_sim_attest.py
ANCRE — Attested Noise Client Runtime Engine
SIM attestation layer via GSMA IoT SAFE

Mode DEV  : mock SIM (Termux, pas de SIM physique requise)
Mode PROD : pyscard + SIM IoT SAFE réelle

Auteur : SAS VERA
Version : 0.1
"""

import os
import hashlib
import json
import base64
import logging
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import (
    CertificateBuilder,
    NameAttribute,
    Name,
    random_serial_number,
)
from cryptography.x509.oid import NameOID
import cryptography.x509 as x509

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("ANCRE.SIM")

# ─────────────────────────────────────────────
# GSMA IoT SAFE APDU Commands (ETSI TS 102 226)
# ─────────────────────────────────────────────
IOTSAFE_CLA        = 0x80
IOTSAFE_GEN_KEY    = 0x01  # Generate Key Pair
IOTSAFE_GET_CERT   = 0x02  # Get Certificate
IOTSAFE_SIGN       = 0x03  # Compute Signature
IOTSAFE_ALG_ED25519 = 0x09 # Algorithm identifier Ed25519

# Slot SIM utilisé par ANCRE (configurable)
ANCRE_KEY_SLOT     = 0x01


# ─────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────

@dataclass
class SimAttestation:
    """Résultat d'une opération d'attestation SIM."""
    signal_hash: bytes          # SHA-256 du signal bruité
    signature: bytes            # Signature Ed25519 produite par la SIM
    certificate_chain: bytes    # Certificat DER chaîné à la PKI opérateur
    slot: int                   # Slot SIM utilisé
    timestamp_utc: str          # Horodatage de l'opération
    sim_mode: str               # "MOCK" ou "IOTSAFE"

    def to_dict(self) -> dict:
        return {
            "signal_hash": base64.b64encode(self.signal_hash).decode(),
            "signature": base64.b64encode(self.signature).decode(),
            "certificate_chain": base64.b64encode(self.certificate_chain).decode(),
            "slot": self.slot,
            "timestamp_utc": self.timestamp_utc,
            "sim_mode": self.sim_mode,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# ─────────────────────────────────────────────
# Mock SIM (développement Termux)
# ─────────────────────────────────────────────

class MockSimCard:
    """
    Simule une SIM IoT SAFE pour développement local.
    Génère un vrai keypair Ed25519 en mémoire.
    Produit un certificat auto-signé simulant la PKI opérateur.
    NE PAS utiliser en production.
    """

    def __init__(self, slot: int = ANCRE_KEY_SLOT):
        self.slot = slot
        self._private_key: Optional[Ed25519PrivateKey] = None
        self._certificate: Optional[bytes] = None
        self._initialized = False
        log.warning("⚠️  MockSimCard actif — mode développement uniquement")

    def generate_keypair(self) -> bool:
        """Simule IOTSAFE_GEN_KEY — génère Ed25519 in-process."""
        try:
            self._private_key = Ed25519PrivateKey.generate()
            self._certificate = self._build_mock_cert()
            self._initialized = True
            log.info(f"[MOCK] Keypair Ed25519 généré — slot {self.slot}")
            return True
        except Exception as e:
            log.error(f"[MOCK] Erreur génération keypair : {e}")
            return False

    def sign(self, data_hash: bytes) -> bytes:
        """Simule IOTSAFE_SIGN — signe le hash avec la clé in-process."""
        if not self._initialized:
            raise RuntimeError("SIM non initialisée — appeler generate_keypair() d'abord")
        signature = self._private_key.sign(data_hash)
        log.info(f"[MOCK] Signature produite — {len(signature)} bytes")
        return signature

    def get_certificate(self) -> bytes:
        """Simule IOTSAFE_GET_CERT — retourne le certificat DER mock."""
        if not self._initialized:
            raise RuntimeError("SIM non initialisée")
        return self._certificate

    def _build_mock_cert(self) -> bytes:
        """Construit un certificat X.509 auto-signé simulant la PKI opérateur."""
        pub_key = self._private_key.public_key()
        subject = issuer = Name([
            NameAttribute(NameOID.COUNTRY_NAME, "FR"),
            NameAttribute(NameOID.ORGANIZATION_NAME, "ANCRE-MOCK-OPERATOR"),
            NameAttribute(NameOID.COMMON_NAME, f"ANCRE SIM Slot {self.slot}"),
        ])
        import datetime as dt
        cert = (
            CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(pub_key)
            .serial_number(random_serial_number())
            .not_valid_before(dt.datetime.now(dt.timezone.utc))
            .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=365))
            .sign(self._private_key, None)  # Ed25519 n'utilise pas de hash séparé
        )
        return cert.public_bytes(Encoding.DER)

    def is_mock(self) -> bool:
        return True


# ─────────────────────────────────────────────
# Production SIM (stub — requiert pyscard + SIM IoT SAFE réelle)
# ─────────────────────────────────────────────

class ProductionSimCard:
    """
    Interface SIM IoT SAFE réelle via PC/SC (pyscard).
    Requiert :
      - pip install pyscard --break-system-packages
      - SIM avec applet GSMA IoT SAFE installée
      - Accord opérateur pour accès à l'applet

    TODO : implémenter lors du partenariat MVNO.
    """

    def __init__(self, slot: int = ANCRE_KEY_SLOT):
        self.slot = slot
        self._reader = None
        self._connection = None
        try:
            from smartcard.System import readers
            from smartcard.util import toHexString
            self._readers_available = readers()
            log.info(f"[PROD] {len(self._readers_available)} lecteur(s) PC/SC détecté(s)")
        except ImportError:
            raise RuntimeError(
                "pyscard non installé. "
                "Installer avec : pip install pyscard --break-system-packages"
            )
        except Exception as e:
            raise RuntimeError(f"Erreur accès PC/SC : {e}")

    def generate_keypair(self) -> bool:
        """Envoie APDU IOTSAFE_GEN_KEY à la SIM."""
        apdu = [IOTSAFE_CLA, IOTSAFE_GEN_KEY, self.slot, IOTSAFE_ALG_ED25519]
        response, sw1, sw2 = self._send_apdu(apdu)
        if sw1 == 0x90 and sw2 == 0x00:
            log.info(f"[PROD] Keypair généré dans SIM — slot {self.slot}")
            return True
        log.error(f"[PROD] Erreur APDU GEN_KEY : SW={sw1:02X}{sw2:02X}")
        return False

    def sign(self, data_hash: bytes) -> bytes:
        """Envoie APDU IOTSAFE_SIGN à la SIM."""
        apdu = (
            [IOTSAFE_CLA, IOTSAFE_SIGN, self.slot, IOTSAFE_ALG_ED25519,
             len(data_hash)]
            + list(data_hash)
            + [0x00]
        )
        response, sw1, sw2 = self._send_apdu(apdu)
        if sw1 == 0x90 and sw2 == 0x00:
            return bytes(response)
        raise RuntimeError(f"Erreur APDU SIGN : SW={sw1:02X}{sw2:02X}")

    def get_certificate(self) -> bytes:
        """Envoie APDU IOTSAFE_GET_CERT à la SIM."""
        apdu = [IOTSAFE_CLA, IOTSAFE_GET_CERT, self.slot, 0x00, 0x00]
        response, sw1, sw2 = self._send_apdu(apdu)
        if sw1 == 0x90 and sw2 == 0x00:
            return bytes(response)
        raise RuntimeError(f"Erreur APDU GET_CERT : SW={sw1:02X}{sw2:02X}")

    def _send_apdu(self, apdu: list) -> tuple:
        if not self._connection:
            self._connect()
        return self._connection.transmit(apdu)

    def _connect(self):
        if not self._readers_available:
            raise RuntimeError("Aucun lecteur PC/SC disponible")
        self._reader = self._readers_available[0]
        self._connection = self._reader.createConnection()
        self._connection.connect()
        log.info(f"[PROD] Connecté à : {self._reader}")

    def is_mock(self) -> bool:
        return False


# ─────────────────────────────────────────────
# Client d'attestation ANCRE
# ─────────────────────────────────────────────

class AncreSimAttestClient:
    """
    Interface principale d'attestation SIM pour ANCRE.
    Sélectionne automatiquement Mock ou Production selon l'environnement.
    """

    def __init__(self, mock: bool = True, slot: int = ANCRE_KEY_SLOT):
        self.slot = slot
        self.mock = mock

        if mock:
            self._sim = MockSimCard(slot=slot)
        else:
            self._sim = ProductionSimCard(slot=slot)

        # Initialisation du keypair SIM
        if not self._sim.generate_keypair():
            raise RuntimeError("Impossible d'initialiser le keypair SIM")

        log.info(
            f"AncreSimAttestClient initialisé — "
            f"mode={'MOCK' if mock else 'IOTSAFE'} — slot {slot}"
        )

    def attest_signal(self, noisy_signal: float) -> SimAttestation:
        """
        Produit une attestation SIM pour un signal bruité.

        1. Hash SHA-256 du signal
        2. Signature SIM du hash
        3. Récupération du certificat SIM
        4. Retourne SimAttestation complète
        """
        # Hash du signal
        signal_bytes = str(noisy_signal).encode("utf-8")
        signal_hash = hashlib.sha256(signal_bytes).digest()

        # Signature SIM
        signature = self._sim.sign(signal_hash)

        # Certificat SIM
        certificate = self._sim.get_certificate()

        attestation = SimAttestation(
            signal_hash=signal_hash,
            signature=signature,
            certificate_chain=certificate,
            slot=self.slot,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            sim_mode="MOCK" if self.mock else "IOTSAFE",
        )

        log.info(
            f"Attestation produite — "
            f"hash={signal_hash.hex()[:16]}... — "
            f"sig={len(signature)}B — "
            f"mode={attestation.sim_mode}"
        )

        return attestation

    def attest_batch(self, noisy_signals: list[float]) -> SimAttestation:
        """
        Atteste un lot de signaux en une seule opération SIM.
        Réduit la latence SIM pour les signaux haute fréquence.
        Hash = SHA-256 de la concaténation des signaux.
        """
        batch_bytes = b"".join(str(s).encode("utf-8") for s in noisy_signals)
        batch_hash = hashlib.sha256(batch_bytes).digest()

        signature = self._sim.sign(batch_hash)
        certificate = self._sim.get_certificate()

        attestation = SimAttestation(
            signal_hash=batch_hash,
            signature=signature,
            certificate_chain=certificate,
            slot=self.slot,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            sim_mode=f"{'MOCK' if self.mock else 'IOTSAFE'}_BATCH_{len(noisy_signals)}",
        )

        log.info(
            f"Attestation batch — {len(noisy_signals)} signaux — "
            f"hash={batch_hash.hex()[:16]}..."
        )

        return attestation


# ─────────────────────────────────────────────
# Test Termux
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("ANCRE — ancre_sim_attest.py — Test Termux")
    print("=" * 55)

    client = AncreSimAttestClient(mock=True)

    # Test signal unique
    signal = 0.73
    att = client.attest_signal(signal)
    print(f"\n[SIGNAL UNIQUE]")
    print(f"Signal bruité  : {signal}")
    print(f"Hash SHA-256   : {att.signal_hash.hex()[:32]}...")
    print(f"Signature      : {base64.b64encode(att.signature).decode()[:32]}...")
    print(f"Mode           : {att.sim_mode}")
    print(f"Timestamp      : {att.timestamp_utc}")

    # Test batch
    batch = [0.12, 0.87, 0.34, 0.56, 0.91]
    att_batch = client.attest_batch(batch)
    print(f"\n[BATCH {len(batch)} signaux]")
    print(f"Hash batch     : {att_batch.signal_hash.hex()[:32]}...")
    print(f"Mode           : {att_batch.sim_mode}")

    # Export JSON
    print(f"\n[JSON ATTESTATION]")
    print(att.to_json())

    print("\n✅ ancre_sim_attest.py — OK")
