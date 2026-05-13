"""
ancre_pipeline.py
ANCRE — Attested Noise Client Runtime Engine
Pipeline complet v0.2 — Post red team multi-IA

Corrections intégrées :
  P7  — Buffer size limit + timeout (anti-DoS)
  P9  — Coalition cap sur identité device (pas heuristique outlier)
  P10 — Noise scale calibré sur k_actual (pas K_MIN fixe)

Auteur : SAS VERA / ANCRE
Version : 0.2
"""

import uuid
import logging
import numpy as np
from datetime import datetime, timezone

from ancre_verify import (
    AncreAttestVerifier, AncreAttestation, SignedPayload,
    canonical_signal_hash, validate_signal,
)
from ancre_sim_attest import MockSimCard

import cryptography.x509 as x509

log = logging.getLogger("ANCRE.Pipeline")

# ─────────────────────────────────────────────
# Invariants VERA — NON MODIFIABLES
# ─────────────────────────────────────────────
EPSILON_CLIENT = 1.0
EPSILON_SERVER = 0.5
EPSILON_TOTAL  = EPSILON_CLIENT + EPSILON_SERVER  # 1.5
EPSILON_MAX    = 1.5
K_MIN          = 100
W_K            = 0.3

# ─────────────────────────────────────────────
# Paramètres v0.2
# ─────────────────────────────────────────────
MAX_BUFFER_SIZE    = 10_000
BUFFER_TIMEOUT_SEC = 3600


# ─────────────────────────────────────────────
# Client ANCRE v0.2
# ─────────────────────────────────────────────

class AncreClient:
    """Côté appareil — applique bruit LDP et atteste via SIM."""

    def __init__(self, mock_sim: bool = True):
        self._sim = MockSimCard(slot=1)
        self._sim.generate_keypair()
        self._cert_der = self._sim.get_certificate()
        self._cert = x509.load_der_x509_certificate(self._cert_der)
        self._cert_serial = self._cert.serial_number
        self.mock_sim = mock_sim
        log.info(f"AncreClient v0.2 — mock_sim={mock_sim}")

    def process_signal(self, raw_signal: float, nonce: str) -> AncreAttestation:
        """
        1. Valide le signal
        2. Injecte bruit Laplace (ε=1.0)
        3. Détruit le signal brut
        4. Crée SignedPayload avec nonce serveur
        5. SIM signe le payload
        """
        validate_signal(raw_signal)

        noisy = float(np.clip(
            raw_signal + np.random.laplace(0.0, 1.0 / EPSILON_CLIENT),
            0.0, 1.0
        ))
        del raw_signal

        sig_hash = canonical_signal_hash(noisy)
        payload = SignedPayload(
            signal_hash=sig_hash,
            nonce=nonce,
            slot=1,
            sim_mode="MOCK" if self.mock_sim else "IOTSAFE",
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
        )
        payload_sig = self._sim.sign(payload.to_bytes())

        return AncreAttestation(
            noisy_value=noisy,
            payload=payload,
            payload_signature=payload_sig,
            certificate_chain=self._cert_der,
            cert_serial=self._cert_serial,
        )


# ─────────────────────────────────────────────
# Serveur ANCRE v0.2
# ─────────────────────────────────────────────

class AncreServer:
    """Serveur — vérifie, agrège, exporte."""

    def __init__(
        self,
        reject_mock: bool = False,
        max_signals_per_device: int = 5,
    ):
        self.verifier = AncreAttestVerifier(
            reject_mock=reject_mock,
            max_signals_per_device=max_signals_per_device,
        )
        self._buffer: list = []  # (noisy_value, cert_serial)
        self._buffer_opened_at = None
        log.info(f"AncreServer v0.2 — reject_mock={reject_mock}")

    def issue_nonce(self) -> str:
        """Émet un nonce à envoyer au client avant sa soumission."""
        return self.verifier.issue_nonce()

    def receive(self, att: AncreAttestation) -> bool:
        """Vérifie l'attestation et l'ajoute au buffer si valide."""

        # P7 — Limite buffer
        if len(self._buffer) >= MAX_BUFFER_SIZE:
            log.warning("Buffer plein — signal rejeté")
            return False

        # P7 — Timeout buffer
        if self._buffer_opened_at:
            age = (datetime.now(timezone.utc) - self._buffer_opened_at).total_seconds()
            if age > BUFFER_TIMEOUT_SEC:
                log.warning(f"Buffer timeout — flush sans export")
                self._buffer.clear()
                self._buffer_opened_at = None
                self.verifier.reset_device_counts()

        valid, reason = self.verifier.verify(att)

        if valid:
            if not self._buffer_opened_at:
                self._buffer_opened_at = datetime.now(timezone.utc)
            self._buffer.append((att.noisy_value, att.cert_serial))
            log.info(f"Signal accepté — buffer={len(self._buffer)} — {reason}")
        else:
            log.warning(f"Signal rejeté — {reason}")

        return valid

    def aggregate(self) -> dict:
        """
        P9 — Coalition cap par identité device.
        P10 — Noise scale sur k_actual.
        """
        k_actual = len(self._buffer)

        if k_actual < K_MIN:
            self._buffer.clear()
            self._buffer_opened_at = None
            return {
                "kill_switch_triggered": True,
                "reason": f"K={k_actual} < {K_MIN}",
                "aggregate_value": 0.0,
                "k_actual": k_actual,
                "epsilon_total": EPSILON_TOTAL,
                "vsi": 0.0,
                "attestation_rate": 0.0,
                "pipeline": "ANCRE_v0.2",
            }

        # P9 — Cap par identité device
        max_per_device = max(1, int(k_actual * W_K))
        filtered = []
        device_included: dict = {}

        for noisy_val, serial in self._buffer:
            count = device_included.get(serial, 0)
            if count < max_per_device:
                filtered.append(noisy_val)
                device_included[serial] = count + 1

        k_filtered = len(filtered)

        if k_filtered < K_MIN:
            self._buffer.clear()
            self._buffer_opened_at = None
            return {
                "kill_switch_triggered": True,
                "reason": f"K post-coalition={k_filtered} < {K_MIN}",
                "aggregate_value": 0.0,
                "k_actual": k_filtered,
                "epsilon_total": EPSILON_TOTAL,
                "vsi": 0.0,
                "attestation_rate": 0.0,
                "pipeline": "ANCRE_v0.2",
            }

        # Trimmed median-of-means
        arr = np.array(filtered)
        np.random.shuffle(arr)
        n_groups = min(10, k_filtered)
        groups = np.array_split(arr, n_groups)
        means = sorted([float(np.mean(g)) for g in groups if len(g) > 0])
        trim = max(1, int(len(means) * 0.2))
        trimmed = means[trim:-trim] if len(means) > 2 * trim else means
        agg = float(np.median(trimmed))

        # P10 — Noise scale k_actual
        sensitivity = 1.0 / k_filtered
        noise_scale = sensitivity / EPSILON_SERVER
        agg = float(np.clip(agg + np.random.laplace(0.0, noise_scale), 0.0, 1.0))

        # VSI
        sigma_signal = float(np.std(arr)) if len(arr) > 1 else 1.0
        sigma_noise = 1.0 / EPSILON_CLIENT
        noise_ratio = min(sigma_noise / max(sigma_signal, 1e-9), 1.0)
        k_factor = min(k_filtered / K_MIN, 1.0)
        rho = max(0.0, 1.0 - noise_ratio)
        vsi = round(float(np.clip(rho * (1.0 - noise_ratio) * k_factor, 0.0, 1.0)), 4)

        result = {
            "kill_switch_triggered": False,
            "aggregate_value": agg,
            "k_actual": k_filtered,
            "k_before_coalition_filter": k_actual,
            "epsilon_total": EPSILON_TOTAL,
            "noise_scale_actual": noise_scale,
            "vsi": vsi,
            "attestation_rate": 1.0,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "pipeline": "ANCRE_v0.2",
        }

        self._buffer.clear()
        self._buffer_opened_at = None
        log.info(f"Agrégation v0.2 — K={k_filtered} — agg={agg:.4f} — VSI={vsi}")
        return result


# ─────────────────────────────────────────────
# Test Termux
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("ANCRE — ancre_pipeline.py v0.2 — Test Termux")
    print("=" * 55)

    N = 120
    print(f"\nGénération de {N} signaux — {N} clients distincts...")

    server = AncreServer(reject_mock=False, max_signals_per_device=5)
    accepted = 0

    for i in range(N):
        client = AncreClient(mock_sim=True)
        nonce = server.issue_nonce()
        raw = float(np.random.beta(2, 5))
        att = client.process_signal(raw, nonce=nonce)
        if server.receive(att):
            accepted += 1

    print(f"Buffer : {accepted}/{N} signaux acceptés")

    result = server.aggregate()

    print(f"\n{'='*55}")
    print("RÉSULTAT AGRÉGATION ANCRE v0.2")
    print(f"{'='*55}")
    import json
    print(json.dumps(result, indent=2))

    assert not result["kill_switch_triggered"], "Kill-switch déclenché"
    assert result["k_actual"] >= K_MIN, f"K={result['k_actual']} < {K_MIN}"
    assert result["epsilon_total"] <= EPSILON_MAX
    assert 0.0 <= result["aggregate_value"] <= 1.0

    print(f"\n✅ Invariants vérifiés")
    print(f"   K={result['k_actual']} ≥ {K_MIN}")
    print(f"   ε_total={result['epsilon_total']} ≤ {EPSILON_MAX}")
    print(f"   Agrégat={result['aggregate_value']:.4f} ∈ [0,1]")
    print(f"   pipeline={result['pipeline']}")
    print(f"\n✅ ancre_pipeline.py v0.2 — OK")
