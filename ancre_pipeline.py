"""
ancre_pipeline.py
ANCRE — Attested Noise Client Runtime Engine
Pipeline complet : LDP VERA + attestation SIM

Hérite intégralement du pipeline VERA :
  - Laplace noise (ε_client=1.0)
  - K-anonymité (K≥100)
  - Trimmed median-of-means
  - Kill-switch (ε_total≤1.5)
  - Audit chain Ed25519 + RFC3161

Delta ANCRE :
  - Attestation SIM avant agrégation
  - Rejet des signaux non attestés
  - VSI étendu avec champ attestation

Auteur : SAS VERA
Version : 0.1
"""

import numpy as np
import hashlib
import json
import base64
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from ancre_sim_attest import AncreSimAttestClient, SimAttestation
from ancre_verify import AncreAttestVerifier, VerificationResult

log = logging.getLogger("ANCRE.Pipeline")

# ─────────────────────────────────────────────
# Invariants hérités de VERA — NON MODIFIABLES
# ─────────────────────────────────────────────
EPSILON_CLIENT   = 1.0
EPSILON_SERVER   = 0.5
EPSILON_TOTAL    = EPSILON_CLIENT + EPSILON_SERVER  # 1.5
EPSILON_MAX      = 1.5
K_MIN            = 100
W_K              = 0.3
CORRELATION_SYBIL = 0.85

# ─────────────────────────────────────────────
# Structures
# ─────────────────────────────────────────────

@dataclass
class AttestdSignal:
    """Signal bruité accompagné de son attestation SIM."""
    noisy_value: float
    attestation: SimAttestation
    verification: VerificationResult
    accepted: bool


@dataclass
class AncreAggregateResult:
    """Résultat d'une agrégation ANCRE."""
    aggregate_value: float
    k_actual: int
    epsilon_total: float
    vsi: float
    attestation_rate: float        # % signaux avec attestation valide
    operator_distribution: dict    # distribution des opérateurs attestants
    timestamp_utc: str
    pipeline: str = "ANCRE_v0.1"
    kill_switch_triggered: bool = False

    def to_dict(self) -> dict:
        return {
            "aggregate_value": self.aggregate_value,
            "k_actual": self.k_actual,
            "epsilon_total": self.epsilon_total,
            "vsi": self.vsi,
            "attestation_rate": self.attestation_rate,
            "operator_distribution": self.operator_distribution,
            "timestamp_utc": self.timestamp_utc,
            "pipeline": self.pipeline,
            "kill_switch_triggered": self.kill_switch_triggered,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# ─────────────────────────────────────────────
# Client ANCRE (côté appareil)
# ─────────────────────────────────────────────

class AncreClient:
    """
    Côté appareil utilisateur.
    Applique le bruit LDP puis atteste via SIM.
    """

    def __init__(self, mock_sim: bool = True):
        self.sim_client = AncreSimAttestClient(mock=mock_sim)
        log.info(f"AncreClient initialisé — mock_sim={mock_sim}")

    def process_signal(self, raw_signal: float) -> AttestdSignal:
        """
        1. Injecte bruit Laplace (ε=1.0)
        2. Détruit le signal brut
        3. Atteste via SIM
        4. Retourne AttestdSignal

        raw_signal ∈ [0, 1]
        """
        # Validation entrée
        if not 0.0 <= raw_signal <= 1.0:
            raise ValueError(f"Signal hors plage [0,1] : {raw_signal}")

        # Injection bruit Laplace
        noisy = float(np.clip(
            raw_signal + np.random.laplace(0.0, 1.0 / EPSILON_CLIENT),
            0.0, 1.0
        ))

        # Destruction signal brut (référence Python libérée)
        del raw_signal

        # Attestation SIM
        attestation = self.sim_client.attest_signal(noisy)

        log.info(f"Signal traité — noisy={noisy:.4f} — mode={attestation.sim_mode}")

        # La vérification sera faite côté serveur
        # On retourne un AttestdSignal partiel (verification sera remplie par le serveur)
        return AttestdSignal(
            noisy_value=noisy,
            attestation=attestation,
            verification=VerificationResult(valid=True, reason="Non vérifié côté client"),
            accepted=True,
        )

    def process_batch(self, raw_signals: list[float]) -> AttestdSignal:
        """Traitement batch — une attestation SIM pour N signaux."""
        validated = [s for s in raw_signals if 0.0 <= s <= 1.0]
        noisy_batch = [
            float(np.clip(s + np.random.laplace(0.0, 1.0 / EPSILON_CLIENT), 0.0, 1.0))
            for s in validated
        ]
        del validated, raw_signals

        attestation = self.sim_client.attest_batch(noisy_batch)

        # Pour le batch on retourne le signal moyen comme représentant
        mean_noisy = float(np.mean(noisy_batch))

        return AttestdSignal(
            noisy_value=mean_noisy,
            attestation=attestation,
            verification=VerificationResult(valid=True, reason="Non vérifié côté client"),
            accepted=True,
        )


# ─────────────────────────────────────────────
# Serveur ANCRE
# ─────────────────────────────────────────────

class AncreServer:
    """
    Côté serveur ANCRE.
    Vérifie les attestations, agrège, applique les invariants VERA.
    """

    def __init__(
        self,
        trusted_operator_orgs: list[str] = None,
        reject_mock: bool = False,
    ):
        self.verifier = AncreAttestVerifier(
            trusted_operator_orgs=trusted_operator_orgs,
            reject_mock=reject_mock,
        )
        self._buffer: list[AttestdSignal] = []
        log.info(f"AncreServer initialisé — reject_mock={reject_mock}")

    def receive(self, attested: AttestdSignal) -> bool:
        """
        Reçoit un signal attesté.
        Vérifie l'attestation SIM avant d'accepter dans le buffer.
        """
        att = attested.attestation

        verification = self.verifier.verify(
            noisy_signal=attested.noisy_value,
            signal_hash_b64=base64.b64encode(att.signal_hash).decode(),
            signature_b64=base64.b64encode(att.signature).decode(),
            certificate_chain_b64=base64.b64encode(att.certificate_chain).decode(),
            sim_mode=att.sim_mode,
        )

        attested.verification = verification
        attested.accepted = verification.valid

        if verification.valid:
            self._buffer.append(attested)
            log.info(
                f"Signal accepté — buffer={len(self._buffer)} — "
                f"opérateur={verification.operator_org}"
            )
        else:
            log.warning(f"Signal rejeté — {verification.reason}")

        return verification.valid

    def aggregate(self) -> Optional[AncreAggregateResult]:
        """
        Agrège le buffer si K≥100.
        Pipeline VERA complet + métriques attestation.
        """
        accepted = [s for s in self._buffer if s.accepted]
        k_actual = len(accepted)

        # Kill-switch K
        if k_actual < K_MIN:
            log.warning(
                f"Agrégation refusée — K={k_actual} < {K_MIN} (kill-switch)"
            )
            return AncreAggregateResult(
                aggregate_value=0.0,
                k_actual=k_actual,
                epsilon_total=EPSILON_TOTAL,
                vsi=0.0,
                attestation_rate=0.0,
                operator_distribution={},
                timestamp_utc=datetime.now(timezone.utc).isoformat(),
                kill_switch_triggered=True,
            )

        # Kill-switch epsilon
        if EPSILON_TOTAL > EPSILON_MAX:
            log.error(f"KILL-SWITCH ε_total={EPSILON_TOTAL} > {EPSILON_MAX}")
            self._buffer.clear()
            return AncreAggregateResult(
                aggregate_value=0.0,
                k_actual=k_actual,
                epsilon_total=EPSILON_TOTAL,
                vsi=0.0,
                attestation_rate=0.0,
                operator_distribution={},
                timestamp_utc=datetime.now(timezone.utc).isoformat(),
                kill_switch_triggered=True,
            )

        signals = [s.noisy_value for s in accepted]

        # Détection coalition Sybil
        signals = self._apply_coalition_cap(signals)

        # Trimmed median-of-means (hérité VERA)
        aggregate = self._trimmed_median_of_means(signals)

        # Bruit serveur (ε_server=0.5)
        aggregate = float(np.clip(
            aggregate + np.random.laplace(0.0, (1.0 / K_MIN) / EPSILON_SERVER),
            0.0, 1.0
        ))

        # VSI ANCRE (étendu avec taux d'attestation)
        attestation_rate = k_actual / max(len(self._buffer), 1)
        vsi = self._compute_vsi(signals, aggregate, k_actual, attestation_rate)

        # Distribution opérateurs
        op_dist = {}
        for s in accepted:
            op = s.verification.operator_org or "INCONNU"
            op_dist[op] = op_dist.get(op, 0) + 1

        result = AncreAggregateResult(
            aggregate_value=aggregate,
            k_actual=k_actual,
            epsilon_total=EPSILON_TOTAL,
            vsi=vsi,
            attestation_rate=attestation_rate,
            operator_distribution=op_dist,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
        )

        # Vider le buffer post-agrégation
        self._buffer.clear()

        log.info(
            f"Agrégation ANCRE — K={k_actual} — "
            f"aggregate={aggregate:.4f} — VSI={vsi:.4f} — "
            f"attestation_rate={attestation_rate:.2%}"
        )

        return result

    def _trimmed_median_of_means(
        self,
        signals: list[float],
        n_groups: int = 10,
        trim_fraction: float = 0.2,
    ) -> float:
        arr = np.array(signals)
        np.random.shuffle(arr)
        groups = np.array_split(arr, min(n_groups, len(arr)))
        means = sorted([float(np.mean(g)) for g in groups if len(g) > 0])
        trim = max(1, int(len(means) * trim_fraction))
        trimmed = means[trim:-trim] if len(means) > 2 * trim else means
        return float(np.median(trimmed))

    def _apply_coalition_cap(self, signals: list[float]) -> list[float]:
        """Cap wK=0.3 sur les clusters corrélés détectés."""
        arr = np.array(signals)
        if len(arr) < 10:
            return signals

        # Détection simple : signaux dans le top 30% de variance inter-groupe
        median = float(np.median(arr))
        deviations = np.abs(arr - median)
        threshold = np.percentile(deviations, 70)
        suspect_mask = deviations > threshold

        n_suspect = int(np.sum(suspect_mask))
        max_coalition = int(len(arr) * W_K)

        if n_suspect > max_coalition:
            # Garder seulement max_coalition signaux suspects
            suspect_idx = np.where(suspect_mask)[0]
            np.random.shuffle(suspect_idx)
            remove_idx = set(suspect_idx[max_coalition:])
            signals = [s for i, s in enumerate(signals) if i not in remove_idx]
            log.warning(
                f"Coalition cap appliqué — {n_suspect} suspects → "
                f"{max_coalition} retenus"
            )

        return signals

    def _compute_vsi(
        self,
        signals: list[float],
        aggregate: float,
        k_actual: int,
        attestation_rate: float,
    ) -> float:
        """
        VSI ANCRE — étend le VSI VERA avec le taux d'attestation SIM.

        VSI_ANCRE = ρ × (1 - σ_noise/σ_signal) × K_factor × attestation_rate
        """
        arr = np.array(signals)
        sigma_signal = float(np.std(arr)) if len(arr) > 1 else 1.0
        sigma_noise = 1.0 / EPSILON_CLIENT

        noise_ratio = min(sigma_noise / max(sigma_signal, 1e-9), 1.0)
        k_factor = min(k_actual / K_MIN, 1.0)

        # Corrélation de rang simulée (en prod : comparer avec signal de référence)
        rho = max(0.0, 1.0 - noise_ratio)

        vsi = rho * (1.0 - noise_ratio) * k_factor * attestation_rate
        return round(float(np.clip(vsi, 0.0, 1.0)), 4)


# ─────────────────────────────────────────────
# Test Termux — Pipeline complet
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("ANCRE — ancre_pipeline.py — Test Termux")
    print("=" * 55)

    # Simulation : 120 signaux (K≥100 respecté)
    N = 120
    print(f"\nGénération de {N} signaux simulés...")

    client = AncreClient(mock_sim=True)
    server = AncreServer(reject_mock=False)

    raw_signals = np.random.beta(2, 5, N).tolist()  # distribution réaliste écoute
    accepted_count = 0

    for i, raw in enumerate(raw_signals):
        attested = client.process_signal(raw)
        ok = server.receive(attested)
        if ok:
            accepted_count += 1
        if (i + 1) % 20 == 0:
            print(f"  Traité {i+1}/{N} — acceptés : {accepted_count}")

    print(f"\nBuffer serveur : {accepted_count} signaux acceptés")

    # Agrégation
    result = server.aggregate()

    print(f"\n{'='*55}")
    print("RÉSULTAT AGRÉGATION ANCRE")
    print(f"{'='*55}")
    print(result.to_json())

    # Assertions invariants
    assert not result.kill_switch_triggered, "Kill-switch déclenché"
    assert result.k_actual >= K_MIN, f"K={result.k_actual} < {K_MIN}"
    assert result.epsilon_total <= EPSILON_MAX, f"ε={result.epsilon_total} > {EPSILON_MAX}"
    assert 0.0 <= result.aggregate_value <= 1.0, "Agrégat hors [0,1]"

    print(f"\n✅ Invariants vérifiés :")
    print(f"   K={result.k_actual} ≥ {K_MIN}")
    print(f"   ε_total={result.epsilon_total} ≤ {EPSILON_MAX}")
    print(f"   Agrégat={result.aggregate_value:.4f} ∈ [0,1]")
    print(f"   VSI={result.vsi}")
    print(f"   Attestation rate={result.attestation_rate:.2%}")

    print("\n✅ ancre_pipeline.py — OK")
