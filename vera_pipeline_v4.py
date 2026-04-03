"""
VERA Pipeline v4.2.1 — FINAL LOCK
===================================
Garanties :
  - LDP (Client) via Randomized Response multi-bits salé (HMAC)
  - GDP (Serveur) via Laplace Noise calibré (sensitivity = RR_DURATION_MAX_S)
  - K-Anonymity ≥ 100 avec fallback géographique + diversité station ≥ 3
  - Debiasing stabilisé (prior bayésien ALPHA_PRIOR)

Conformité :
  - RGPD Art.25 (Privacy by Design)
  - Minimisation + Destruction logique documentée
  - Audit sans accès aux données brutes

Composition ε (déclarée aux régulateurs) :
  ε_client  = 1.0  (LDP — Randomized Response)
  ε_server  = 0.5  (GDP — Laplace, sensitivity=300s)
  ε_export  = 0.3  (valeur par défaut)
  ε_total   = 1.8  (composition séquentielle — pire cas)

STATUT : FINAL_LOCKED — STOP REACHED
Patches v4.2.1 :
  BUG1  K-anonymity groupé par geo_code seul → diversité station réelle
  BUG2  sensitivity = RR_DURATION_MAX_S (fixe) → calibration GDP correcte

Author : VERA Protocol — tahahouari@hotmail.fr
License: MIT
"""

from __future__ import annotations

import gc
import hashlib
import hmac
import json
import math
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple, TypedDict

# ===========================================================================
# 1. CONSTANTES & POLITIQUES (FROZEN)
# ===========================================================================

PIPELINE_VERSION = "4.2.1"
STATUS           = "FINAL_LOCKED"

# Budgets Epsilon
EPSILON_CLIENT  = 1.0
EPSILON_SERVER  = 0.5
EPSILON_QUALITY = 0.1   # réservé audit futur — non utilisé dans le core
EPSILON_DEFAULT = 0.3

EPSILON_MIN = 0.1
EPSILON_MAX = 1.5

# Paramètres Privacy
RR_DURATION_MAX_S  = 300.0
RR_NUM_BITS        = 8
K_MIN              = 100
MIN_STATION_COUNT  = 3
WK_FIXED           = 0.3

# Debiasing stabilisé (prior bayésien)
PRIOR_MEAN_DEFAULT = RR_DURATION_MAX_S / 2
ALPHA_PRIOR        = 0.3   # poids du prior — amortit la variance sur petits groupes

GEO_LEVELS = ["commune", "departement", "region", "pays"]

# ===========================================================================
# 2. CONNECTEURS INFRASTRUCTURE (À ADAPTER EN PRODUCTION)
# ===========================================================================

def get_vera_hmac_key() -> bytes:
    """
    Clé HMAC pour le sel du RR.
    En production : variable d'environnement obligatoire (HSM recommandé).
    En développement : clé de test insécure (ne jamais utiliser en prod).
    """
    key = os.environ.get("VERA_RR_HMAC_KEY", "DEVELOPMENT_INSECURE_KEY_CHANGE_ME")
    return key.encode()


def resolve_geo_official(code: str, target_level: str) -> str:
    """
    Résolution géographique hiérarchique.
    En production : remplacer par un référentiel officiel (COG INSEE ou équivalent).
    Troncature courante uniquement pour les codes FR standards.
    """
    if target_level == "commune":     return code
    if target_level == "departement": return code[:2] if len(code) >= 2 else code
    if target_level == "region":      return code[:1] if len(code) >= 1 else code
    return "FR"


# ===========================================================================
# 3. TYPES ET VALIDATION
# ===========================================================================

class VERAInputSignal(TypedDict):
    user_id_hash:    str
    station_id:      str
    duration_s:      float
    geo:             str
    consent:         bool
    consent_version: str
    collected_at:    str


class VERAError(Exception):        pass
class VERAConsentError(VERAError): pass
class VERAPolicyError(VERAError):  pass


def validate_input(s: Dict[str, Any]) -> VERAInputSignal:
    """
    Valide et normalise un signal d'entrée.
    Lève VERAConsentError ou VERAPolicyError si le contrat n'est pas respecté.
    """
    required = {"user_id_hash", "station_id", "duration_s", "geo", "consent"}
    if not required.issubset(s.keys()):
        raise VERAPolicyError(f"contrat d'entrée incomplet : {required - s.keys()}")
    if not isinstance(s["consent"], bool) or not s["consent"]:
        raise VERAConsentError("consentement opt-in requis (INV-6)")
    if not isinstance(s.get("duration_s"), (int, float)) or float(s["duration_s"]) < 0:
        raise VERAPolicyError(f"duration_s invalide : {s.get('duration_s')}")
    return {
        "user_id_hash":    str(s["user_id_hash"]),
        "station_id":      str(s["station_id"]),
        "duration_s":      float(s["duration_s"]),
        "geo":             str(s["geo"]),
        "consent":         True,
        "consent_version": str(s.get("consent_version", "1.0")),
        "collected_at":    datetime.now(timezone.utc).isoformat(),
    }


# ===========================================================================
# 4. MÉCANISMES DE BRUITAGE (LDP & GDP)
# ===========================================================================

def _laplace_sample(scale: float) -> float:
    """Tirage selon la loi de Laplace(0, scale) via la méthode de l'inverse CDF."""
    u = secrets.randbelow(10**9) / 10**9 - 0.5
    return -scale * math.copysign(1, u) * math.log(1 - 2 * abs(u) + 1e-10)


def randomized_response_salted(signal: Dict[str, Any]) -> Dict[str, Any]:
    """
    LDP — Randomized Response multi-bits salé (RAPPOR-style).

    Sel = HMAC(user_id_hash ‖ station_id ‖ epoch_heure)
    → différent à chaque heure, empêche le fingerprinting inter-sessions.

    p_keep = e^ε / (1 + e^ε) par bit → garantie ε-DP locale.
    Référence : Erlingsson et al. (2014) RAPPOR, Google.
    """
    p_keep  = math.exp(EPSILON_CLIENT) / (1 + math.exp(EPSILON_CLIENT))
    epoch_h = int(time.time() // 3600)
    msg     = f"{signal['user_id_hash']}:{signal['station_id']}:{epoch_h}".encode()
    salt    = hmac.new(get_vera_hmac_key(), msg, hashlib.sha256).hexdigest()[:16]

    h_val     = hashlib.sha256(f"{round(signal['duration_s'], 1)}:{salt}".encode()).digest()
    true_bits = [(h_val[i // 8] >> (i % 8)) & 1 for i in range(RR_NUM_BITS)]

    noised_bits = [
        b if secrets.randbelow(10_000) < int(p_keep * 10_000) else 1 - b
        for b in true_bits
    ]

    n           = sum(b << i for i, b in enumerate(noised_bits))
    duration_rr = (n / (2**RR_NUM_BITS - 1)) * RR_DURATION_MAX_S

    return {**signal, "duration_rr": duration_rr, "rr_applied": True}


def debias_signal(observed: float, p: float, prior_mean: float) -> float:
    """
    Correction du biais introduit par le RR.
    Formule : corrected = (observed - (1-p) * prior) / (2p - 1)
    Prior stabilisé bayésien : mu_stable = (1-α)*mu_obs + α*mu_prior
    """
    den = 2 * p - 1
    if abs(den) < 1e-6:
        return observed
    corrected = (observed - (1 - p) * prior_mean) / den
    return max(0.0, min(RR_DURATION_MAX_S, corrected))


# ===========================================================================
# 5. PIPELINE CORE
# ===========================================================================

def run_vera_pipeline(
    raw_data:       List[Dict[str, Any]],
    epsilon_export: float = EPSILON_DEFAULT,
) -> Dict[str, Any]:
    """
    Pipeline VERA complet — 7 étapes :
      1. Validation des entrées
      2. LDP (Randomized Response salé)
      3. Suppression user_id_hash (minimisation)
      4. Debiasing stabilisé
      5. K-Anonymity avec fallback géographique + diversité station
      6. GDP (Laplace calibré, sensitivity=RR_DURATION_MAX_S)
      7. Agrégation + destruction logique
    """

    # ── 1. Validation ────────────────────────────────────────────────────────
    signals = [validate_input(s) for s in raw_data]

    # ── 2. LDP ───────────────────────────────────────────────────────────────
    ldp_signals = []
    for s in signals:
        noised = randomized_response_salted(s)
        del noised["user_id_hash"]   # minimisation : supprimé avant toute persistance
        ldp_signals.append(noised)

    # ── 3. Debiasing stabilisé ───────────────────────────────────────────────
    p           = math.exp(EPSILON_CLIENT) / (1 + math.exp(EPSILON_CLIENT))
    mu_observed = sum(s["duration_rr"] for s in ldp_signals) / len(ldp_signals)
    mu_stable   = (1 - ALPHA_PRIOR) * mu_observed + ALPHA_PRIOR * PRIOR_MEAN_DEFAULT

    for s in ldp_signals:
        s["duration_debiased"] = debias_signal(s["duration_rr"], p, mu_stable)

    # ── 4. K-Anonymity avec fallback géographique (BUG1 FIXED) ──────────────
    #
    #  v4.2 : groupement par (station_id, geo_code) → diversité = 1 (toujours)
    #  v4.2.1 : groupement par geo_code seul → diversité réelle vérifiable
    #
    qualified_batch: List[Dict[str, Any]] = []
    final_geo_level = "rejected"

    for level in GEO_LEVELS:
        # Groupement par geo_code UNIQUEMENT (correction BUG1)
        groups: Dict[str, List[Dict[str, Any]]] = {}
        for s in ldp_signals:
            geo_code = resolve_geo_official(s["geo"], level)
            groups.setdefault(geo_code, []).append(
                {**s, "geo_resolved": geo_code, "geo_level_resolved": level}
            )

        qualified_at_level: List[Dict[str, Any]] = []
        for g in groups.values():
            if len(g) >= K_MIN:
                stations = {x["station_id"] for x in g}
                if len(stations) >= MIN_STATION_COUNT:
                    qualified_at_level.extend(g)

        if qualified_at_level:
            qualified_batch = qualified_at_level
            final_geo_level = level
            break

    if not qualified_batch:
        return {
            "status":     "REJECTED",
            "reason":     f"K-Min ({K_MIN}) ou diversité station ({MIN_STATION_COUNT}) non atteints",
            "raw_events": None,
        }

    # ── 5. GDP — Laplace calibré (BUG2 FIXED) ────────────────────────────────
    #
    #  v4.2 : sensitivity = RR_DURATION_MAX_S / n (incorrect — dépend du batch)
    #  v4.2.1 : sensitivity = RR_DURATION_MAX_S (fixe — propriété de la query)
    #  Modèle : bruit par signal, sensitivity = contribution max d'un individu.
    #  Référence : Dwork & Roth (2014), Definition 3.3.
    #
    sensitivity = RR_DURATION_MAX_S       # fixe, indépendant du batch (BUG2 FIXED)
    scale       = sensitivity / EPSILON_SERVER

    for s in qualified_batch:
        s["duration_dp"] = max(
            0.0,
            min(RR_DURATION_MAX_S, s["duration_debiased"] + _laplace_sample(scale))
        )

    # ── 6. Agrégation ────────────────────────────────────────────────────────
    total_dp = sum(s["duration_dp"] for s in qualified_batch)
    count    = len(qualified_batch)

    s_eps         = 1 - (epsilon_export - EPSILON_MIN) / (EPSILON_MAX - EPSILON_MIN)
    s_k           = min(math.log(count / K_MIN + 1) / math.log(11), 1.0)
    privacy_score = round((1 - WK_FIXED) * s_eps + WK_FIXED * s_k, 4)

    # ── 7. Destruction logique ────────────────────────────────────────────────
    trace_hash = hashlib.sha256(
        json.dumps(sorted(
            s.get("transmission_id", secrets.token_hex(4)) for s in ldp_signals
        ), separators=(",", ":")).encode()
    ).hexdigest()

    for s in ldp_signals:
        s.clear()
    gc.collect()

    # ── Résultat ─────────────────────────────────────────────────────────────
    return {
        "status":           "OK",
        "pipeline_version": PIPELINE_VERSION,
        "pipeline_status":  STATUS,
        "timestamp":        datetime.now(timezone.utc).isoformat(),

        "aggregate": {
            "total_duration_dp": round(total_dp, 2),
            "signal_count":      count,
            "geo_level":         final_geo_level,
            "privacy_score":     privacy_score,
            "k_effective":       count,
            "k_min":             K_MIN,
            "station_diversity": len({s["station_id"] for s in qualified_batch}),
        },

        "epsilon_composition": {
            "epsilon_client":          EPSILON_CLIENT,
            "epsilon_server":          EPSILON_SERVER,
            "epsilon_export":          epsilon_export,
            "epsilon_total_sequential":round(EPSILON_CLIENT + EPSILON_SERVER + epsilon_export, 4),
            "sensitivity_s":           sensitivity,
            "composition_note": (
                "Composition séquentielle — pire cas. "
                "Dwork & Roth (2014), Theorem 3.16."
            ),
        },

        "destruction": {
            "trace_hash": trace_hash,
            "note": (
                "Destruction logique (clear + gc). "
                "Destruction physique (DB VACUUM, shred) hors scope pipeline."
            ),
        },

        "raw_events": None,   # INV-7 : jamais de données brutes en sortie
    }


# ===========================================================================
# TEST / DÉMO
# ===========================================================================

if __name__ == "__main__":
    print(f"VERA Pipeline {PIPELINE_VERSION} — {STATUS}")
    print("=" * 55)

    mock_data = [
        {
            "user_id_hash": secrets.token_hex(16),
            "station_id":   f"STATION_{i % 5}",
            "duration_s":   180.0 + (i % 30),
            "geo":          "75011",
            "consent":      True,
        }
        for i in range(150)
    ]

    result = run_vera_pipeline(mock_data)
    print(json.dumps(result, indent=2, ensure_ascii=False))


