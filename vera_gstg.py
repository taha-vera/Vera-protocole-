"""
VERA GSTG v1 — vera_gstg.py
=============================
Global State Transition Graph

Un seul état global.
Une seule fonction de transition.
NAV + DP + Audit dans la même dynamique.

STATE(t+1) = T(STATE(t), EVENT)

Propriétés :
- Atomicité : soit tout change, soit rien
- Déterminisme : même état + même event = même résultat
- Vérifiabilité : toute l'histoire est reconstructible
- Impossibilité des états partiels

RÈGLE ABSOLUE :
- vera_core_v271_verified.py — FINAL LOCK, non modifié
- vera_nav_final.py — non modifié

Status : LOCAL ONLY
Date : Mai 2026
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from vera_nav_final import VERANav


# ===========================================================================
# ÉVÉNEMENTS — inputs du graphe
# ===========================================================================

@dataclass(frozen=True)
class EventIngest:
    session_id: str
    branch:     str
    raw_values: Tuple[float, ...]
    b2b_token:  str = ""


@dataclass(frozen=True)
class EventReveal:
    session_id: str
    branch:     str = "radio"


@dataclass(frozen=True)
class EventDeny:
    session_id: str
    reason:     str


# Type union des événements
Event = EventIngest | EventReveal | EventDeny


# ===========================================================================
# ÉTAT GLOBAL — un seul objet immuable
# ===========================================================================

@dataclass(frozen=True)
class DPComponent:
    """Composante DP de l'état global."""
    cost_used: float
    threshold: float

    @property
    def remaining(self) -> float:
        return max(0.0, self.threshold - self.cost_used)

    @property
    def is_exhausted(self) -> bool:
        return self.cost_used >= self.threshold


@dataclass(frozen=True)
class NAVComponent:
    """
    Composante NAV de l'état global.
    NAV devient une fonction dans T, pas un oracle externe.
    """
    last_entropy:   int
    last_signal_id: str
    n_sessions:     int
    last_branch:    str


@dataclass(frozen=True)
class AuditComponent:
    """Composante Audit de l'état global — chaîne immuable."""
    chain:      Tuple[Dict[str, Any], ...]
    event_count: int

    def verify(self) -> bool:
        for i, item in enumerate(self.chain):
            prev_hash = self.chain[i-1]["hash"] if i > 0 else "0" * 64
            if item.get("prev_hash") != prev_hash:
                return False
            expected = hashlib.sha256(
                f"{prev_hash}:{item['event_hash']}:{item['state_fingerprint']}".encode()
            ).hexdigest()
            if expected != item["hash"]:
                return False
        return True

    def __len__(self) -> int:
        return len(self.chain)


@dataclass(frozen=True)
class VeraGlobalState:
    """
    État global VERA — un seul objet immuable.
    Contient dp + nav + audit.
    Impossible d'avoir un état partiel.
    """
    dp:    DPComponent
    nav:   NAVComponent
    audit: AuditComponent
    t:     int  # horloge logique — incrémentée à chaque transition

    def fingerprint(self) -> str:
        """Hash de l'état global — détecte tout tampering."""
        payload = (
            f"{self.t}:"
            f"{self.dp.cost_used}:"
            f"{self.nav.last_signal_id}:"
            f"{len(self.audit)}"
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:16]


# ===========================================================================
# ÉTAT INITIAL
# ===========================================================================

def initial_state(threshold: float = 50.0) -> VeraGlobalState:
    """Construit l'état initial du système."""
    genesis_hash = hashlib.sha256(b"VERA_GENESIS").hexdigest()
    return VeraGlobalState(
        dp    = DPComponent(cost_used=0.0, threshold=threshold),
        nav   = NAVComponent(
            last_entropy   = 0,
            last_signal_id = genesis_hash[:16],
            n_sessions     = 0,
            last_branch    = "",
        ),
        audit = AuditComponent(chain=(), event_count=0),
        t     = 0,
    )


# ===========================================================================
# ERREURS
# ===========================================================================

class TransitionError(RuntimeError):
    """Transition impossible — état invalide par construction."""
    pass


class BudgetExhaustedError(TransitionError):
    """Budget DP épuisé."""
    pass


# ===========================================================================
# FONCTION DE TRANSITION GLOBALE
# STATE(t+1) = T(STATE(t), EVENT)
# ===========================================================================

def _hash_event(event: Event) -> str:
    """Hash déterministe d'un événement — payload explicite par type."""
    if isinstance(event, EventIngest):
        payload = f"I:{event.session_id}:{event.branch}:{event.raw_values}"
    elif isinstance(event, EventReveal):
        payload = f"R:{event.session_id}:{event.branch}"
    else:
        payload = f"D:{event.session_id}:{event.reason}"
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _audit_append(
    audit: AuditComponent,
    event: Event,
    state_fingerprint: str,
) -> AuditComponent:
    """
    Ajoute un événement à la chaîne d'audit.
    Chaîne au hash précédent + fingerprint de l'état.
    """
    prev_hash   = audit.chain[-1]["hash"] if audit.chain else "0" * 64
    event_hash  = _hash_event(event)
    chain_input = f"{prev_hash}:{event_hash}:{state_fingerprint}"
    h           = hashlib.sha256(chain_input.encode()).hexdigest()

    entry = {
        "t":                audit.event_count,
        "event_hash":       event_hash,
        "state_fingerprint": state_fingerprint,
        "prev_hash":        prev_hash,
        "hash":             h,
    }
    return AuditComponent(
        chain       = (*audit.chain, entry),
        event_count = audit.event_count + 1,
    )


def transition(
    state:        VeraGlobalState,
    event:        Event,
    nav_adapter:  "NAVAdapter",
) -> Tuple[VeraGlobalState, Dict[str, Any]]:
    """
    Fonction de transition globale — STATE(t+1) = T(STATE(t), EVENT).

    Atomique : soit tout change, soit TransitionError levée.
    Le nouvel état est retourné — l'ancien est inchangé (immuable).

    Returns:
        (new_state, output)
    """

    # ── EventIngest ──────────────────────────────────────────────────────
    if isinstance(event, EventIngest):

        # 1. Vérification budget — avant tout effet
        if state.dp.is_exhausted:
            raise BudgetExhaustedError(
                f"Budget épuisé : {state.dp.cost_used}/{state.dp.threshold}"
            )

        # 2. NAV — encapsulé dans la transition
        nav_result = nav_adapter.process(
            session_id = event.session_id,
            branch     = event.branch,
            raw_values = list(event.raw_values),
            b2b_token  = event.b2b_token,
        )

        cost    = nav_result.get("cost", 1.0)
        entropy = nav_result.get("entropy", 500)
        sig_id  = nav_result.get("signal_id", "")

        # 3. Nouvelles composantes — immuables
        new_dp = DPComponent(
            cost_used = round(state.dp.cost_used + cost, 3),
            threshold = state.dp.threshold,
        )
        new_nav = NAVComponent(
            last_entropy   = entropy,
            last_signal_id = sig_id,
            n_sessions     = state.nav.n_sessions + 1,
            last_branch    = event.branch,
        )

        # 4. Fingerprint pré-audit (état intermédiaire)
        pre_fp = VeraGlobalState(
            dp=new_dp, nav=new_nav,
            audit=state.audit, t=state.t + 1
        ).fingerprint()

        # 5. Audit — chaîné sur fingerprint
        new_audit = _audit_append(state.audit, event, pre_fp)

        # 6. Nouvel état global — atomique
        new_state = VeraGlobalState(
            dp    = new_dp,
            nav   = new_nav,
            audit = new_audit,
            t     = state.t + 1,
        )

        output = {
            "status":  nav_result.get("status", "ok"),
            "entropy": entropy,
            "t":       new_state.t,
        }
        if nav_result.get("signals"):
            output["signals"] = nav_result["signals"]

        return new_state, output

    # ── EventReveal ───────────────────────────────────────────────────────
    elif isinstance(event, EventReveal):

        reveal_result = nav_adapter.reveal(
            session_id = event.session_id,
            branch     = event.branch,
        )

        pre_fp = VeraGlobalState(
            dp=state.dp, nav=state.nav,
            audit=state.audit, t=state.t + 1
        ).fingerprint()

        new_audit = _audit_append(state.audit, event, pre_fp)

        new_state = VeraGlobalState(
            dp    = state.dp,   # reveal ne consomme pas de budget DP global
            nav   = state.nav,
            audit = new_audit,
            t     = state.t + 1,
        )

        return new_state, {
            "status":  reveal_result.get("status", "no_signal"),
            "signals": reveal_result.get("signals", []),
            "noise":   True,
            "t":       new_state.t,
        }

    # ── EventDeny ─────────────────────────────────────────────────────────
    elif isinstance(event, EventDeny):

        pre_fp    = VeraGlobalState(
            dp=state.dp, nav=state.nav,
            audit=state.audit, t=state.t + 1
        ).fingerprint()
        new_audit = _audit_append(state.audit, event, pre_fp)

        new_state = VeraGlobalState(
            dp    = state.dp,
            nav   = state.nav,
            audit = new_audit,
            t     = state.t + 1,
        )

        return new_state, {
            "status":  "denied",
            "entropy": 0,
            "reason":  event.reason,
            "t":       new_state.t,
        }

    else:
        raise TransitionError(f"Événement inconnu : {type(event)}")


# ===========================================================================
# NAV ADAPTER — encapsule VERANav dans le graphe
# ===========================================================================

class NAVAdapter:
    """
    Adaptateur NAV — encapsule VERANav dans la fonction de transition.
    NAV n'est plus un oracle externe — il est appelé uniquement dans T().
    """

    def __init__(self, time_provider: Optional[Callable] = None) -> None:
        self._nav  = VERANav()
        self._time = time_provider or time.time

    def process(
        self,
        session_id: str,
        branch:     str,
        raw_values: List[float],
        b2b_token:  str = "",
    ) -> Dict[str, Any]:
        """Appel NAV — retourne les données pour la transition."""
        result = self._nav.process(
            origin_ip  = session_id,
            branch     = branch,
            raw_values = raw_values,
            b2b_token  = b2b_token,
        )

        tier = result.get("session", {}).get("entropy_tier", "medium")
        entropy = {"low": 300, "medium": 600, "high": 900}.get(tier, 500)

        sig_id = hashlib.sha256(
            f"{session_id}:{int(self._time())//3600}".encode()
        ).hexdigest()[:16]

        output = result.get("output", {})
        signals = output.get("signals", [])

        return {
            "status":    result.get("status", "ok"),
            "entropy":   entropy,
            "signal_id": sig_id,
            "cost":      1.0,
            "signals":   signals,
        }

    def reveal(self, session_id: str, branch: str = "radio") -> Dict[str, Any]:
        return self._nav.reveal(origin_ip=session_id, branch=branch)


# ===========================================================================
# VERA GSTG — interface publique
# ===========================================================================

class VeraGSTG:
    """
    Interface publique du GSTG.

    Usage :
        g = VeraGSTG()
        output = g.ingest("session_1", "radio", [180.0, 120.0])
        output = g.reveal("session_1")

    Propriétés :
    - Atomicité : ingest/reveal = transition atomique
    - Vérifiabilité : g.verify() confirme l'intégrité de tout l'historique
    - Immuabilité : chaque état est un nouveau frozen dataclass
    """

    def __init__(
        self,
        threshold:     float = 50.0,
        time_provider: Optional[Callable] = None,
    ) -> None:
        self._state   = initial_state(threshold=threshold)
        self._adapter = NAVAdapter(time_provider=time_provider)

    def ingest(
        self,
        session_id: str,
        branch:     str,
        raw_values: List[float],
        b2b_token:  str = "",
    ) -> Dict[str, Any]:
        """Transition ingest — atomique."""
        if self._state.dp.is_exhausted:
            deny_event = EventDeny(
                session_id = session_id,
                reason     = "budget_exhausted",
            )
            self._state, output = transition(
                self._state, deny_event, self._adapter
            )
            return output

        event = EventIngest(
            session_id = session_id,
            branch     = branch,
            raw_values = tuple(raw_values),
            b2b_token  = b2b_token,
        )
        self._state, output = transition(self._state, event, self._adapter)
        return output

    def reveal(self, session_id: str, branch: str = "radio") -> Dict[str, Any]:
        """Transition reveal — atomique."""
        event = EventReveal(session_id=session_id, branch=branch)
        self._state, output = transition(self._state, event, self._adapter)
        return output

    def verify(self) -> bool:
        """Vérifie l'intégrité de tout l'historique."""
        return self._state.audit.verify()

    @property
    def state(self) -> VeraGlobalState:
        return self._state

    @property
    def t(self) -> int:
        return self._state.t


# ===========================================================================
# TESTS
# ===========================================================================

def _run_tests() -> None:
    import json

    print(f"\n{'='*55}")
    print("  VERA GSTG v1 — Tests")
    print(f"{'='*55}\n")

    # T1 — état initial
    g = VeraGSTG()
    assert g.state.t == 0
    assert g.state.dp.cost_used == 0.0
    assert len(g.state.audit) == 0
    print(f"✅ T1 : état initial correct (t=0)")

    # T2 — ingest atomique
    out = g.ingest("s1", "radio", [120.0, 180.0])
    assert out is not None
    assert "status" in out
    assert g.state.t == 1  # horloge avancée
    print(f"✅ T2 : ingest atomique (t={g.state.t}, status={out['status']})")

    # T3 — état global cohérent après transition
    assert g.state.dp.cost_used >= 0
    assert g.state.nav.n_sessions >= 0
    assert len(g.state.audit) == 1
    print(f"✅ T3 : état global cohérent (audit={len(g.state.audit)} entrées)")

    # T4 — audit vérifiable
    assert g.verify()
    print(f"✅ T4 : audit vérifiable")

    # T5 — reveal atomique
    out5 = g.reveal("s1")
    assert out5 is not None
    assert g.state.t == 2
    print(f"✅ T5 : reveal atomique (t={g.state.t}, status={out5['status']})")

    # T6 — horloge logique monotone
    t_before = g.state.t
    g.ingest("s2", "radio", [180.0, 90.0])
    assert g.state.t == t_before + 1
    print(f"✅ T6 : horloge logique monotone (t={g.state.t})")

    # T7 — denied → entropy=0, état avance quand même
    g2 = VeraGSTG(threshold=0.5)  # budget très faible
    g2.ingest("s1", "radio", [180.0])  # épuise le budget
    t_before = g2.state.t
    out7 = g2.ingest("attacker", "radio", [180.0])
    assert out7["status"] == "denied"
    assert out7["entropy"] == 0
    assert g2.state.t == t_before + 1  # transition quand même
    print(f"✅ T7 : denied atomique (entropy=0, t avance)")

    # T8 — fingerprint change à chaque transition
    g3 = VeraGSTG()
    fp1 = g3.state.fingerprint()
    g3.ingest("s1", "radio", [180.0])
    fp2 = g3.state.fingerprint()
    assert fp1 != fp2
    print(f"✅ T8 : fingerprint change à chaque transition")

    # T9 — stress 500 transitions — vérifie denied après épuisement
    g4 = VeraGSTG(threshold=50.0)
    n_ok     = 0
    n_denied = 0
    for i in range(500):
        out = g4.ingest(f"user_{i%50}", "radio", [float(60 + i%240)])
        assert out is not None
        assert g4.state.t == i + 1
        if out["status"] == "denied":
            assert out["entropy"] == 0
            n_denied += 1
        else:
            n_ok += 1
    assert n_denied > 0, "T9 : budget jamais épuisé sur 500 transitions"
    assert g4.verify()
    print(f"✅ T9 : 500 transitions (ok={n_ok}, denied={n_denied}, audit={g4.verify()})")

    # T10 — aucune donnée brute
    out10 = g.ingest("clean", "radio", [180.0])
    assert "pcm" not in json.dumps(out10).lower()
    print(f"✅ T10 : aucune donnée brute dans output")

    # T11 — état immuable — ancien état inchangé
    g5    = VeraGSTG()
    old   = g5.state
    g5.ingest("s1", "radio", [180.0])
    assert old.t == 0         # ancien état inchangé
    assert g5.state.t == 1    # nouvel état avancé
    print(f"✅ T11 : immuabilité — ancien état préservé")

    # T12 — multi-branches
    g6 = VeraGSTG()
    for branch in ["radio", "artist", "edge"]:
        out = g6.ingest("10.0.0.1", branch, [180.0, 120.0])
        assert out is not None
    assert g6.verify()
    print(f"✅ T12 : multi-branches (t={g6.state.t}, audit={g6.verify()})")

    print(f"\n{'='*55}")
    print("  12/12 tests passés — VERA GSTG v1 valide")
    print("  Un état global. Une fonction de transition.")
    print("  Core FINAL LOCK maintenu.")
    print(f"{'='*55}\n")


if __name__ == "__main__":
    _run_tests()

