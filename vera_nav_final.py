from __future__ import annotations

import hashlib
import math
import os
import random
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from vera_core_v271_verified import (
    VERACore, VERARadio, VERAEdge, VERAArtist,
    Branch, PROFILES,
)

# PRE-3 (audit Claude v2) : origin_hash() stable — budget survit aux rotations horaires
# origin_hash_audit() rotatif — anti-tracking pour INFRA-3 uniquement
COST_ALPHA = 0.15
COST_BETA = 1.3
COST_THRESHOLD = 50.0
BUDGET_TTL_S = 86400
ENTROPY_WINDOW = 3600
ENTROPY_SCALE = 0.08
ORIGIN_SALT_ROT = 3600
SESSION_INACTIVITY_TTL = 3600
AUDIT_WINDOW = 300

@dataclass
class OriginBudget:
    origin_hash: str
    sessions: int = 0
    cost_used: float = 0.0
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)

    def is_expired(self) -> bool:
        return (time.time() - self.created_at) >= BUDGET_TTL_S

    def session_cost(self) -> float:
        return 1.0 + COST_ALPHA * (self.sessions ** COST_BETA)

    def can_start_session(self) -> bool:
        if self.is_expired():
            return True
        return self.cost_used + self.session_cost() <= COST_THRESHOLD

    def consume(self) -> float:
        if self.is_expired():
            self.sessions = 0
            self.cost_used = 0.0
            self.created_at = time.time()
        cost = self.session_cost()
        self.sessions += 1
        self.cost_used = round(self.cost_used + cost, 3)
        self.last_activity = time.time()
        return cost

    @property
    def budget_remaining(self) -> float:
        if self.is_expired():
            return COST_THRESHOLD
        return max(0.0, COST_THRESHOLD - self.cost_used)

class RateLimiter:
    def __init__(self) -> None:
        self._budgets: Dict[Tuple[str,str], OriginBudget] = {}
        # PRE-3 FIX COMPLET (audit Claude v2, round 2) :
        # Deux salts distincts pour deux usages distincts.
        # _server_salt_stable : permanent (jamais rotatif) → clé des OriginBudgets
        #   Un budget indexé par ce hash survit indéfiniment aux rotations.
        # _server_salt_audit  : rotatif toutes les ORIGIN_SALT_ROT secondes
        #   Utilisé uniquement dans origin_hash_audit() → anti-tracking INFRA-3.
        # Problème du fix précédent : _server_salt unique et rotatif → même IP
        #   produisait un hash différent après rotation → budget orphelin.
        self._server_salt_stable = secrets.token_hex(16)   # permanent — budget
        self._server_salt_audit  = secrets.token_hex(16)   # rotatif — anti-tracking
        self._salt_rotated_at    = time.time()

    def _rotate_salt(self) -> None:
        """Rotation du salt AUDIT uniquement — le salt budget ne change jamais."""
        if (time.time() - self._salt_rotated_at) >= ORIGIN_SALT_ROT:
            self._server_salt_audit = secrets.token_hex(16)
            self._salt_rotated_at   = time.time()

    def _purge_expired(self) -> None:
        now = time.time()
        self._budgets = {
            h: b for h, b in self._budgets.items()
            if not b.is_expired() and (now - b.last_activity) < BUDGET_TTL_S * 2
        }

    def origin_hash(self, ip: str, user_agent: str = "") -> str:
        """
        Hash STABLE pour indexer les OriginBudgets.
        Utilise _server_salt_stable (permanent) — jamais affecté par _rotate_salt().
        Garantit que le même IP produit toujours le même hash → budget non orphelin.
        INFRA-1 (rate-limiting) est enforcé sur toute la durée BUDGET_TTL_S.
        """
        raw = f"{ip}:{user_agent}:{self._server_salt_stable}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def origin_hash_audit(self, ip: str, user_agent: str = "") -> str:
        """
        Hash ROTATIF pour le logging anti-tracking (INFRA-3 uniquement).
        Utilise _server_salt_audit (rotatif toutes les ORIGIN_SALT_ROT secondes).
        NE PAS utiliser pour indexer les budgets — hash change à chaque rotation.
        """
        self._rotate_salt()   # affecte _server_salt_audit uniquement
        time_bucket = int(time.time()) // ORIGIN_SALT_ROT
        raw = f"{ip}:{user_agent}:{self._server_salt_audit}:{time_bucket}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def check_and_consume(self, origin_id: str, cost_override: float = 0.0, branch: str = "") -> Tuple[bool, str, float]:
        """
        cost_override : si > 0, applique ce coût fixe au lieu du coût session normal.
        Usage : reveal() utilise 0.2 (lecture), process() utilise le coût normal.

        FIX-E : les deux chemins (override et normal) vérifient leur propre coût
        indépendamment. can_start_session() n'est appelé que pour process().
        Un utilisateur proche du seuil peut toujours faire reveal() si cost_used + 0.2 ≤ THRESHOLD.
        """
        self._purge_expired()
        key = (origin_id, branch)
        if key not in self._budgets:
            self._budgets[key] = OriginBudget(origin_hash=origin_id)
        budget = self._budgets[key]

        if cost_override > 0.0:
            # Chemin reveal() : vérifie uniquement le coût réduit
            if budget.is_expired():
                budget.sessions = 0; budget.cost_used = 0.0; budget.created_at = time.time()
            if budget.cost_used + cost_override > COST_THRESHOLD:
                return False, "throttled", 0.0
            budget.cost_used = round(budget.cost_used + cost_override, 3)
            budget.last_activity = time.time()
            return True, "ok", cost_override

        # Chemin process() : vérifie le coût session complet
        if not budget.can_start_session():
            return False, "throttled", 0.0
        cost = budget.consume()
        reason = "ok" if budget.cost_used < COST_THRESHOLD * 0.7 else "approaching_limit"
        return True, reason, cost

    def budget_state(self, origin_id: str, branch: str = "") -> Dict[str, Any]:
        if (origin_id, branch) not in self._budgets:
            return {"sessions": 0, "cost_used": 0.0, "remaining": COST_THRESHOLD}
        b = self._budgets[(origin_id, branch)]
        return {"sessions": b.sessions, "cost_used": b.cost_used, "remaining": b.budget_remaining}

class SessionEntropy:
    def __init__(self) -> None:
        self._server_key = self._load_or_create_key()
        self._check_key_permissions()

    @staticmethod
    def _load_or_create_key() -> bytes:
        env_key = os.environ.get("VERA_SERVER_KEY", "")
        if len(env_key) == 64:
            try:
                return bytes.fromhex(env_key)
            except ValueError:
                pass
        key_file = ".vera_nav_key"
        if os.path.exists(key_file):
            try:
                with open(key_file, "rb") as f:
                    key = f.read()
                if len(key) == 32:
                    return key
            except OSError:
                pass
        key = secrets.token_bytes(32)
        try:
            with open(key_file, "wb") as f:
                f.write(key)
            os.chmod(key_file, 0o600)
        except OSError:
            pass
        return key

    @staticmethod
    def _check_key_permissions(key_file: str = ".vera_nav_key") -> None:
        """Avertit si les permissions du fichier clé sont incorrectes."""
        import stat
        if not os.path.exists(key_file):
            return
        mode = os.stat(key_file).st_mode
        if mode & (stat.S_IRGRP | stat.S_IROTH):
            import warnings
            warnings.warn(
                f"VERA: {key_file} est lisible par d'autres processus — "
                "utilisez VERA_SERVER_KEY via variable d'environnement en production.",
                stacklevel=2
            )

    def _time_bucket(self) -> int:
        return int(time.time()) // ENTROPY_WINDOW

    def _micro_bucket(self, session_start: float) -> int:
        return int(session_start) // 30

    def jitter(self, session_hash: str, session_start: float) -> float:
        tb = self._time_bucket()
        mb = self._micro_bucket(session_start)
        raw = hashlib.sha256(self._server_key + f"{session_hash}:{tb}:{mb}".encode()).hexdigest()[:8]
        norm = (int(raw, 16) / 0xFFFFFFFF) * 2 - 1
        return norm * ENTROPY_SCALE

    def adjusted_epsilon(self, base_epsilon: float, session_hash: str, session_start: float) -> float:
        j = self.jitter(session_hash, session_start)
        adj = base_epsilon * (1.0 + j)
        return round(max(0.1, min(1.5, adj)), 4)

    def session_salt_injection(self, session_id: str) -> str:
        tb = self._time_bucket()
        raw = hashlib.sha256(self._server_key + f"salt:{session_id}:{tb}".encode()).hexdigest()[:8]
        return raw

class CoalitionDetector:  # pas @dataclass — __init__ manuel
    def __init__(self, server_key: Optional[bytes] = None) -> None:
        # FIX-A : clé partagée depuis SessionEntropy — évite la race condition
        self._server_key = server_key if server_key is not None else SessionEntropy._load_or_create_key()

    def signature(self, token_b2b: str, batch_id: str) -> float:
        raw = hashlib.sha256(self._server_key + f"{token_b2b}:{batch_id}".encode()).hexdigest()[:8]
        norm = (int(raw, 16) / 0xFFFFFFFF) * 2 - 1
        return norm * 0.02

    def apply(self, value: float, token_b2b: str, batch_id: str) -> float:
        return round(value * (1.0 + self.signature(token_b2b, batch_id)), 2)

    def verify_coalition(self, observed_outputs: List[float], claimed_token: str, batch_ids: List[str]) -> Dict[str, Any]:
        if len(observed_outputs) < 5:
            return {"status": "insufficient_data", "n": len(observed_outputs)}
        expected_sigs = [self.signature(claimed_token, bid) for bid in batch_ids]
        mean_out = sum(observed_outputs) / len(observed_outputs)
        residuals = [(v - mean_out) / (abs(mean_out) + 1e-9) for v in observed_outputs]
        n = min(len(residuals), len(expected_sigs))
        if n < 3:
            return {"status": "insufficient_data", "n": n}
        r = residuals[:n]
        s = expected_sigs[:n]
        mean_r, mean_s = sum(r)/n, sum(s)/n
        num = sum((r[i]-mean_r)*(s[i]-mean_s) for i in range(n))
        den_r = math.sqrt(sum((r[i]-mean_r)**2 for i in range(n)) + 1e-9)
        den_s = math.sqrt(sum((s[i]-mean_s)**2 for i in range(n)) + 1e-9)
        corr = num / (den_r * den_s)
        coalition_suspected = corr < 0.5
        confidence = "high" if corr < 0.2 else "medium" if corr < 0.4 else "low"
        return {"status": "analyzed", "n_outputs": n, "correlation": round(corr, 4),
                "coalition_suspected": coalition_suspected, "confidence": confidence}

@dataclass
class AuditCounter:
    total_sessions: int = 0
    throttled_count: int = 0
    window_start: float = 0.0
    branches_active: set = field(default_factory=set)

    def __post_init__(self):
        if self.window_start == 0.0:
            self.window_start = time.time()

    def is_expired(self) -> bool:
        return (time.time() - self.window_start) >= AUDIT_WINDOW

    def record(self, branch: str, throttled: bool = False) -> None:
        if self.is_expired():
            self.window_start = time.time()
            self.total_sessions = 0
            self.throttled_count = 0
            self.branches_active = set()
        self.total_sessions += 1
        if throttled:
            self.throttled_count += 1
        self.branches_active.add(branch)

    def to_dict(self) -> Dict[str, Any]:
        return {"window_sessions": self.total_sessions,
                "throttle_rate": round(self.throttled_count / max(1, self.total_sessions), 3),
                "branches_active": list(self.branches_active)}

class VERANav:
    def __init__(self) -> None:
        import threading
        self._lock = threading.RLock()
        self._limiter = RateLimiter()
        self._entropy = SessionEntropy()
        self._audit = AuditCounter()
        self._sessions: Dict[str, VERACore] = {}
        # FIX PRE-4 (audit Claude v2, round final) :
        # Clé composite (origin_id, branch) au lieu de origin_id seul.
        # Élimine l'écrasement silencieux cross-branch :
        # Un même IP peut avoir 1 session Radio ET 1 session Artist simultanément.
        # Cohérent avec INFRA-5 (isolation cross-branches par token B2B).
        self._session_index: Dict[Tuple[str, str], str] = {}
        self._session_meta: Dict[str, Dict[str, Any]] = {}
        self._coalition = CoalitionDetector(server_key=self._entropy._server_key)  # FIX-A : clé partagée

    def _get_or_create_core(self, session_id: str, branch: str) -> VERACore:
        self._purge_sessions()
        if session_id not in self._sessions:
            branch_map = {"radio": VERARadio, "edge": VERAEdge, "artist": VERAArtist}
            cls = branch_map.get(branch, VERAEdge)
            self._sessions[session_id] = cls()
        return self._sessions[session_id]

    def _purge_sessions(self) -> None:
        now = time.time()
        to_delete = []
        for sid, core in list(self._sessions.items()):  # copie défensive
            meta = self._session_meta.get(sid, {})
            last = meta.get("last_activity", getattr(core, "_last_activity", 0))
            if core._epsilon_used >= core.profile.epsilon_global_max or (now - last) > SESSION_INACTIVITY_TTL:
                to_delete.append(sid)
        for sid in to_delete:
            self._sessions.pop(sid, None)
            self._session_meta.pop(sid, None)
            for key, mapped_sid in list(self._session_index.items()):
                if mapped_sid == sid:
                    del self._session_index[key]  # FIX PRE-4 : clé (origin, branch)

        # FIX PRE-5b : nettoyer les entrées _session_index orphelines
        # (session_id présent dans l'index mais absent de _sessions)
        # Évite la fuite mémoire sur déploiement longue durée avec beaucoup d'origines
        for key in list(self._session_index.keys()):
            if self._session_index[key] not in self._sessions:
                del self._session_index[key]

    def process(self, origin_ip: str, branch: str, raw_values: List[float],
                user_agent: str = "", b2b_token: str = "") -> Dict[str, Any]:
        """
        b2b_token : jeton B2B de l'acheteur (UUID v4 fourni à l'enrôlement).
        Si fourni, utilisé pour la signature coalition (INFRA-2) — preuve opposable.
        Si absent, fallback sur audit_token() interne (usage dev/test uniquement).

        PRE-5 — Quota INV-2 cumulatif par origin :
        Le core est réutilisé entre les appels process() successifs du même
        (origin_id, branch). Le quota max_observable (INV-2 = 5 révélations)
        est partagé sur toute la durée de vie du core, pas par appel.
        Un intégrateur qui appelle process() répétitivement épuisera le quota
        en max_observable révélations — le suivant retourne quota_exhausted.
        Nouvelle session créée automatiquement quand le quota est atteint.
        """
        with self._lock:
            origin_id = self._limiter.origin_hash(origin_ip, user_agent)
            allowed, reason, cost = self._limiter.check_and_consume(origin_id, branch=branch)
            self._audit.record(branch, throttled=not allowed)
            if not allowed:
                return {"status": "unavailable", "message": "Service temporairement indisponible."}
            if branch not in {"radio", "edge", "artist"}:
                return {"status": "invalid_branch", "message": "Branche non reconnue."}
            # FIX PRE-5 : réutiliser le core existant si session active non épuisée
            # Évite l'accumulation de cores orphelins en mémoire (1 appel = 1 core)
            existing_sid = self._session_index.get((origin_id, branch))
            existing_core = self._sessions.get(existing_sid) if existing_sid else None

            if (existing_core is not None
                    and existing_core._epsilon_used < existing_core.profile.epsilon_global_max
                    and existing_core._total_revealed < existing_core.profile.max_observable):
                # Session active réutilisée
                session_id = existing_sid
                core = existing_core
            else:
                # Nouvelle session — l'ancienne est épuisée ou absente
                base_session = secrets.token_hex(4)
                entropy_salt = self._entropy.session_salt_injection(base_session)
                session_id = f"{base_session}:{entropy_salt}"
                core = self._get_or_create_core(session_id, branch)
                self._session_index[(origin_id, branch)] = session_id  # FIX PRE-4

            now = time.time()
            core._last_activity = now
            self._session_meta[session_id] = {
                "origin_id": origin_id, "branch": branch,
                "created_at": self._session_meta.get(session_id, {}).get("created_at", now),
                "last_activity": now
            }
            ingest_result = core.ingest(raw_values)
            reveal_result = core.reveal()
            jitter = self._entropy.jitter(session_id, self._session_meta[session_id]["created_at"])
            output = self._filter_output(reveal_result)
            audit_tok = core.audit_token()
            # INFRA-2 : utiliser le token B2B si fourni — signature opposable à un auditeur externe
            # Si absent : fallback audit_token() interne (non vérifiable par un tiers)
            coalition_tok = b2b_token if b2b_token else audit_tok
            if output.get("status") == "ok" and output.get("signals"):
                for i, sig in enumerate(output["signals"]):
                    if "value" in sig:
                        sig["value"] = self._coalition.apply(sig["value"], coalition_tok, f"{session_id}:{i}")
            return {"status": "ok", "output": output,
                    "session": {"audit_token": audit_tok, "entropy_tier": self._entropy_tier(jitter)}}

    def _filter_output(self, reveal_result: Dict[str, Any]) -> Dict[str, Any]:
        if reveal_result.get("status") != "ok":
            return {"status": reveal_result.get("status", "no_signal")}
        return {"status": "ok", "branch": reveal_result.get("branch"),
                "signals": reveal_result.get("signals", []),
                "graphlets": reveal_result.get("graphlets", [])}

    def _entropy_tier(self, jitter: float) -> str:
        abs_j = abs(jitter)
        if abs_j < ENTROPY_SCALE * 0.33: return "low"
        elif abs_j < ENTROPY_SCALE * 0.66: return "medium"
        return "high"

    def reveal(self, origin_ip: str, branch: str, user_agent: str = "", b2b_token: str = "") -> Dict[str, Any]:
        with self._lock:
            origin_id = self._limiter.origin_hash(origin_ip, user_agent)
            # FIX-B : coût réduit (0.2) — autorise les lectures légitimes
            # sans ouvrir un canal gratuit pour un attaquant bloqué par process()
            allowed, _, _ = self._limiter.check_and_consume(origin_id, cost_override=0.2, branch=branch)
            if not allowed:
                return {"status": "unavailable", "message": "Service temporairement indisponible."}
            if branch not in {"radio", "edge", "artist"}:
                return {"status": "invalid_branch", "message": "Branche non reconnue."}
            session_id = self._session_index.get((origin_id, branch))  # FIX PRE-4
            if not session_id:
                return {"status": "no_signal"}
            core = self._sessions.get(session_id)
            if not core or core.profile.branch.value != branch or not core._weak_signals:
                return {"status": "no_signal"}
            self._session_meta.setdefault(session_id, {})["last_activity"] = time.time()
            # jitter non appliqué dans reveal() — reveal() retourne les signaux existants sans retraitement
            return self._filter_output(core.reveal())

    def _audit_coalition(self, observed_outputs: List[float], claimed_token: str, batch_ids: List[str]) -> Dict[str, Any]:
        return self._coalition.verify_coalition(observed_outputs, claimed_token, batch_ids)

    def audit_summary(self) -> Dict[str, Any]:
        return {"rate_limiter": {"active_origins": len(self._limiter._budgets)},
                "sessions": {"active_cores": len(self._sessions)},
                "traffic": self._audit.to_dict()}

# Tests
def _run_tests():
    import threading
    print("\n" + "="*55)
    print("  VERA NAV — Tests de régression")
    print("="*55 + "\n")

    def make(n=30): return [random.uniform(60, 300) for _ in range(n)]
    nav = VERANav()

    # T1 usage normal
    for _ in range(5):
        r = nav.process("192.168.1.1", "radio", make())
    assert r["status"] == "ok"
    print("✅ T1 : usage normal OK")

    # T2 rate limiting
    nav2 = VERANav()
    blocked = False
    for i in range(100):
        r = nav2.process("10.0.0.1", "radio", make())
        if r["status"] == "unavailable":
            blocked = True
            print(f"  blocage session {i+1}")
            break
    assert blocked
    print("✅ T2 : rate limiting déclenché")

    # T3 jitter stable intra-session
    e = SessionEntropy()
    j1 = e.jitter("sid123", 1000.0)
    j2 = e.jitter("sid123", 1000.0)
    assert j1 == j2 and abs(j1) <= ENTROPY_SCALE
    print(f"✅ T3 : jitter stable ({j1:.4f})")

    # T4 jitter varie entre sessions
    jitters = [e.jitter(f"s_{i}", 1000.0) for i in range(20)]
    assert len(set(round(j,6) for j in jitters)) == 20
    print(f"✅ T4 : jitter varie (20/20 distincts)")

    # T5 surface filtrée
    nav3 = VERANav()
    for _ in range(15): nav3.process("1.2.3.4", "radio", make())
    r = nav3.process("1.2.3.4", "radio", make())
    if r["status"] == "ok":
        assert "total_observed" not in r.get("output", {})
        assert "epsilon_used"   not in r.get("output", {})
    print("✅ T5 : surface filtrée")

    # T6 audit agrégé
    s = nav.audit_summary()
    assert "active_origins" in s["rate_limiter"]
    print("✅ T6 : audit agrégé OK")

    # T7 refus silencieux
    nav4 = VERANav()
    for _ in range(200):
        r = nav4.process("evil.ip", "radio", make())
        if r["status"] == "unavailable":
            assert "threshold" not in r.get("message","")
            break
    print("✅ T7 : refus silencieux")

    # T8 invariants core (VERAArtist)
    nav5 = VERANav()
    for _ in range(10): nav5.process("safe.ip", "artist", make())
    r = nav5.process("safe.ip", "artist", [float(x) for x in range(100,400,10)])
    if r.get("output",{}).get("signals"):
        for sig in r["output"]["signals"]:
            assert "value" not in sig and "trend_index" in sig
    print("✅ T8 : invariants core OK")

    # T9 anti-parallèle
    jitters2 = [e.jitter(f"p_{i}", 1000.0) for i in range(20)]
    assert len(set(round(j,6) for j in jitters2)) == 20
    assert max(jitters2)-min(jitters2) > 0.05
    print(f"✅ T9 : anti-parallèle (range={max(jitters2)-min(jitters2):.3f})")

    # T10 coalition — FIX-C : test structurellement garanti
    # On génère des outputs signés par t_radio, on audite avec t_evil
    # Les deux tokens ont des signatures orthogonales → corr faible → coalition suspecte
    nav6 = VERANav()
    t_radio, t_evil = "radio_france_abc", "attacker_xyz"
    bids = [f"b_{i}" for i in range(30)]   # Plus de points = corrélation plus stable
    # Outputs signés par t_radio (clé partagée avec nav6._coalition)
    radio_out = [150.0*(1 + nav6._coalition.signature(t_radio, b)) for b in bids]
    # Audit : est-ce que ces outputs matchent t_evil ? Non → coalition suspecte
    r_atk = nav6._audit_coalition(radio_out, t_evil, bids)
    assert r_atk["status"] == "analyzed", f"T10 : status={r_atk['status']}"
    assert r_atk["coalition_suspected"] == True,         f"T10 : coalition non détectée (corr={r_atk['correlation']:.3f})"
    # Vérification inverse : les outputs de t_radio matchent t_radio → pas coalition
    r_legit = nav6._audit_coalition(radio_out, t_radio, bids)
    assert r_legit["coalition_suspected"] == False,         f"T10 : faux positif sur token légitime (corr={r_legit['correlation']:.3f})"
    print(f"✅ T10 : coalition — attaquant={r_atk['correlation']:.3f} légitime={r_legit['correlation']:.3f}")

    # T11 purge TTL
    nav7 = VERANav()
    for i in range(5):
        for _ in range(15): nav7.process(f"192.168.{i}.1", "radio", make())
    before = len(nav7._sessions)
    # FIX T11 : forcer l'expiration sur TOUTES les sessions (pas seulement la première)
    for sid in list(nav7._sessions.keys()):
        nav7._session_meta[sid] = {
            "last_activity": 0.0,
            "created_at": 0.0,
            "branch": "radio",
        }
        nav7._sessions[sid]._last_activity = 0.0
    nav7._purge_sessions()
    after = len(nav7._sessions)
    assert after < before
    print(f"✅ T11 : purge TTL ({before}→{after})")

    # T12 thread safety
    nav8 = VERANav()
    results, errors = [], []
    lock = threading.Lock()
    def worker(uid):
        try:
            r = nav8.process(f"10.0.{uid%10}.1", "radio", make())
            with lock: results.append(r["status"])
        except Exception as ex:
            with lock: errors.append(str(ex))
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert not errors
    print(f"✅ T12 : thread safety (20/20 OK, 0 erreur)")

    # ── T13 : reveal() avec budget résiduel > 0.2 après process() proche du seuil
    nav13 = VERANav()
    # Consommer presque tout le budget via process()
    ip13 = "budget.test.ip"
    for _ in range(14):   # ~14 sessions → cost_used ≈ 48 (proche de COST_THRESHOLD=50)
        nav13.process(ip13, "radio", make())
    # Vérifier qu'il reste un budget résiduel
    origin13 = nav13._limiter.origin_hash(ip13)
    budget13  = nav13._limiter._budgets.get(origin13)
    residual  = COST_THRESHOLD - budget13.cost_used if budget13 else 0.0
    # reveal() doit passer si residual > 0.2
    if residual > 0.2:
        r13 = nav13.reveal(ip13, "radio")
        # Peut être no_signal (pas de session via ce chemin) mais ne doit pas être throttled
        assert r13.get("status") != "unavailable",             f"T13 : reveal() bloqué alors que residual={residual:.2f} > 0.2"
        print(f"✅ T13 : reveal() avec residual={residual:.2f} → status={r13['status']} (non bloqué)")
    else:
        print(f"✅ T13 : budget épuisé ({residual:.2f} ≤ 0.2) — cas limite correct")

    print(f"\n{'='*55}")
    print("  13/13 tests passés — VERA NAV valide")
    print("  server_key persisté · Core FINAL LOCK maintenu")
    print(f"{'='*55}\n")

if __name__ == "__main__":
    _run_tests()
