# VERA — Décisions architecturales documentées

Ce fichier documente les choix délibérés qui ont été questionnés lors des audits
externes et les raisons pour lesquelles ils ont été maintenus.

---

## DEC-1 : INV-2 protège les révélations, pas le volume ingesté

**Question :** Un attaquant peut accumuler via `ingest()` sans limite de session,
puis faire un seul `reveal()` pour obtenir `max_observable=5` signaux issus
de nombreuses fusions.

**Décision :** INV-2 protège le **nombre de révélations par session**, non le
volume ingesté. C'est intentionnel — la valeur informationnelle est dans la
révélation, pas dans l'accumulation.

Un attaquant qui accumule 1000 valeurs via `ingest()` obtient toujours
exactement 5 signaux faibles au maximum via `reveal()` — chacun bruité,
pondéré et dégradé selon INV-3/INV-6.

**Défense complémentaire :** INFRA-1 (rate-limiting, coût super-linéaire)
limite le nombre de sessions par origine économique. L'accumulation massive
est économiquement dissuasive via le NAV, pas via le core.

**Référence :** PRE-1, INFRA-1, `vera_nav_final.py`

---

## DEC-2 : `random` standard pour le bruit Laplace (pas `secrets` ni `numpy`)

**Question :** `random` sans seed fixe dans un contexte multi-thread peut
être influencé par un attaquant contrôlant le timing.

**Décision :** Maintenu pour trois raisons :
1. `random` Python est thread-safe sous **CPython** (le GIL protège l'état interne).
   Hypothèse : CPython uniquement — sur PyPy ou toute implémentation sans GIL,
   cette garantie ne tient pas. VERA cible Termux/Edge où CPython est standard.
2. En differential privacy, le bruit DP ≠ bruit cryptographique —
   `secrets` serait un overhead injustifié sans gain DP réel
3. `numpy` est une dépendance externe — VERA est conçu sans dépendance
   pour le déploiement Termux/Edge

**Contexte :** Un attaquant qui contrôle le timing au niveau du scheduler OS
a déjà un niveau d'accès qui compromet l'ensemble du système, pas seulement
le bruit Laplace.

---

## DEC-3 : Chaîne de dérivation `audit_token` depuis `session_id`

**Question :** Si `session_id` fuite par un canal externe, `audit_token` est
compromis.

**Décision :** Acceptable dans le contexte B2B avec token isolé. Si `session_id`
fuite, c'est une compromission système complète — le durcissement de la
dérivation ne changerait pas le niveau de risque global.

**Contexte :** `audit_token` est utilisé uniquement pour la corrélation
intra-session côté auditeur. Il n'est pas exposé aux utilisateurs finaux.

---

## DEC-4 : Coupling amplitude réelle ±0.25 (pas ±5)

**Constat :** `bias ∈ [0.88, 0.95]` → `(bias - 0.9) ∈ [-0.02, 0.05]`
→ coupling réel ∈ [-0.25, +0.25].

**Clarification :** L'effet visé est la **non-séparabilité analytique**
bias/nonlinear, pas l'amplitude. Même faible, le coupling force un modèle
joint — c'est l'invariant structurel qui compte.

L'effet est marginal par rapport au bruit Laplace dominant (scale=35 pour la branche
radio) — le coupling ±0.25 est statistiquement quasi-invisible à cette échelle.
Il introduit néanmoins une dépendance structurelle non nulle entre les composantes
bias et nonlinear, rendant la séparation analytique formellement incorrecte.
**Documenté pour transparence, pas comme défense principale.**

La documentation du code a été mise à jour pour refléter l'amplitude réelle.

---

## DEC-5 : TEST25 comme mesure partielle

**Constat :** TEST25 mesure N=500 sessions (un point). Le plateau ~3.25%
est documenté sur N=5→2000 dans le header mais pas vérifié par ce test.

**Décision :** TEST25 valide le mécanisme de convergence. La courbe complète
est disponible via `vera_benchmark.py` (4 graphes, N=5→250, 1000 sims/point).


---

## DEC-7 : Quota INV-2 cumulatif par origin (PRE-5)

**Constat (audit Claude externe) :** Avec PRE-5, `process()` réutilise le core
existant pour un `(origin_id, branch)` donné. Le quota `max_observable=5`
(INV-2) s'applique cumulativement sur tous les appels successifs du même origin,
pas par appel individuel.

**Implication pour l'intégrateur :** Un client qui appelle `process()` 6 fois
sur la même branche verra le 6e retourner `quota_exhausted`. Une nouvelle session
est créée automatiquement — le quota repart à zéro.

**Documenté dans le docstring de `process()`.**

---

## DEC-6 : verify_coalition() détecte "mauvais token", pas "coalition" au sens strict

**Constat (audit Claude externe) :** Une corrélation faible (corr < 0.5) entre
résidus observés et signatures attendues signifie "mauvais token réclamé",
pas nécessairement "coalition active". Un token simplement invalide donnerait
le même résultat.

**Décision :** La détection est conservative — elle signale toute incohérence
entre token et outputs. C'est une détection d'anomalie, pas une preuve de
coalition au sens cryptographique strict.

Pour une preuve de coalition réelle, il faudrait comparer les signatures
de plusieurs tokens entre eux — hors scope du core NAV, délégué à l'audit
INFRA-3 (logging 30j).

**Usage correct :** `coalition_suspected = True` = "ces outputs ne correspondent
pas au token déclaré — investigation requise", pas "coalition prouvée".

