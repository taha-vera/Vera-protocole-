# VERA DP Formal Specification v1.0
**Status : DRAFT — post-pilote Radio France**
**Date : Mai 2026**
**Auteur : VERA Protocol — tahahouari@hotmail.fr**

## 1. Unité de privacy
Unité = session (hash temporaire, TTL <= 7 jours)
- Cohérent avec INV-6
- Évite le cross-session leakage
- Implémentable sans casser v2.7.1

D = {s_1, s_2, ..., s_n} — chaque s_i = une session
D' = D \ {s_i} — VERA protège présence/absence d'une session

## 2. Fonction mesurée
f(D) = médiane({raw_values}) dans [0, 86400]

## 3. Sensibilité (Δf)
Borne conservative : Δf <= 86400
Borne pratique (à valider) : Δf <= 300
Action post-pilote : mesurer Δf réel sur données Radio France

## 4. Mécanisme Laplace
M(D) = f(D) + Laplace(Δf / ε)
ε global cible = 1.0
noise_base=35.0 actuel = borne empirique non calibrée — post-pilote

## 5. Privacy Budget
budget = 1.0 par session
cost_per_reveal = 0.2
max_reveals = 5 = INV-2
epsilon_global_max=50 actuel à recalibrer sur ε=1.0 post-pilote

## 6. Composition cross-branches
ε_total = ε_Radio + ε_Artist + ε_Edge <= 1.0
Implémentation : VERABudgetManager (PENDING_v3 P8)
Prérequis : token B2B obligatoire (PENDING_v3 P7)

## 7. Ce que v2.7.1 satisfait déjà
- Destruction données brutes : OK INV-7
- Bruit Laplace présent : OK _laplace()
- Budget fini par session : OK INV-4
- K-anonymity partiel : OK INV-2
- Composition cross-branches : NON — post-pilote
- Sensibilité Δf calibrée : NON — post-pilote
- ε global formel : NON — post-pilote

## 8. Roadmap
- Mesurer Δf réel : post-pilote RF
- Calibrer scale=Δf/ε : post-pilote RF
- VERABudgetManager : post-pilote RF
- Preprint arXiv : post-pilote RF
- PETS 2027 : 2027

## 9. Claim défendable aujourd'hui
VERA v2.7.1 implémente une differential privacy empirique avec ε
non calibré formellement. Non-reconstructibilité mesurée à >=3.25%
sur N=2000 simulations. Calibration formelle documentée dans
PENDING_v3 — réalisée post-pilote Radio France.
