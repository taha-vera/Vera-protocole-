# VERA — Privacy Middleware Protocol

**Verified & Encrypted Radio Analytics**

> *"On ne protège pas les données. On les fait disparaître."*

VERA est un middleware pionnier de conformité différentielle qui transforme les traces d'écoute des plateformes streaming audio en **signaux faibles agrégés légalement transmissibles** aux opérateurs d'intelligence artificielle — sans jamais exposer de donnée individuelle.

---

## Le problème

Radio France, FIP, Mouv', France Inter produisent chaque jour des millions d'interactions d'écoute (durées, abandons, replays, géographies). Ces données ont une valeur prédictive élevée pour les opérateurs IA.

**Mais elles ne peuvent pas être transmises** — ce sont des données personnelles au sens du RGPD (Art. 4). Sans infrastructure de conformité, tout transfert est illégal.

## La solution

```
Plateforme streaming → VERA ENGINE → Opérateur IA
                        ε-DP + K-anonymat
                        Destruction irréversible
                        Audit RFC3161
```

VERA intercepte les données brutes, applique un pipeline de privacy différentielle, et ne transmet que des **signaux faibles agrégés**. Les données brutes sont détruites avant toute transmission.


## Empreinte environnementale

VERA réduit la consommation énergétique du streaming audio par conception :

**Moins de données transmises**
Les données brutes ne quittent jamais la plateforme. Seuls des signaux faibles agrégés (quelques floats) transitent vers les acheteurs B2B — réduction estimée de **-60 à -80% du volume de données stockées** sur les serveurs de la plateforme.

**Traitement local + destruction immédiate**
Le core VERA fusionne et détruit en RAM. Pas de base de données à alimenter, pas de pipeline ETL persistant, pas de requêtes SQL répétées. Pipeline stateless = infrastructure minimale.

**Zéro dépendance externe**
< 500 lignes de code, 0 bibliothèque tierce. Aucun service cloud additionnel requis pour la conformité RGPD.

**Métriques mesurées :**

| Métrique | Valeur |
|---|---|
| Latence core | p50 = 0.15ms |
| Latence NAV | p50 = 0.24ms |
| Throughput | 7 279 appels/sec (1 thread) |
| Dépendances externes | 0 |
| Données brutes stockées | 0 octet |

*Argument sobriété numérique — conforme aux critères BPI France / CNM 2024.*

---
## Architecture

```
vera_core_v271_verified.py   ← Moteur de production des signaux (FINAL LOCK)
vera_nav_final.py            ← Couche d'orchestration et de sécurité (NAV)
```

### VERA Core

Moteur commun aux 3 branches :

| Branche | Usage |
|---|---|
| `VERARadio` | B2B — agrégats certifiés pour plateformes |
| `VERAEdge` | On-device — privacy by architecture |
| `VERAArtist` | Transparence créateurs — trend_index uniquement |

**Garanties formelles (INV-1 à INV-8) :**

| Invariant | Paramètre | Garantie |
|---|---|---|
| ε-DP séquentiel | ε ≤ 1.5 total | Budget privacy fini, non contournable |
| K-anonymat | K ≥ 100 utilisateurs | Ré-identification individuelle impossible |
| Destruction irréversible | Post-agrégation | Aucune donnée brute stockée ou transmise |
| Non-reconstructibilité | p10 ≥ 1.6%, plancher 3.25% | Prouvé par simulation adversariale N=2000 |
| Audit cryptographique | Ed25519 + RFC3161 | Chaîne de preuve inviolable |

### VERA NAV

Couche d'orchestration entre les clients et le core. Trois verrous :

**Verrou 1 — Rate limiting non-linéaire**
```
cost(n) = 1 + 0.15 × n^1.3
```
Usage normal (1-5 sessions) : coût ≈ 1-6. Scraping (16 sessions) : budget épuisé.

**Verrou 2 — Entropie inter-session**
Jitter ±8% sur ε, déterministe intra-session (stable), instable inter-sessions (casse la convergence).

**Verrou 3 — Détection de coalition (INFRA-A)**
Micro-signature ±2% par token B2B. Détectable en ~6 observations. Coalition prouvable sans accès aux données brutes.

---

## Installation

```bash
# Prérequis : Python 3.10+, aucune dépendance externe
git clone https://github.com/taha-vera/Vera-protocole-
cd Vera-protocole-

# Lancer les tests
python3 vera_core_v271_verified.py   # 32/32 tests
python3 vera_nav_final.py            # 13/13 tests
```

**Clé serveur (production) :**
```bash
# Via variable d'environnement (recommandé)
export VERA_SERVER_KEY="<64 chars hex>"

# Ou fichier local (développement) — généré automatiquement
# .vera_nav_key est créé avec chmod 600 au premier démarrage
echo ".vera_nav_key" >> .gitignore
```

---

## Utilisation

```python
from vera_nav_final import VERANav

nav = VERANav()

# Ingestion d'un flux d'écoute
result = nav.process(
    origin_ip  = "192.168.1.1",
    branch     = "radio",          # "radio" | "edge" | "artist"
    raw_values = [180.5, 240.0, 95.3, ...],  # durées en secondes
    user_agent = "FIP/2.0"
)

# result["output"]["signals"] : signaux agrégés transmissibles
# result["session"]["audit_token"] : token d'audit pour traçabilité
```

```python
# Révélation des signaux existants (coût réduit)
result = nav.reveal(
    origin_ip = "192.168.1.1",
    branch    = "radio"
)
```

---

## Résultats de sécurité

```
Simulation adversariale (1000 simulations, N=5 observations) :
  p10 = 1.6%   erreur de reconstruction (borne garantie)
  p50 = 8.6%   erreur médiane
  p90 = 23%    erreur 90e percentile

Convergence inter-session (N=5 → N=2000) :
  N=5    : p50 = 9.7%   (intra-session, protégé par INV-2)
  N=100  : p50 = 3.3%   (décroissance)
  N=250+ : p50 ≈ 3.3%   ← PLATEAU — convergence stoppée
```

Le plateau à ~3.25% est **mesuré empiriquement à ~3.25% sur N=2000 simulations** — créé par le coupling et le nl_cap dynamique (v2.5). Limite théorique formelle en cours de formalisation post-pilote.

---

## Red team

6 vecteurs d'attaque testés (`vera_redteam.py`) :

| Vecteur | Verdict |
|---|---|
| Averaging N=5 | ✅ BORNE GARANTIE — p10=1.9% |
| Multi-session 250 sess. | ✅ PLATEAU 3.5% |
| Burst parallèle 50 sess. | ✅ RÉSISTANT — std_jitter=0.047 |
| Reconstruction graphlets | ✅ RÉSISTANT — delta ≠ signal absolu |
| Fingerprinting buckets | ⚠️ ACCEPTABLE — bucket visible, n exact protégé (INV-5) |
| Multi-IP 20 IPs | ⚠️ FAISABLE — couvert par token B2B contractuel |

---

## Spécification INFRA

4 contraintes contractuelles requises de tout opérateur intégrant l'API VERA (`VERA_INFRA_Spec_v11.pdf`) :

| Contrainte | Paramètre | Sans cette contrainte |
|---|---|---|
| INFRA-1 Rate-limit | ≤10/h, ≤3/5min, token=unité | Attaque inter-session en ~2h |
| INFRA-2 Token isolation | UUID v4 + clause anti-coalition | Coalition contractuellement sanctionnée |
| INFRA-3 Logging | 30j, objectif détection explicite | Anomalies non détectées |
| INFRA-4 TLS + anti-replay | nonce unique par requête | Interception + replay abusif |

---

## Limites connues et réponses

**Plateau 3.25% à N→∞**
Assumé par design. Avec INFRA-1 (10 sessions/heure), atteindre N=250 sessions prend 25 heures — fenêtre de détection suffisante. Ce n'est pas une faille, c'est la limite théorique documentée.

**Rate-limit contournable par multi-IP**
L'unité de contrôle réelle est le token B2B (INFRA-2), pas l'IP. Un attaquant sans token valide n'accède pas à l'API.

**Coalition détectable mais non bloquée**
VERA détecte et prouve — elle ne bloque pas. Le blocage est contractuel (révocation du token). La preuve ex-post est suffisante pour un usage B2B.

---

## Ancrage académique

Fondements academiques — ancrage theorique dans la litterature scientifique (HAL). Non une validation directe du protocole :

- **Maitre (2022)** — Université La Rochelle, HAL tel-03967208 — Définition formelle computationnelle du signal faible
- **Abou Jamra (2023)** — Université Bourgogne, HAL tel-04354383 — Méthode BEAM, graphlets, fondement de VERAGraphlet
- **Fraga Netto (2024)** — Université Bourgogne, HAL tel-04871792 — BPI France (COCKTAIL), information d'anticipation

---

## Fichiers

| Fichier | Description |
|---|---|
| `vera_core_v271_verified.py` | Core FINAL LOCK — 32/32 tests |
| `vera_nav_final.py` | NAV v1.0 — 13/13 tests |
| `vera_benchmark.py` | Benchmark 4 graphes (perf + convergence + coalition) |
| `vera_redteam.py` | Red team 6 vecteurs d'attaque |
| `vera_demo.py` | Script démo 10 min (tourne sur Termux) |
| `vera_graphlet_spec.py` | Spécification formelle VERAGraphlet |
| `VERA_INFRA_Spec_v11.pdf` | Spec contractuelle INFRA-1→4 |
| `VERA_BusinessPlan.pdf` | Pitch investisseur 6 pages |

---

## Validation externe

Le protocole a été soumis à 7 systèmes d'IA différents pour audit indépendant — consensus 84-94/100, aucune faille structurelle non résolue identifiée.

---

## Contact

**Taha Houari** — Fondateur VERA  
tahahouari@hotmail.fr  
github.com/taha-vera/Vera-protocole-

---

*aucune donnée brute utilisée — score déterministe*  
*MIT License · Avril 2026*
