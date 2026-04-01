# VERA — Privacy-First Music Streaming Protocol

> Écoute sans pub. Artistes rémunérés par la vente de signaux faibles agrégés aux opérateurs IA.

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Privacy](https://img.shields.io/badge/privacy-ε%3D0.3-blue)](genesis_proof.json)
[![STOP](https://img.shields.io/badge/STOP-reached-brightgreen)](genesis_proof.json)
[![Audit](https://img.shields.io/badge/audit-S2--ready-purple)](genesis_proof.json)

---

## Table des matières

1. [Qu'est-ce que VERA ?](#quest-ce-que-vera-)
2. [Le modèle économique](#le-modèle-économique)
3. [Architecture technique](#architecture-technique)
4. [Privacy différentielle](#privacy-différentielle)
5. [Audit sans données](#audit-sans-données)
6. [Vérification indépendante](#vérification-indépendante)
7. [Conformité](#conformité)
8. [Démarrage rapide](#démarrage-rapide)
9. [Contact](#contact)

---

## Qu'est-ce que VERA ?

**Gratuit pour tout le monde.** Zéro pub. Zéro abonnement.

| Partie | Ce que VERA apporte |
|--------|---------------------|
| Auditeurs | Streaming gratuit · sans pub · sans abonnement · qualité Opus 128kbps |
| Artistes | +30 % vs Spotify · paiement J+3 · transparence totale |
| Opérateurs IA | Signaux d'écoute propres · structurés · conformes RGPD · prêts à l'emploi |

VERA est l'intermédiaire entre les auditeurs consentants et les acheteurs de données IA.
Aucune publicité, aucun abonnement : la donnée agrégée et anonymisée finance la musique.

---

## Le modèle économique

```
Auditeur écoute → consentement explicite → signal agrégé DP
→ vendu aux opérateurs IA → revenus → artistes rémunérés
```

**Ratio clé :**

| Composant | Coût / Revenu | Détail |
|-----------|--------------|--------|
| Coût diffusion | ~0,001 €/heure | Cloudflare R2 + CDN · Opus 128kbps |
| Signal IA vendu | >0,01 €/heure | Marge ×10 |
| Rémunération artiste | 0,0052 €/stream | +30 % vs Spotify (0,0031 €) |

Seuil de rentabilité estimé : **2 millions d'heures d'écoute mensuelles.**

---

## Architecture technique

### Codec
**Opus 128 kbps** — qualité perçue supérieure au MP3 256 kbps, données divisées par 2.

### Diffusion (Edge)
- **Cloudflare R2 + CDN** — egress fees quasi-nuls
- **P2P WebRTC hybride** (phase scale) — coût bande passante ÷4

### Pipeline DP
- Privacy différentielle ε = 0,3
- Données brutes détruites sous 48h
- Seuls les agrégats sortent — zéro donnée personnelle exposée

---

## Privacy différentielle

8 invariants enforcés · 52 tests automatisés

| # | Invariant | Valeur | Description |
|---|-----------|--------|-------------|
| INV-1 | ε ∈ [0,1 ; 1,5] | 0,3 (défaut) | Niveau de bruit minimal/maximal |
| INV-2 | K ≥ 100 | Cohorte minimale | Agrégation uniquement au-delà du seuil |
| INV-3 | wK = 0,3 fixe | Poids Privacy Score | Équilibre ε / taille cohorte |
| INV-4 | Kill-switch | Arrêt automatique | Arrêt d'urgence si ε dérive |
| INV-5 | Destruction irréversible | 48h max | Données brutes purgées |
| INV-6 | Consentement requis | Opt-in obligatoire | Pas de collecte sans accord explicite |
| INV-7 | Zéro brute en sortie | raw_events = null | Aucune donnée individuelle dans l'export |
| INV-8 | Randomized Response | Laplace(ε) | Bruit calibré appliqué |

Preuve de destruction : des logs de purge signés sont annexés au registre d'audit (chaîne append-only).

---

## Audit sans données

Un auditeur indépendant (CNIL, BPI France, tiers) peut vérifier l'intégrité complète du système **sans jamais accéder à une seule donnée brute**.

```
[Agrégat DP]
    ↓ hash SHA-256
[AuditEntry chaînée]
    ↓ append-only
[ImmutableLog]
    ↓ export JSON signé Ed25519
[Snapshot]
    ↓ ancrage RFC3161
[Auditeur indépendant]
    → vérifie sans VERA, sans données, sans clé secrète
```

### Preuve d'arrêt (STOP)

Le fichier [`genesis_proof.json`](genesis_proof.json) contient :

- La clé publique Ed25519 du système
- Son empreinte (fingerprint)
- Un ancrage RFC3161 signé par FreeTSA
- Le hash de l'état initial du registre

Cet ancrage constitue une **preuve d'antériorité indépendante**, vérifiable pour toujours, même en l'absence du système original.

```json
{
  "public_key": "EQxh/IsfwcHrmdLfvPe7v28+S1ecO67fkHVUC30ft5M=",
  "fingerprint": "5b740cd64b3c48eb911122783ed1c12751139e5652a161e59e7ac257c77c670c",
  "anchored_at": "2026-03-31T21:01:11.766654+00:00",
  "anchor_hash": "13a7d636c137f8366ce0cdd70b2245b7d4d2fc39340e608ecf8b403ab596d25e",
  "tsa": "FreeTSA",
  "stop_reached": true
}
```

### S2 — Deux niveaux de validité

Le système distingue explicitement :

- `valid_internal` : intégrité locale vérifiable sans réseau (signatures, chaîne de hachages, invariants DP)
- `valid_stop` : preuve d'antériorité externe via ancrage RFC3161

Ces deux propriétés ne sont jamais confondues dans les rapports d'audit.

---

## Vérification indépendante

### Prérequis

```bash
pip install cryptography
```

### Vérification complète

```bash
python3 vera_audit_core.py --verify genesis_proof.json
```

Cela retourne un rapport JSON avec :

- `valid_internal` : état de l'intégrité locale
- `valid_stop` : présence et validité de l'ancrage externe
- Détail des 8 invariants
- Liste des témoins (checkpoints)
- Warnings éventuels (ex. obfuscation only)

### Vérification du token RFC3161

Pour valider complètement la chaîne de confiance du TSA :

```bash
openssl ts -verify -in token.tsr -data anchor_hash.bin -CAfile freetsa-root.pem
```

### Publication de la clé publique

L'empreinte de la clé publique est disponible via :

- Dépôt GitHub : [`genesis_proof.json`](genesis_proof.json)
- DNS TXT : `_vera.pk.vera.stream` (à venir)

---

## Conformité

| Référentiel | État | Justification |
|-------------|------|---------------|
| RGPD | ✅ | Privacy différentielle ε=0,3, destruction J+48h, AIPD réalisée |
| CNIL | ✅ | Audit sans données, registre Art.30, consentement explicite |
| AI Act européen | ✅ | Signaux agrégés uniquement, traçabilité complète |
| BPI France | ✅ | Dossier prêt, modèle économique documenté |
| CNM | ✅ | Grille d'éligibilité remplie |

### Registre des traitements (Art. 30)

- **Finalité** : financement du streaming par vente de signaux agrégés
- **Base légale** : consentement explicite (art. 6‑1‑a)
- **Durée** : agrégats conservés indéfiniment, données brutes ≤ 48h
- **Sous‑traitants** : Cloudflare (R2, CDN), FreeTSA (horodatage)

---

## Démarrage rapide

### Initialisation du registre d'audit

```python
from vera_audit_core import VERAWithAudit

vera = VERAWithAudit()
agg = {
    "epsilon": 0.3,
    "k": 5100,
    "k_min": 100,
    "wk": 0.3,
    "privacy_score": 0.87,
    "station_count": 12,
    "aggregated_at": "2026-04-01T12:00:00Z"
}
vera.aggregate_and_audit(agg)
report = vera.get_audit_report()
print(report["result"]["summary_internal"])
```

### Export pour auditeur

```python
bundle = vera.export_for_auditor()
with open("audit_bundle.json", "w") as f:
    json.dump(bundle, f, indent=2)
```

### Ancrage externe (STOP)

```bash
python3 vera_anchor_net.py --anchor-genesis
```

---

## Gain pour les opérateurs IA

> Signaux DP agrégés = données prêtes à l'emploi, structurées, conformes RGPD.
> Zéro scraping, zéro nettoyage, zéro risque légal.

**VERA ne stocke rien.** Données brutes détruites sous 48h — seuls les agrégats DP sortent.

Format de sortie type :

```json
{
  "timestamp": "2026-04-01T12:00:00Z",
  "epsilon": 0.3,
  "k": 5100,
  "privacy_score": 0.87,
  "aggregates": {
    "track_id": "5b7c8f2a",
    "listen_count_dp": 127,
    "avg_duration_dp": 183.4
  }
}
```

---

## Dépôt et artefacts

```
vera/
├── README.md
├── LICENSE
├── vera_audit_core.py        # Cœur d'audit (S2)
├── vera_anchor_net.py        # Ancrage réseau RFC3161
├── genesis_proof.json        # Preuve d'arrêt signée
├── docs/
│   ├── audit_report.md
│   ├── aipd_complete.pdf
│   └── registre_traitements.pdf
└── tests/
    ├── test_invariants.py
    └── test_audit_chain.py
```

---

## Contact

**tahahouari@hotmail.fr**

---

> *"Ne me faites pas confiance. Vérifiez le code."*
> *"Ne me faites pas confiance. Vérifiez l'ancrage."*

---

*Dernière mise à jour : 2026-04-01 · Version : 2.0 · Statut : Prêt pour audit BPI France / CNIL*


