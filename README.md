VERA is a privacy-first protocol that transforms user signals into anonymous, irreversible statistics — with no accounts and no tracking. It ensures structural anonymity, fair redistribution for artists (+30% minimum), and provides ethically usable data for AI while minimizing energy consumption (Green IT# VERA — Privacy-First Music Data Compliance Protocol

> **VERA produit des décisions exploitables sans jamais exposer de données individuelles.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Status: Beta](https://img.shields.io/badge/Status-Beta-gold.svg)]()
[![Compliance: RGPD · AI Act · RFC3161](https://img.shields.io/badge/Compliance-RGPD%20%7C%20AI%20Act%20%7C%20RFC3161-green.svg)]()

---

## Ce que fait VERA

VERA est un protocole B2B white-label qui transforme des données d'écoute brutes en signaux agrégés exploitables — conformes RGPD, AI Act, et auditables par preuve cryptographique.

Les plateformes (radios, distributeurs, streamers) intègrent VERA pour :
- rendre leurs données d'écoute **vendables aux opérateurs IA**
- **éliminer leur exposition légale** RGPD / AI Act
- produire des **décisions produit défendables** sans accès aux données brutes

---

## Architecture

```
Données brutes → LDP Edge Layer (ε=1.0) → Signal agrégé → Audit RFC3161
                      ↓                          ↓                ↓
               Bruit local ajouté         Irréversible       Hash chaîné
               (aucun accès serveur)      K_MIN = 100        TSA qualifiée EU
```

**Invariants techniques garantis :**
- `ε ∈ [0.1, 1.5]` — budget de confidentialité paramétrable
- `K_MIN = 100` — seuil réglementaire plancher, non négociable
- Destruction irréversible des données brutes post-agrégation
- Preuve RFC3161 vérifiable par tout auditeur externe

---

## Modèle économique

| Coût de traitement | Signal revendu |
|---|---|
| ~0.001 €/heure | >0.01 €/heure |

Les acheteurs de signal : labels, opérateurs IA, chercheurs, régies publicitaires.

---

## Conformité

| Standard | Statut |
|---|---|
| RGPD / CNIL | ✅ LDP — aucune donnée personnelle transmise |
| AI Act (EU) | ✅ Traçabilité causale complète |
| RFC3161 | ✅ Timestamping qualifié EU |
| BPI / CNM | ✅ Compatible financement public FR |

---

## Démo — Deal Closer

Le fichier `static/index.html` est un dashboard de closing opérationnel :

- **Signal live** — mise à jour toutes les 3 secondes
- **Insight automatique** — genre, pic d'écoute, skip rate, ROI estimé
- **Verify & Download Proof** — génère un `vera_proof.json` signé RFC3161
- **Inject Event** — simule un batch entrant en temps réel

---

## Preuve d'ancrage (Genesis)

Le fichier `genesis_proof.json` contient l'ancrage cryptographique initial du protocole :

```json
{
  "stop_reached": true,
  "tsa": "freetsa.org",
  "token_valid": true
}
```

Vérifiable sur tout client RFC3161 compatible.

---

## Contact

**Taha Houari** — Founder  
tahahouari@hotmail.fr  
[github.com/taha-vera/Vera-protocole-](https://github.com/taha-vera/Vera-protocole-)

---

*VERA — signal. pas données.*