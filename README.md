# ANCRE
## Attested Noise Client Runtime Engine

**Middleware de confidentialité avec attestation matérielle SIM — indépendant de toute infrastructure GAFA.**

ANCRE étend le pipeline de confidentialité différentielle [VERA Radio](https://github.com/taha-vera/Vera-protocole-) avec une couche d'attestation client via GSMA IoT SAFE. La carte SIM signe chaque signal bruité avant transmission. Le serveur vérifie l'attestation avant agrégation.

---

## Architecture

```
Appareil utilisateur
  └─ ANCRE Client Runtime
       ├─ Bruit Laplace (ε=1.0)
       ├─ Validation signal (NaN/Inf/bornes)
       ├─ SignedPayload : hash + nonce + slot + sim_mode + timestamp
       └─ SIM (IoT SAFE, CC EAL4+/5+) signe le payload

Serveur ANCRE
  └─ AncreVerifierV2 : PKI + nonce + hash + expiry cert + quota device
  └─ AncreServerV2 : cap coalition (identité) + TMoM + bruit serveur
  └─ Chaîne d'audit : Ed25519 + RFC3161
```

## Racine de confiance

PKI de la carte SIM via opérateur télécom (Orange, SFR, Bouygues, Transatel).  
**Aucune dépendance à Google, Apple ou toute infrastructure propriétaire GAFA.**

---

## Structure du dépôt

```
ancre-protocole/
├── ancre_sim_attest.py         # Interface SIM (Mock + stub production IoT SAFE)
├── ancre_verify.py             # Vérification serveur v0.1
├── ancre_pipeline.py           # Pipeline complet v0.1
├── ancre_patch_v0.2.py         # Vérificateur + serveur corrigés v0.2 (10 patches)
├── ancre_tests.py              # Tests adversariaux v0.1 (29/29)
├── ancre_tests_v0.2.py         # Tests adversariaux v0.2 (validés red team)
├── ANCRE_Whitepaper_v0.2.md    # Whitepaper technique
├── ANCRE_Product_Brief_v0.2.md # Fiche produit (prospection B2B)
├── SECURITY.md                 # Modèle de menace et limites connues
└── README.md
```

---

## Invariants de sécurité

| Paramètre | Valeur | Application |
|---|---|---|
| ε_client | 1.0 | Fixe — non configurable |
| ε_server | 0.5 | Fixe — non configurable |
| ε_total | ≤ 1.5 | Kill-switch |
| K_min | 100 | Kill-switch |
| wK | 0.3 | Cap par identité device (serial certificat) |
| Fenêtre nonce | 5 min | Cache UUID anti-replay |
| Quota device | 3 signaux/session | Par serial certificat |
| Limite buffer | 10 000 signaux | Protection DoS |
| Taille cert max | 8 Ko | Protection DoS |

---

## Ce qu'ANCRE prouve

✅ Une clé Ed25519 résidente SIM a signé le signal bruité déclaré  
✅ Le certificat est chaîné à la PKI d'un opérateur télécom de confiance  
✅ Le certificat était valide au moment de la signature  
✅ Le nonce était frais (non rejoué)  
✅ Le signal est dans [0,1] et n'est pas NaN/Inf  
✅ Le device n'a pas dépassé son quota de session (résistance Sybil)  

## Ce qu'ANCRE ne prouve pas

⚠️ Que le bruit Laplace a été appliqué au ε déclaré (limite architecturale)  
⚠️ Qu'un binaire client compromis n'a pas été utilisé  
⚠️ Support iOS (Apple bloque l'accès SIM tiers)  

---

## Validation red team

ANCRE v0.1 a été évalué par 6 reviewers de sécurité IA indépendants.  
12 vulnérabilités critiques ont été identifiées et corrigées en v0.2.

| Sévérité | Trouvées | Corrigées |
|---|---|---|
| Critique | 4 | 4 |
| Élevée | 6 | 5 + 1 documentée |
| Moyenne | 2 | 2 |

Voir `ANCRE_Whitepaper_v0.2.md` Section 4 et Annexe A pour la matrice complète.

---

## Démarrage rapide (Termux / Android)

```bash
pip install cryptography numpy --break-system-packages

# Tests pipeline v0.1
python ancre_sim_attest.py
python ancre_verify.py
python ancre_pipeline.py

# Tests adversariaux v0.2
python ancre_tests_v0.2.py
```

---

## Relation avec VERA

ANCRE est un produit distinct de VERA Radio. Il réutilise le pipeline de confidentialité VERA (LDP, K-anonymité, TMoM, chaîne d'audit) et y ajoute une couche d'attestation matérielle.

| | VERA Radio | ANCRE |
|---|---|---|
| Attestation client | Chaîne d'audit post-hoc | SIM hardware temps réel |
| Déployabilité | Tout Android | Tout téléphone avec SIM |
| Dépendance GAFA | Aucune | Aucune |
| Racine de confiance | VERA (Ed25519) | PKI opérateur télécom |
| Marché cible | Radio, streaming B2B | Médical, finance, NIS2 |

---

## Statut

**v0.2 — Validé red team — Développement (SIM mock)**  
Le déploiement en production nécessite un partenariat IoT SAFE avec un MVNO ou opérateur télécom.

---

*SAS VERA — Paris, France*  
*Contact : tahahouari@hotmail.fr*  
*Dépôt VERA : github.com/taha-vera/Vera-protocole-*
