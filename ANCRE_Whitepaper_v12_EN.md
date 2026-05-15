# ANCRE: Attestation & Noise for Confidential Radio Emissions
## A Differentially Private Aggregation Protocol for Audio Analytics

**Taha Houari**  
SAS VERA, Paris, France  
tahahouari@hotmail.fr  
https://github.com/taha-vera/Vera-protocole-

---

## Abstract

We present ANCRE (*Attestation & Noise for Confidential Radio Emissions*), a differentially private aggregation protocol for B2B audio streaming analytics. ANCRE addresses a fundamental tension: listening data is commercially valuable to AI operators but legally restricted under GDPR.

Three contributions: **(i) Theoretical** — a Central DP mechanism based on the trimmed mean (TMoM, α=0.1) with exact discrete Laplace noise (Ghosh et al., 2012) under substitute adjacency (H6: closed window), achieving ε=0.5-DP per aggregation (δ=0). **(ii) Architectural** — a Sybil-resistance layer via GSMA IoT SAFE SIM attestation, an operational anti-fraud measure independent of the DP guarantee. **(iii) Empirical** — Spearman ρ=0.9997 on Last.fm (92,834 events, K=100), vs ρ=0.9823 for local DP at the same ε.

Under add/remove adjacency, effective ε=1.0 (same implementation, conservative bound). The protocol is designed to support GDPR Articles 25 and 89 compliance.

**Keywords**: differential privacy, trimmed mean, discrete Laplace, substitute adjacency, Sybil resistance, audio analytics

---

## 1. Context and Problem

### 1.1 The Radio Listening Data Problem

Audio streaming platforms collect granular listening data commercially valuable to AI operators, but sensitive under GDPR (EU 2016/679). Selling raw data risks sanctions up to 4% of global turnover (Article 83).

```
Raw data       → Maximum value, legally restricted
Aggregated data → Legally defensible, reduced value
```

**Question**: Can a mechanism produce useful aggregates with a formal privacy guarantee, compatible with GDPR?

### 1.2 Differential Privacy

Differential Privacy (Dwork et al., 2006; Dwork & Roth, 2014) guarantees that observing M(D) cannot increase confidence about individual participation by more than e^ε. For ε=0.5: confidence multiplier ≤ 1.65.

### 1.3 Limitations of Existing Approaches

**Local DP** (Apple, RAPPOR): strong protection, weak utility — requires millions of users. At ε=0.5 on Last.fm: ρ=0.9823 (vs 0.9997 for ANCRE).

**Central DP without attestation**: better utility, vulnerable to Sybil attacks.

**IEEE 754 Laplace**: LSB leakage introduces δ > 0 (Mironov, 2012).

**Shuffle/MPC** (Prio, Prochlo): strong guarantees without fully trusted server, but require complex multi-party infrastructure.

ANCRE targets: Central DP with high utility, physical Sybil resistance, exact discrete noise (δ=0).

### 1.4 Contributions

**C1 — High-utility Central DP**: TMoM (α=0.1) + exact DLap. ε=0.5-DP (δ=0). ρ=0.9997 on Last.fm.

**C2 — Sybil resistance via SIM attestation**: IoT SAFE (GSMA, ETSI TS 102 226) binds each signal to a telecom operator certificate. Operational measure, independent of DP guarantee.

**C3 — Formal sensitivity proof**: explicit stable sort, tie-breaking convention, Structural Lemma on |T(D) △ T(D')| ≤ 2.

**Scope note**: C1 and C3 are formal DP contributions. C2 is operational security. The combination is, to our knowledge, novel for audio/radio analytics.

### 1.5 Target Use Case

**Actors**: Radio France, FIP, Mouv', France Inter (data producers); AI operators (buyers); CNIL, DPC (regulators).

**Flow**:
```
1. Listener → raw signal on terminal
2. Client: optional LDP noise + IoT SAFE SIM attestation
3. Server: SIM verification → TMoM + DLap → certified aggregate
4. AI operator purchases aggregate
```

**LDP note**: When the optional client layer is active (ε_client=1.0), full system provides (1.5, 0)-DP per aggregation. Section 3 proves the server-side guarantee independently.

---

## 2. Protocol Architecture

### 2.1 Overview

```
┌──────────────────────────────────────────┐
│ Layer 1: Client — Optional LDP + SIM     │
└────────────────────┬─────────────────────┘
                     │ Signal + Attestation
┌────────────────────▼─────────────────────┐
│ Layer 2: Server — Central DP             │
│ SIM verify, TMoM, DLap, Budget          │
└────────────────────┬─────────────────────┘
                     │ Certified aggregate
┌────────────────────▼─────────────────────┐
│ Layer 3: AI Operator                     │
└──────────────────────────────────────────┘
```

### 2.2 Layer 1 — Client

**Signal validation**: xᵢ ∈ [0,1], NaN/Inf rejected (H2).

**Optional LDP**: `clamp(raw + DLap(1/ε_client), 0, 1)`. Raw signal destroyed after.

**SIM attestation**: `payload = {SHA256(signal), nonce, slot, timestamp}`. SIM signs with Ed25519. `signal_hash = SHA256(struct.pack('>d', value))` — deterministic IEEE 754.

### 2.3 Layer 2 — Server

**Verification order** (12 steps, signature at step 8 — before nonce/quota to prevent DoS):

```
1. Certificate size  5. Expiry         9.  Timestamp
2. Signal validity   6. Operator      10.  Nonce anti-replay
3. Mock policy       7. CA chain      11.  Signal hash
4. DER parse         8. ED25519 SIG   12.  Device quota (max 1/SIM)
```

**Aggregation**:
```
Step 1: Sybil dedup   → one signal per SIM serial
Step 2: TMoM_α        → stable sort, trim L each side
Step 3: DLap noise    → scale_int = round(r×Δ/ε), noise = k/r
Step 4: Post-process  → clamp(tmom + noise, 0, 1)
Step 5: Response      → {result, n, ε_used, δ=0, ε_total}
```

### 2.4 Protocol Invariants

| Parameter | Value | Role |
|---|---|---|
| K_MIN | 100 | K-anonymity, kill-switch |
| ε_SERVER | 0.5 | Budget per aggregation |
| ε_MAX | 1.5 | Total (3 aggregations) |
| α | 0.1 | TMoM trim fraction |
| r | 1000 | DLap resolution |
| MAX_BUFFER | 10,000 | Memory limit |
| NONCE_TTL | 300s | Anti-replay window |

### 2.5 Supporting Components

**EpsilonBudget (u64)**: micro-epsilon tracking, no float drift. Exactly 3 aggregations.

**PolicyEngine**: atomic irreversible kill-switch (Release/Acquire ordering).

**SessionGuard**: credential permanently invalidated after budget exhaustion.

**HMAC-SHA256 audit chain**: `entry_i = HMAC(key, prev_hash || agg || k || ε)`. Append-only.

**RFC3161**: FreeTSA anchor, 2026-03-31T21:01:11 UTC.

---

## 3. Formal Guarantees

### 3.1 Adversary Model

Central DP (McSherry, 2009), semi-honest server. Adversary observes M(D) and published metadata (n, ε). DLap eliminates LSB channels.

**Out of model**: timing O(n log n), physical SIM compromise.

### 3.2 Definitions

**Def. 1 — Substitute adjacency (~_s)**: D ~_s D' iff |D|=|D'|=n, D'=(D\{x_k})∪{x'_k}.

**Def. 2 — Add/remove adjacency (~_ar)**: D ~_ar D' iff |D △ D'|=1.

**Def. 3 — ε-DP** (Dwork & Roth, Def. 2.4): Pr[M(D)∈S] ≤ e^ε × Pr[M(D')∈S] for all D~_s D', S.

**Adjacency choice**: ANCRE proves ε=0.5-DP under ~_s (H6: n fixed and public before output). Under ~_ar: same implementation, ε=1.0 (sensitivity doubles to 2/n_eff). GDPR Article 17 concerns may require ~_ar analysis; we recommend CNIL consultation for production.

### 3.3 Hypotheses

| | Hypothesis | Statement | Required for Thm. 1? |
|---|---|---|---|
| H1 | One signal/SIM/window | max_per_device=1 | Yes |
| H2 | Bounded signals | xᵢ ∈ [0,1] | Yes |
| H3 | n public before output | atomic order | No |
| H4 | ChaCha20 independence | architectural trust | No |
| H5 | Fixed population | composition (Claim 3.16) | For Cor. 1 |
| H5a | Homogeneous params | α, ε, n identical | For Cor. 1 |
| H6 | Closed window | n fixed before aggregate() | Yes (~_s justification) |

### 3.4 Discrete Laplace Mechanism

(Ghosh et al., 2012; Canonne et al., 2020):

```
DLap(b) = G₁ − G₂,  Gi ~ Geom(p),  p = 1 − e^{−1/b}
```

Resolution r=1000: scale_int = round(r×Δ/ε) = 25 (n=100, ε=0.5). p ≈ 0.039 — non-degenerate. δ=0 by construction (finite grid, no LSB leakage).

**MSE**: For μ ∈ (Δ/ε, 1−Δ/ε): MSE ≈ 2(Δ/ε)² = 0.00125 (n=100).

### 3.5 Lemma 1 — TMoM Sensitivity

**Lemma 1.** *Let D = {x₁,...,xₙ}, xᵢ ∈ [0,1], n ≥ 100, α = 0.1. Under ~_s:*

```
Δ_subst(TMoM_α) ≤ 1/(0.8n)
```

**Setup**: Let s(D) be the stable sorted sequence of D (total_cmp/TimSort; ties by original index). Define:

```
L = ⌊αn⌋,  U = n−L,  T(D) = {s(D)_{L+1},...,s(D)_U},  n_eff = |T(D)| ≥ 0.8n
```

**Structural Lemma**: Under ~_s, `|T(D) △ T(D')| ≤ 2` — specifically, either T(D)=T(D'), or exactly one element exits and one enters.

*Proof*: n constant → L, U, n_eff constant → |T(D)|=|T(D')|=n_eff. A single substitution modifies one rank in s(D), shifting at most one lower and one upper boundary element. Hence |T(D) △ T(D')| ∈ {0, 2}. □

**Main proof**: Two cases:

*Case A — T(D)=T(D')*: ΔTMoM = 0. ✓

*Case B — one exit e, one entry f*:

```
TMoM(D') − TMoM(D) = (f − e) / n_eff
```

This is a **single signed difference** — not a sum of two terms. Even when both trim boundaries shift simultaneously (x_k crosses from lower to upper tail), n_eff remains constant and the net sum change is one replacement: e exits, f enters.

By H2: f, e ∈ [0,1], therefore |f−e| ≤ 1:

```
|ΔTMoM| = |f−e|/n_eff ≤ 1/n_eff ≤ 1/(0.8n)  □
```

**Tight bound**: Achieved when e=0, f=1 (or reverse) — verified numerically at |ΔTMoM| = 1/80.

**Complete case table**:

| Case | x_k | x'_k | e (exits) | f (enters) |
|---|---|---|---|---|
| 1-2 | tail | same tail | — | — |
| 3 | center | center | x_k | x'_k |
| 4-5 | tail | center | s(D)_{L+1} or s(D)_U | x'_k |
| 6-7 | center | tail | x_k | s(D')_{L+1} or s(D')_U |
| 8 | lower | upper | s(D)_{L+1} | s(D)_{U+1} |
| 9 | upper | lower | s(D)_U | s(D)_L |

### 3.6 Theorem 1 — ε-DP of M_ANCRE

**Theorem 1.** *Under H1, H2, H6, ~_s: M_ANCRE satisfies ε=0.5-DP (δ=0).*

**Step 1**: By Lemma 1, Δ ≤ 1/(0.8n). M₀ = TMoM_α + DLap(Δ/ε) satisfies ε-DP (Ghosh et al., 2012, Thm. 1).

**Step 2**: clamp is data-independent. By Prop. 2.1 (Dwork & Roth):

```
M_ANCRE = clamp ∘ M₀  satisfies  ε=0.5-DP (δ=0).  □
```

H3, H4, H5 not required.

### 3.7 Corollary 1 — Composition

Under H1, H3, H5, H5a, k≤3 aggregations: ε_total=1.5, δ_total=0.

By Prop. 3.14 (Dwork & Roth) — pure DP, no independence assumption. EpsilonBudget (u64) enforces ε_total ≤ 1.5. □

---

## 4. Experimental Validation

### 4.1 Implementation

**Rust v0.7**: 59 unit tests, 8 modules, 0.8s on ARM64.  
**Python v0.3**: 21 tests (SIM attestation, pipeline).

### 4.2 Discrete Laplace Validation

KS-test (n=10,000, scale=0.025): stat=0.0089 < threshold 0.020. ✓

| Property | Theoretical | Empirical |
|---|---|---|
| E[DLap] | 0 | −0.0003 ± 0.0002 |
| Var[DLap] | 0.00125 | 0.00124 ± 0.00003 |

### 4.3 Empirical DP Check (Indicative)

D/D' protocol: 100 signals, one replaced by 0.5+δ. 10,000 trials.

| δ | Max ratio | e^0.5=1.649 | Status |
|---|---|---|---|
| 0.1 | 1.41 | 1.649 | ✓ |
| 0.5 | 1.38 | 1.649 | ✓ |

**Warning**: indicative only. Formal guarantee rests on Theorem 1.

### 4.4 Utility Baseline Comparison

All evaluated on Last.fm hetrec2011 (92,834 events), K=100.

**Mechanism comparison** (ε=0.5):

| Mechanism | ρ (Spearman) | MSE | δ |
|---|---|---|---|
| No privacy | 1.0000 | 0 | — |
| Local DP (ε=0.5) | 0.9823 | 0.0089 | 0 |
| Mean + DLap | 0.9991 | 0.0018 | 0 |
| **TMoM (α=0.1) + DLap** | **0.9997** | **0.0012** | **0** |
| Laplace f64 (v0.6) | 0.9996 | 0.0013 | 2.9×10⁻¹⁵ |

**Effect of ε** (TMoM + DLap):

| ε | ρ | MSE | Note |
|---|---|---|---|
| 0.1 | 0.9923 | 0.0081 | Strong privacy |
| 0.5 | 0.9997 | 0.0012 | ANCRE default |
| 1.0 | 0.9999 | 0.0003 | ~_ar bound |

At ε=1.0 (add/remove adjacency), ρ=0.9999 — system remains highly useful under conservative model.

**Effect of K_MIN**:

| K | ρ | MSE |
|---|---|---|
| 50 | 0.9994 | 0.0014 |
| **100** | **0.9997** | **0.0012** |
| 200 | 0.9998 | 0.0011 |

---

## 5. Limitations, Discussion, and Future Work

### 5.1 Model Limitations

**5.1.1 Substitute vs Add/Remove Adjacency**

ANCRE proves ε=0.5-DP under ~_s (justified by H6: n fixed, public). Under ~_ar (presence protected), same implementation gives ε=1.0 — still ρ=0.9999 (Table §4.4). GDPR Article 17 (right to erasure) may require ~_ar. We recommend CNIL consultation.

**5.1.2 Sybil Resistance**

Cost analysis: IoT SAFE SIMs ≈ €5–50/year. Dominating K=100 window: 51 SIMs ≈ €255–2,550/year — meaningful barrier, not cryptographic guarantee. MockSimCard in development accepts any certificate; production requires live SIM.

**5.1.3 Timing Side-Channels**

TMoM sort: O(n log n), data-dependent. DLap geometric sampler: variable time. Both are outside the formal DP model. Constant-time implementations planned for v0.8.

**5.1.4 LDP + Central DP Composition**

When client LDP is active: (1.5, 0)-DP per aggregation by Prop. 3.14. Theorem 1 proves server-side guarantee independently.

**5.1.5 Static Evaluation**

Last.fm is a static offline dataset. Real-time streaming requires continual observation model (Dwork et al., 2010) — not implemented in v0.7.

### 5.2 Comparison with State of the Art

| Approach | DP Model | δ | Sybil | ρ (ε=0.5) |
|---|---|---|---|---|
| ANCRE v0.7 | Central, ~_s | 0 | IoT SAFE SIM | **0.9997** |
| Apple DP | Local, (ε,δ) | >0 | None | ~0.98 |
| RAPPOR | Local | 0 | None | 0.9823 |
| Prio/Prochlo | Shuffle/MPC | ~0 | Partial | High |

### 5.3 Regulatory Alignment

**GDPR**: Designed to support Articles 25 (Privacy by Design) and 89 (statistical processing). DP alone does not constitute anonymization under WP29/EDPB guidance. A DPIA (Article 35) is required for production deployment.

**EU AI Act**: Article 10 applies if aggregates feed downstream AI systems.

### 5.4 Future Work

**v0.8**: TEE/ARM TrustZone for H4 hardware guarantee; constant-time DLap sampler; Rényi DP composition (ε_total ≈ 1.3 for k=3).

**v1.0**: ~_ar proof (ε=1.0); continual observation; membership inference evaluation; Coq/Lean verification of Structural Lemma.

**Production**: Telecom SIM partnership; CNIL consultation.

---

## References

```
[1]  Dwork, C. & Roth, A. (2014). Algorithmic Foundations of DP.
     Foundations and Trends in TCS.

[2]  Ghosh, A., Roughgarden, T. & Sundararajan, M. (2012).
     Universally Utility-Maximizing Privacy Mechanisms.
     SIAM Journal on Computing 41(6).

[3]  Canonne, C., Kamath, G. & Steinke, T. (2020).
     The Discrete Gaussian for DP. NeurIPS 2020.

[4]  McSherry, F. (2009). Privacy Integrated Queries. ACM SIGMOD.

[5]  Dwork, C. & Lei, J. (2009). DP and Robust Statistics. ACM STOC.

[6]  Mironov, I. (2012). On Significance of the LSB for DP. ACM CCS.

[7]  Kairouz, P. et al. (2021). Advances and Open Problems in
     Federated Learning. JMLR 22(1).

[8]  Douceur, J.R. (2002). The Sybil Attack. IPTPS 2002.

[9]  Dwork, C. et al. (2006). Calibrating Noise to Sensitivity. TCC 2006.

[10] Bassily, R. & Smith, A. (2015). Local, Private, Efficient
     Protocols for Succinct Histograms. STOC 2015.

[11] Dwork, C. et al. (2010). Differential Privacy Under
     Continual Observation. STOC 2010.

[12] Mironov, I. (2017). Rényi Differential Privacy. CSF 2017.
```

---

*Code: https://github.com/taha-vera/Vera-protocole-*  
*RFC3161: FreeTSA, 2026-03-31T21:01:11 UTC*
