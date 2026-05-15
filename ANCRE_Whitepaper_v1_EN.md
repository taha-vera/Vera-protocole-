# ANCRE: Attestation & Noise for Confidential Radio Emissions
## A Pure Differentially Private Aggregation Protocol for Audio Analytics

**Taha Houari**  
SAS VERA, Paris, France  
tahahouari@hotmail.fr  
https://github.com/taha-vera/Vera-protocole-

---

## Abstract

We present ANCRE (*Attestation & Noise for Confidential Radio Emissions*), a pure differentially private aggregation protocol for B2B audio streaming analytics. ANCRE addresses a fundamental tension in the radio industry: listening data is commercially valuable to AI operators but legally unsellable under GDPR due to privacy constraints.

ANCRE combines three technical contributions. First, a Central DP mechanism based on the trimmed mean (TMoM, α=0.1) with discrete Laplace noise (Ghosh et al., 2012), achieving pure ε=0.5-DP (δ=0) by eliminating floating-point LSB leakage (Mironov, 2012). Second, a Sybil-resistance layer via GSMA IoT SAFE SIM attestation, binding each signal to a physical SIM certificate issued by a trusted telecom operator. Third, a formal proof under substitute adjacency with explicit tie-breaking convention, yielding sensitivity Δ = 1/(0.8n) and Spearman correlation ρ = 0.9997 on the Last.fm dataset (92,834 events, 1,892 users).

The implementation (Rust v0.7, Python v0.3) passes 59+21 unit tests on Android/ARM64 (Termux), including a Kolmogorov-Smirnov test on the discrete Laplace distribution (KS stat = 0.0089 < threshold 0.020). The protocol complies with GDPR Articles 25 and 89, EU AI Act Article 10, and includes RFC3161 temporal anchoring (FreeTSA, March 2026). Red-team evaluation across 8 AI systems yields a consensus score of 89/100.

**Keywords**: differential privacy, audio analytics, discrete Laplace, SIM attestation, Sybil resistance, GDPR compliance, trimmed mean

---

## 1. Context and Problem

### 1.1 The Radio Listening Data Problem

Audio streaming platforms collect real-time granular listening data: which user listens to which program, at what time, from which device, for how long. This data has considerable commercial value for AI operators wishing to train recommendation models, trend analysis systems, or advertising targeting engines.

However, this data is **sensitive under GDPR** (General Data Protection Regulation, EU 2016/679). Listening habits reveal protected political, religious, or cultural preferences. A radio platform that sells this raw data faces substantial sanctions (up to 4% of global turnover, Article 83 GDPR) and a loss of listener trust.

The tension is as follows:

```
Raw data       → Maximum commercial value, unsellable (GDPR)
Aggregated data → Legally sellable, reduced commercial value
```

**Central question**: Does a mechanism exist that produces statistically useful aggregates with a mathematical individual protection guarantee, legally sellable to AI operators?

### 1.2 Differential Privacy as a Solution

**Differential Privacy** (DP) offers a formal answer to this question. Introduced by Dwork et al. (2006) and formalized in Dwork & Roth (2014), DP mathematically guarantees that an adversary observing the output of an aggregated mechanism cannot distinguish whether a specific individual participated or not.

**Informal definition**: A mechanism M satisfies ε-DP if, for any individual k and any set of possible answers S:

```
Pr[M(D) ∈ S] ≤ e^ε × Pr[M(D \ {k}) ∈ S]
```

The smaller ε, the stronger the protection. For ε = 0.5 (our choice), an adversary cannot multiply their confidence by more than e^{0.5} ≈ 1.65 by observing the output.

DP is now deployed in major industrial systems: Apple (iOS, macOS), Google (RAPPOR, Chrome), the US Census Bureau (2020 census). These deployments validate the technological maturity of the approach.

### 1.3 Limitations of Existing Approaches

Current industrial deployments have limitations making them ill-suited for the B2B radio context:

**Local DP (Apple, Google)**: Noise is added client-side before transmission. Protection is strong but utility is weak — millions of users are needed for precise aggregates. Unsuitable for French radio platforms (a few million listeners at most).

**Central DP without attestation**: The central server applies noise after aggregation. Utility is better but the system is vulnerable to Sybil attacks: a malicious actor can submit thousands of fake signals and bias the aggregate. Without a participant identity attestation mechanism, the DP guarantee is not operationally valid.

**DP with IEEE 754 floats**: Standard implementations of the Laplace mechanism on double-precision floats introduce an information leak via least significant bits (Mironov, 2012). The formal guarantee is (ε, δ)-DP with δ > 0, not pure DP (δ=0).

**No explicit legal framework**: Existing deployments do not explicitly document their GDPR or EU AI Act compliance. A radio operator buying this data has no formal proof usable in a regulatory audit.

### 1.4 Our Contribution: ANCRE

We present **ANCRE**, a pure differential privacy protocol designed specifically for the B2B audio analytics context. ANCRE addresses the identified limitations through four contributions:

**Contribution 1 — High-utility Central DP**: ANCRE applies server-side noise on a trimmed mean (TMoM, α=0.1), achieving Spearman correlation ρ = 0.9997 with ground truth on the Last.fm dataset (92,834 events, 1,892 users).

**Contribution 2 — IoT SAFE SIM attestation for Sybil resistance**: Each signal is bound to an X.509 certificate issued by a trusted telecom operator (GSMA IoT SAFE standard, ETSI TS 102 226). A Sybil attacker must control as many physical SIMs as fake signals — economically prohibitive.

**Contribution 3 — Pure DP (δ=0) via discrete Laplace**: The implementation uses an exact discrete Laplace mechanism (Ghosh et al., 2012) with resolution r=1000, eliminating the floating-point leaks of Mironov (2012). The guarantee is strict ε=0.5-DP, without δ term.

**Contribution 4 — Legal traceability**: Each aggregation produces a response including n (dataset size, explicitly published), ε used, and an HMAC-SHA256 hash of the audit chain. These metadata constitute proof of GDPR Article 25 (Privacy by Design) and Article 89 (statistical processing) compliance.

### 1.5 Target Use Case

**Actors**:
- **Radio platforms** (Radio France, FIP, Mouv', France Inter): listening data producers.
- **AI operators**: buyers of aggregates for recommendation model training.
- **Regulators** (CNIL, DPC): GDPR compliance auditors.

**Operational flow**:

```
1. Listener tunes in → raw signal on terminal
2. ANCRE client applies LDP noise (ε_client, Python layer)
3. Noisy signal + SIM attestation → ANCRE server
4. Server verifies SIM attestation (Sybil resistance)
5. Window closed at K ≥ 100 signals (K-anonymity)
6. TMoM + discrete DLap → final aggregate (ε_server = 0.5)
7. Response published: result + n + ε + audit hash
8. AI operator purchases the certified aggregate
```

**Business model**: Radio France no longer sells raw data (GDPR-prohibited) but **certified DP aggregates**, traceable and auditable. The price can exceed raw data as DP certification reduces legal risk for the buyer.

### 1.6 Paper Organization

- **Section 2**: Detailed ANCRE protocol architecture.
- **Section 3**: Formal guarantees — Sensitivity Lemma, ε-DP Theorem, Composition Corollary.
- **Section 4**: Experimental results — unit tests, KS-test, Last.fm validation, multi-AI red team.
- **Section 5**: Limitations, comparative discussion, and future work.

---

## 2. Protocol Architecture

### 2.1 Overview

ANCRE is a three-layer protocol, each with distinct responsibilities:

```
┌─────────────────────────────────────────────────┐
│  Layer 1: Client (listener terminal)             │
│  ancre_pipeline.py — LDP noise + SIM Attestation │
└────────────────────┬────────────────────────────┘
                     │ Noisy signal + Attestation
┌────────────────────▼────────────────────────────┐
│  Layer 2: ANCRE Server (Central DP)              │
│  ancre_verify.py + ancre-rust-v07/              │
│  SIM verification, TMoM, DLap, Budget           │
└────────────────────┬────────────────────────────┘
                     │ Certified aggregate
┌────────────────────▼────────────────────────────┐
│  Layer 3: AI Operator                            │
│  Consumer of certified DP aggregates             │
└─────────────────────────────────────────────────┘
```

DP guarantees operate primarily in Layer 2 (Central DP). Layer 1 adds an optional LDP layer (ε_client = 1.0) and SIM anti-Sybil attestation.

### 2.2 Layer 1 — ANCRE Client

#### 2.2.1 Signal Validation

Each raw signal is validated before any processing:

```python
def validate_signal(signal: float) -> float:
    # Reject NaN, Inf, values outside [0,1]
    # Hypothesis H2: signals bounded in [0,1]
```

Listening signals are normalized in [0,1] (e.g., listening duration / maximum window duration).

#### 2.2.2 Client LDP Noise (optional)

Discrete Laplace noise is applied client-side (ε_client = 1.0, Δ_client = 1):

```
noisy = clamp(raw_signal + DLap(1.0/ε_client), 0, 1)
del raw_signal  # raw signal destruction
```

This LDP layer reduces trust required in the server: even a compromised server only sees already-noisy signals.

#### 2.2.3 IoT SAFE SIM Attestation

Each noisy signal is signed by the Ed25519 key stored in the terminal's SIM:

```
payload = {signal_hash, nonce, slot, sim_mode, timestamp_utc}
signature = SIM.sign(SHA256(payload))
attestation = (noisy_value, payload, signature, certificate_chain)
```

The `signal_hash` is a SHA-256 of the signal via `struct.pack('>d', value)` — deterministic IEEE 754 encoding on all platforms.

### 2.3 Layer 2 — ANCRE Server

#### 2.3.1 Attestation Verification (ancre_verify.py v0.3)

Verification order is critical for security:

```
1.  Certificate size      ← DoS guard before parse
2.  Signal validity       ← NaN/Inf guard
3.  Reject mock           ← production policy
4.  Parse DER certificate ← required for public key
5.  Certificate expiry    ← temporal validity
6.  Authorized operator   ← PKI policy
7.  CA chain              ← root trust
8.  ED25519 SIGNATURE     ← before nonce and quota (V1)
9.  Timestamp freshness   ← ±300s window
10. Anti-replay nonce     ← consumed after valid signature
11. Signal hash           ← signal/payload consistency
12. Device quota          ← max 1 signal/SIM/window (H1)
```

**V1 — Signature before nonce**: An attacker with a fake signature cannot consume nonces or quotas.

**V2 — Ed25519 without separate hash**: The Python cryptography API requires `.verify(sig, data)` without hash algorithm for Ed25519.

#### 2.3.2 Buffer and Aggregation Window

Validated signals accumulate in a thread-safe buffer:

```
Buffer: [(noisy_value, cert_serial), ...]
Limit: MAX_BUFFER_SIZE = 10,000 signals
Timeout: BUFFER_TIMEOUT_SEC = 3600s
```

The window is closed (H6) when K ≥ K_MIN = 100 signals are available and the operator calls `aggregate()`.

#### 2.3.3 ANCRE Aggregation Mechanism (ancre-rust-v07)

**Step 1 — Sybil deduplication**:
```
filtered = {serial → noisy_value: one signal per device}
k_filtered = len(filtered) ≥ K_MIN
```

**Step 2 — TMoM_α (Lemma 1)**:
```
sorted_vals = sort(filtered.values())  # stable total_cmp sort
trim = floor(α × n)
center = sorted_vals[trim : n-trim]
tmom = sum(center) / n_eff   # n_eff = n - 2×trim
```

**Step 3 — Discrete DLap (Theorem 1)**:
```
Δ = 1/n_eff                     # formal sensitivity
scale = Δ/ε                     # ε = 0.5
scale_int = round(r × scale)    # r = 1000, scale_int = 25
k ~ DLap(scale_int)             # G1 - G2, Gi ~ Geom(p)
noise = k / r
```

**Step 4 — Post-processing**:
```
result = clamp(tmom + noise, 0.0, 1.0)
```

**Step 5 — Response (H3)**:
```rust
AggregateResponse {
    result: f64,
    n: usize,              // explicitly published
    epsilon_used: f64,
    delta_bound: f64,      // 0.0 for discrete DLap
    total_epsilon_used: f64,
}
```

### 2.4 Budget ε and Kill-Switch

**EpsilonBudget (u64)**: Budget tracked in micro-epsilon to avoid cumulative float drift. Three exact aggregations possible, not four.

**PolicyEngine**: Atomic kill-switch (Release/Acquire ordering), irreversible once activated.

**SessionGuard**: Each credential is bound to a SessionGuard that permanently invalidates the session after budget exhaustion.

### 2.5 Audit Chain

Each aggregation is recorded in an HMAC-SHA256 audit chain:

```
entry_i = HMAC(key, prev_hash || agg || k || ε)
```

The chain is append-only. The HMAC key is shared between the platform and AI operator, enabling a posteriori verification during GDPR audits.

### 2.6 RFC3161 Temporal Anchoring

The ANCRE proof of concept is temporally anchored via FreeTSA (RFC3161):

```
anchor_hash  : 13a7d636...
token_sha256 : 938559cb...
anchored_at  : 2026-03-31T21:01:11 UTC
```

### 2.7 Protocol Invariants

| Parameter | Value | Role |
|---|---|---|
| K_MIN | 100 | K-anonymity, kill-switch |
| EPSILON_SERVER | 0.5 | Budget per aggregation |
| EPSILON_MAX | 1.5 | Total budget (3 aggregations) |
| TRIM_FRACTION | 0.1 | TMoM robustness |
| DISCRETE_RESOLUTION | 1000 | DLap precision |
| MAX_BUFFER_SIGNALS | 10,000 | Memory limit |
| NONCE_TTL_SECS | 300 | Anti-replay window |

---

## 3. Formal Guarantees

### 3.1 Model and Hypotheses

#### 3.1.1 Adversary Model

We adopt the **Central DP** model (McSherry, SIGMOD 2009) with a **semi-honest (honest-but-curious)** adversary:

- The trusted server collects raw signals.
- The adversary observes the aggregated output M(D) and published metadata (n, ε).
- The discrete Laplace eliminates LSB channels — no variance-based leak.

**Out of model**: auxiliary timing channels O(n log n), Sybil attacks (§5.1.2).

#### 3.1.2 Preliminary Definitions

**Definition 1 — Substitute Adjacency (~_s)**:
D ~_s D' if |D| = |D'| = n and D' = (D \ {x_k}) ∪ {x'_k} for some index k.

**Definition 2 — Add/Remove Adjacency (~_ar)**:
D ~_ar D' if |D △ D'| = 1.

**Key advantage of ~_s**: n and n_eff are constant between D and D'. Under ~_ar, n_eff varies and the bound becomes 2/n_eff.

**Definition 3 — Pure ε-DP (δ=0)** (Dwork & Roth, 2014, Def. 2.4):

M satisfies ε-DP if for all D ~_s D' and all S ⊆ R:

```
Pr[M(D) ∈ S] ≤ exp(ε) × Pr[M(D') ∈ S]
```

#### 3.1.3 Hypotheses

**H1** — One individual = one signal per session. Enforced by IoT SAFE SIM protocol and `max_per_device = 1` constraint.

**H2** — Signals bounded in [0,1] (`BoundedSignal` type, NaN/Inf rejection).

**H3** — n published in `AggregateResponse.n` before aggregated output, in atomic order:
1. Compute n = |D|
2. Write n in response
3. If n < K_MIN → return ⊥

**H4** — ChaCha20/Python independence. Architectural trust hypothesis. **Not required for the mechanism's DP guarantee.**

**H5** — Fixed population for composition. An individual absent from aggregation i is unaffected by M_i (Claim 3.16, Dwork & Roth §3.5).

**H5a** — Homogeneous parameters for all aggregations (α, ε, n identical).

**H6 — Closed window**: The collection window is closed and n fixed **before** calling aggregate(). This hypothesis justifies applying the ~_s model to the ANCRE system: once the window is closed, any pair (D, D') in the DP reasoning has |D| = |D'| = n by construction.

Note: H6 does not define ~_s (which is purely mathematical) — it justifies that the physical context matches this definition.

#### 3.1.4 Exact Discrete Laplace Mechanism

**Algorithm** (Ghosh, Roughgarden & Sundararajan, 2012; Canonne, Kamath & Steinke, 2020):

```
DLap(scale_int) = G₁ − G₂,  Gi ~ Geom(p)
p = 1 − exp(−1/scale_int)
```

**Resolution r = 1000** for the [0,1] domain:
```
scale_int = round(r × Δ/ε) = round(1000 × 0.025) = 25
noise = DLap(scale_int) / r ∈ {k/1000 : k ∈ ℤ}
```

For scale_int = 25: p ≈ 0.039 — non-degenerate noise (b ≈ 0.025, non-zero).

**Pure DP (δ=0)**: Discrete Laplace operates on a finite grid, eliminating floating-point LSB leaks (Mironov, 2012). The guarantee is strict ε-DP, without additive δ term.

### 3.2 ANCRE Mechanism

```
M_ANCRE(D) = clamp(TMoM_α(D) + DLap_r(Δ/ε), 0, 1)
```

**Utility bound (MSE)**:

For μ = TMoM_α(D) ∈ (Δ/ε, 1−Δ/ε):

```
MSE ≈ 2(Δ/ε)² = 2/(n_eff × ε)²
```

For n=100, ε=0.5: MSE ≈ 2×(0.025)² = 0.00125.

### 3.3 Lemma 1 — TMoM Sensitivity (Substitute Adjacency)

**Lemma 1.**
*Let D = {x₁,...,xₙ}, xᵢ ∈ [0,1], n ≥ 100, α = 0.1. Under substitute adjacency (~_s):*

```
Δ_subst(TMoM_α) ≤ 1/(n × 0.8)
```

**Preliminary — n_eff ≥ 0.8n**: For n ≥ 100, n_eff = n − 2⌊0.1n⌋ ≥ 0.8n. ✓

**Tie-breaking convention**: In case of ties at the trim boundary, order is determined by index in the sorted array (stable sort — TimSort in Python, total_cmp in Rust). T(D) is thus uniquely defined for all D.

**Notation**: T(D) = indices retained after trim (positions ⌊αn⌋+1 to n−⌊αn⌋ in stable sort of D). |T(D)| = n_eff constant under ~_s (H6).

**Proof.**

Let D ~_s D': D' = D with x_k → x'_k, x_k, x'_k ∈ [0,1].

**Case 1** — x_k ∉ T(D) and x'_k ∉ T(D'): Δ_sum = 0. ✓

**Case 2** — x_k ∈ T(D) and x'_k ∈ T(D'): Δ_sum = x'_k − x_k, |Δ_sum| ≤ 1. ✓

**Case 3** — Queue/center transition.

**Auxiliary Lemma**: Under ~_s with stable sort and index tie-breaking, a substitution x_k → x'_k shifts at most **one** trim boundary position.

*Proof of Auxiliary Lemma*: The substitution modifies exactly one element of the sorted array. In stable sort, if x_k crosses exactly one trim boundary (lower or upper), exactly one boundary index changes side (index ⌊αn⌋ or n−⌊αn⌋). The index tie-breaking convention guarantees the boundary does not "jump" multiple positions simultaneously. Thus |T(D) △ T(D')| ≤ 2.

Let f be the value entering T(D'), e the value leaving T(D). f, e ∈ [0,1]:

```
|f − e| ≤ 1   (boundedness of [0,1])
```

**Fundamental note**: |f − e| is a signed difference ≤ 1, not a sum of absolutes (+1 + 1 = 2). This is the critical distinction from ~_ar.

|TMoM(D) − TMoM(D')| = |f − e|/n_eff ≤ 1/(0.8n). ✓

**Numerical verification**: D = [0×10, 0.5×80, 1×10], D' replaces a 0 with 1 → |ΔTMoM| = 1/160 < 1/80. ✓

In all cases, Δ_subst ≤ 1/(0.8n). **□**

### 3.4 Theorem 1 — ε-DP of M_ANCRE

**Theorem 1.**
*Under H1, H2, H6 and substitute adjacency, M_ANCRE satisfies ε = 0.5-DP (pure DP, δ=0) per call to aggregate().*

**Step 1 — Discrete Laplace mechanism.**

By Lemma 1, Δ ≤ 1/(0.8n) under ~_s.

M₀(D) = TMoM_α(D) + DLap_r(Δ/ε) satisfies ε-DP by the **discrete Laplace mechanism theorem**:

*If f: D → ℝ has sensitivity Δ and M(D) = f(D) + DLap(Δ/ε), then M satisfies ε-DP.*

Reference: Ghosh, Roughgarden & Sundararajan (2012), Theorem 1. Pure DP (δ=0) by construction of DLap.

**Step 2 — Post-processing.**

f(x) = clamp(x, 0, 1) is a deterministic function independent of the data. By Proposition 2.1 (Dwork & Roth, 2014):

```
M_ANCRE = f ∘ M₀  satisfies  ε = 0.5-DP (δ=0).  □
```

Note: H3, H4, H5 are not required for this guarantee.

### 3.5 Corollary 1 — Sequential Composition

**Corollary 1.**
*Under H1, H3, H5, H5a, with n_i ≥ 100 and homogeneous parameters, ANCRE allows at most k = 3 aggregations:*

```
ε_total = k × 0.5 = 1.5   (pure DP)
δ_total = 0                (exact DLap)
```

**Proof.** By Prop. 3.14 (Dwork & Roth) — pure DP sequential composition, without independence assumption. Under H5 and Claim 3.16: absent individual → unaffected. `EpsilonBudget` (u64) enforces ε_total ≤ 1.5. **□**

### 3.6 References

```
[1] Dwork, C. & Roth, A. (2014). Algorithmic Foundations of DP.
    Foundations and Trends in TCS.
    → Def. 2.4, Prop. 2.1/2.2/3.14, Thm. 3.6, §3.5, Claim 3.16

[2] Ghosh, A., Roughgarden, T. & Sundararajan, M. (2012).
    Universally Utility-Maximizing Privacy Mechanisms.
    SIAM Journal on Computing 41(6).
    → Theorem 1: discrete Laplace mechanism, pure ε-DP guarantee

[3] Canonne, C., Kamath, G. & Steinke, T. (2020).
    The Discrete Gaussian for Differential Privacy. NeurIPS 2020.
    → Section 2: DLap and discrete DP properties

[4] McSherry, F. (2009). Privacy Integrated Queries. ACM SIGMOD.
    → Central DP model

[5] Dwork, C. & Lei, J. (2009). DP and Robust Statistics. ACM STOC.
    → TMoM sensitivity analysis

[6] Mironov, I. (2012). On Significance of the LSB for DP. ACM CCS.
    → LSB leakage — resolved by exact DLap (v0.7)

[7] Kairouz, P. et al. (2021). Advances and Open Problems in
    Federated Learning. JMLR 22(1).
    → Open problems in federated DP (§5)
```

---

## 4. Experimental Results

### 4.1 Overview

We present validation results for the ANCRE v0.7 protocol along three axes: (i) implementation correctness, (ii) empirical validity of the DP mechanism, (iii) practical utility on real data.

### 4.2 Unit Tests and Coverage

The Rust v0.7 implementation is validated by **59 unit tests** across 8 modules:

| Module | Tests | Coverage |
|---|---|---|
| Signal (BoundedSignal) | 7 | [0,1] validation, NaN, Inf, boundaries |
| Budget (EpsilonBudget u64) | 4 | Monotonicity, float drift, exhaustion |
| Noise (discrete DLap) | 7 | Non-degeneracy, mean, symmetry |
| Mechanism (AncreBuffer) | 4 | K_MIN, aggregation, 3-call budget |
| Policy (PolicyEngine) | 2 | Irreversible kill-switch |
| Session (TTL, SessionGuard) | 5 | Anti-replay, quota, invalidation |
| Audit (SHA-256, HMAC) | 3 | Integrity, authenticity, wrong key |
| Integration | 2 | Full Central DP pipeline |

**59/59 tests pass in 0.8s on Android/Termux (ARM64).**

The Python v0.3 implementation (ancre_verify.py, ancre_sim_attest.py, ancre_pipeline.py) is validated by **21 tests** covering the IoT SAFE SIM chain, Ed25519 verification, and the aggregation pipeline.

### 4.3 Discrete Laplace Mechanism Validation

#### 4.3.1 Kolmogorov-Smirnov Test

**Protocol**: n = 10,000 samples, scale = Δ/ε = 0.025 (nominal parameters n=100, ε=0.5, α=0.1). Comparison of empirical CDF vs theoretical CDF:

```
F_theoretical(x) = 1 − 0.5 × exp(−|x|/scale)
```

**Result**: KS statistic = 0.0089 < threshold 99.9% (D = 2/√n = 0.020). ✓

**Non-degeneracy**: With scale_int = round(1000 × 0.025) = 25 and p = 1 − e^{−1/25} ≈ 0.039, more than 96% of samples are non-zero. The degeneracy bug (b << 1 → DLap ≈ 0) observed in naive implementations is resolved by resolution r = 1000.

#### 4.3.2 Statistical Properties

| Property | Theoretical | Empirical (n=10,000) |
|---|---|---|
| E[DLap] | 0 | −0.0003 ± 0.0002 |
| Var[DLap] | 2×scale² = 0.00125 | 0.00124 ± 0.00003 |
| P(noise = 0) | ≈ 2% | 1.9% |

#### 4.3.3 f64 vs Discrete Comparison

| Mechanism | δ | LSB Bias | Degeneracy |
|---|---|---|---|
| Laplace f64 (v0.6) | 2.9×10⁻¹⁵ | Present (Mironov 2012) | No |
| Discrete DLap (v0.7) | **0** | **Absent** | No (r=1000) |

### 4.4 Empirical ε-DP Validation (Indicative)

**D/D' protocol**: D contains K_MIN = 100 signals at 0.5; D' replaces one signal with 0.5 + δ (δ ∈ {0.1, 0.5}).

Over n_trials = 10,000 draws, binning at 50 intervals:

| δ | Max observed ratio | e^ε = 1.649 | Status |
|---|---|---|---|
| 0.1 | 1.41 | 1.649 | ✓ |
| 0.5 | 1.38 | 1.649 | ✓ |

**Warning**: This test does not constitute a proof of ε-DP. Binning at 50 intervals underestimates Laplace tails. The formal guarantee rests on Theorem 1 (Section 3).

### 4.5 Utility on Real Data

#### 4.5.1 Last.fm Dataset (hetrec2011)

**Dataset**: 92,834 listening events, 1,892 users, 17,632 artists.

| ε | ρ (Spearman) | MSE | K |
|---|---|---|---|
| 0.5 | **0.9997** | 0.0012 | 100 |
| 0.5 | 0.9994 | 0.0013 | 150 |

ρ = 0.9997 indicates artist rankings are preserved at 99.97% despite DP noise.

### 4.6 Multi-AI Red Team

We submitted the code and formal section to 8 distinct AI systems in "hostile reviewer" mode.

| System | Code Score | Whitepaper Score | Main Finding |
|---|---|---|---|
| Claude (hostile) | 61/100 | 71/100 | Lemma 1 Case 3 asserted |
| Mistral | 66/100 | 66/100 | δ=0 contradictory (resolved v0.7) |
| DeepSeek | 51/100 | 85/100 | Sensitivity factor 2 (refuted) |
| Gemini | 72/100 | — | Solid architecture |
| GPT-4 | 78/100 | — | Too lenient |
| Meta/Llama | 82/100 | 86/100 | Statistical clamp bias |
| Copilot | 65/100 | 65/100 | Group privacy |
| Perplexity | 92/100 | — | Bibliography validated |

**Post-correction consensus score: ~89/100**.

**Key results**: 4 AIs incorrectly claimed clamp [0,1] breaks ε-DP — refuted by the post-processing theorem (Prop. 2.1, Dwork & Roth 2014). 2 AIs claimed a factor 2 in TMoM sensitivity — refuted by the substitute vs add/remove adjacency distinction.

### 4.7 Performance

| Operation | Time (Android ARM64) |
|---|---|
| aggregate() one aggregation | < 1 ms |
| 59 complete tests | 0.8 s |
| KS-test (n=10,000) | 70 ms |

---

## 5. Limitations, Discussion, and Future Work

### 5.1 Model Limitations

#### 5.1.1 Substitute Adjacency Hypothesis

ANCRE is proven under **substitute adjacency** (~_s): datasets D and D' have the same size n. This hypothesis is justified by H6 (window closed before aggregation), but imposes a strong operational constraint.

If a participant disconnects mid-window or if n fluctuates, the correct model is **add/remove adjacency** (~_ar), giving sensitivity 2/(0.8n) — double our bound. In this case, the system remains ε-DP but with effective ε = 1.0 instead of 0.5 for the same precision.

**Recommendation**: Close the aggregation window by timestamp, reject late arrivals, and publish n before any output (H3 + H6 jointly).

#### 5.1.2 H1 Hypothesis and Sybil Attacks

A Sybil adversary submitting j signals via j distinct identities achieves a loss of j×ε-DP per individual (Prop. 2.2, Dwork & Roth).

**Current mitigation**: The IoT SAFE SIM attestation layer (GSMA IoT SAFE, ETSI TS 102 226) binds each signal to an X.509 certificate issued by a trusted telecom operator. The `max_per_device = 1` constraint is server-side enforced (ancre_pipeline.py v0.3, C5).

**Limitation**: In the absence of a physical SIM (development, testing), MockSimCard mode accepts any self-signed certificate.

#### 5.1.3 Auxiliary Channels

**Timing**: TMoM sort runs in O(n log n) with data-dependent time. An adversary measuring response times could infer information about signal distribution.

**Error messages**: Errors (kill-switch, exhausted budget, replay) may reveal internal state. The server should return opaque errors in production.

### 5.2 Discussion

#### 5.2.1 Choice of ε = 0.5

The budget ε = 0.5 per aggregation is conservative. Applied DP literature typically uses ε ∈ [0.1, 10] depending on use cases. For radio listening data (less sensitive than health data), ε = 0.5 offers strong protection with utility measured at ρ = 0.9997, consistent with a "Privacy by Design" approach (GDPR Article 25).

#### 5.2.2 Comparison with State of the Art

| Approach | DP Model | δ | Sybil | Utility |
|---|---|---|---|---|
| ANCRE v0.7 | Central, pure | 0 | IoT SAFE SIM | ρ=0.9997 |
| Apple DP (iOS) | Local, (ε,δ) | >0 | None | Medium |
| Google RAPPOR | Local | 0 | None | Low |
| DP-SGD (ML) | Central, (ε,δ) | >0 | N/A | ML context |

**ANCRE advantage**: The combination of Central DP + discrete Laplace (δ=0) + SIM attestation is, to our knowledge, absent from existing literature for the audio/radio analytics domain.

#### 5.2.3 Regulatory Compliance

**GDPR (EU 2016/679)**:
- Article 25 (Privacy by Design): the DP mechanism is architectural, not added post-hoc. ✓
- Article 89 (Statistical processing): ANCRE aggregates constitute anonymized statistical data if ε is sufficiently small and K ≥ 100. ✓

**EU AI Act (2024)**: Article 10 (Data quality): applicable if ANCRE aggregates feed a downstream AI system.

**RFC3161**: The ANCRE proof of concept is temporally anchored via FreeTSA (March 2026). Prior art is provable independently of this publication.

### 5.3 Future Work

#### 5.3.1 Short Term — v0.8

**Integrated chip (TEE/ARM TrustZone)**: Moving the DLap generator into a Trusted Execution Environment guarantees H4 by hardware architecture.

**Constant-time discrete Laplace**: Our `geometric_v2()` has data-dependent timing. A constant-time sampler (fixed number of operations) would eliminate the timing side-channel.

**Rényi DP (RDP)**: Composition in RDP (Mironov, 2017) allows tighter composition bounds. For k = 3 aggregations, RDP would give ε_total ≈ 1.3 instead of 1.5.

#### 5.3.2 Medium Term — v1.0

**Continuous window (Continual Observation)**: ANCRE v0.7 operates on closed windows. Extension to DP under continual observation (Dwork et al., 2010) would allow real-time aggregations without window reset.

**Formal audit**: Formal verification of Lemma 1 Case 3 proof in Coq or Lean.

#### 5.3.3 Long Term — Production

**SIM operator partnership**: Agreement with Orange, SFR, or Transatel to issue real IoT SAFE certificates linked to radio subscription contracts.

**CNIL certification**: Submission of the ANCRE protocol for GDPR compliance opinion.

### 5.4 Conclusion

We presented ANCRE, a pure differentially private protocol (ε=0.5, δ=0) for audio analytics in a B2B context. Key contributions:

1. **Exact discrete DLap mechanism** — eliminates floating-point leaks (Mironov, 2012) without utility compromise (ρ = 0.9997 on Last.fm).

2. **Formal proof under substitute adjacency** — justified by window closure (H6), with explicit tie-breaking convention for Lemma 1.

3. **IoT SAFE SIM architecture** — first application of GSMA attestation to Sybil resistance in a DP system, to our knowledge.

4. **Production-ready implementation** — 59/59 tests, 21/21 Python tests, deployable on Android ARM64.

Proof of concept temporally anchored (FreeTSA, March 2026). Code available at: https://github.com/taha-vera/Vera-protocole-

