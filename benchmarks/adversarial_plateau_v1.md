# VERA — Adversarial Reconstruction Floor v1.0
Status : Empirical benchmark — not a formal guarantee
Date : Mai 2026

## Adversarial model
- White-box statistical adversary
- Knows full structure of _apply_bias()
- Knows bias_range [0.88, 0.95] and nonlinear distribution
- Can launch N parallel sessions
- Aggregates all outputs freely

## Parameters
- S = 180.0
- N_sessions = 1000
- obs_per_session = 5
- Total observations = 5000
- noise_scale = 35.0 (radio profile)

## Results
| N observations | Reconstruction error |
|---|---|
| 5 (1 session) | ~9.66% |
| 500 (100 sessions) | ~3.41% |
| 5000 (1000 sessions) | 2.88% |

## What this does NOT claim
- Not an information-theoretic bound
- Not a formal DP guarantee
- Stronger adversary may achieve lower error

## What this confirms
- Reconstruction error does not converge to zero with N
- Plateau stable between N=500 and N=5000
- Irreducible noise floor exists under this adversarial model
