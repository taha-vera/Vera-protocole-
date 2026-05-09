"""
VERA Benchmark — Last.fm hetrec2011
=====================================
Test sur données réelles : 92834 écoutes, 2000 users, ~1800 artistes
Métriques : Spearman ρ, K effectif, latence, royalties calculables
"""
import sys, os, time, hashlib, math, random
sys.path.insert(0, os.path.expanduser("~/vera"))

# ── Chargement données ────────────────────────────────────────────────────────
def load_lastfm(path):
    data = {}
    with open(path) as f:
        next(f)
        for line in f:
            uid, aid, w = line.strip().split('\t')
            data.setdefault(aid, []).append((uid, int(w)))
    return data

# ── Laplace noise ─────────────────────────────────────────────────────────────
def laplace_noise(scale):
    # Inverse CDF stable : clipping pour éviter log(0)
    u = random.random()
    u = max(1e-10, min(1-1e-10, u))  # clipping numérique
    u = u - 0.5
    return -scale * (1 if u >= 0 else -1) * math.log(1 - 2*abs(u))

# ── Trimmed mean ──────────────────────────────────────────────────────────────
def trimmed_mean(values, beta=0.1):
    s = sorted(values)
    k = max(1, int(len(s)*beta))
    t = s[k:-k] if k < len(s)//2 else s
    return sum(t)/len(t)

# ── Spearman ──────────────────────────────────────────────────────────────────
def spearman(x, y):
    def rank(v):
        sv = sorted(range(len(v)), key=lambda i: v[i])
        r = [0]*len(v)
        for i,j in enumerate(sv): r[j] = i+1
        return r
    rx, ry = rank(x), rank(y)
    n = len(rx)
    d2 = sum((a-b)**2 for a,b in zip(rx,ry))
    return 1 - 6*d2/(n*(n**2-1))

# ── Pipeline VERA ─────────────────────────────────────────────────────────────
def vera_pipeline(artist_data, epsilon_client=1.0, epsilon_server=0.5, k_min=100):
    results = []
    royalties_ok = 0
    royalties_nok = 0

    for aid, listeners in artist_data.items():
        k = len(listeners)
        if k < k_min:
            royalties_nok += 1
            continue
        royalties_ok += 1

        # Signal brut normalisé [0,1]
        weights = [w for _,w in listeners]
        max_w = max(weights) if max(weights) > 0 else 1
        norm_w = [w/max_w for w in weights]

        # Vrai signal = trimmed mean normalisé (comparaison équitable)
        true_signal = trimmed_mean(norm_w)

        # LDP : bruit Laplace avec sensibilité correcte = 1/K
        sensitivity = 1.0 / k
        b_client = sensitivity / epsilon_client
        noised = [w + laplace_noise(b_client) for w in norm_w]

        # Agrégation trimmed mean
        agg = trimmed_mean(noised)

        # Bruit serveur
        b_server = sensitivity / epsilon_server
        final = agg + laplace_noise(b_server)

        results.append((aid, true_signal, final, k))

    return results, royalties_ok, royalties_nok

# ── Main ──────────────────────────────────────────────────────────────────────
print("\n" + "="*60)
print("VERA BENCHMARK — Last.fm hetrec2011 (données réelles)")
print("="*60)

path = os.path.expanduser("~/Vera-protocole-clean/lastfm_data/user_artists.dat")
print("Chargement des données...")
t0 = time.time()
data = load_lastfm(path)
load_time = time.time()-t0

print(f"  {sum(len(v) for v in data.values()):,} écoutes chargées")
print(f"  {len(data):,} artistes uniques")
print(f"  Temps chargement : {load_time:.2f}s")

print("\nExécution pipeline VERA...")
t1 = time.time()
results, ok, nok = vera_pipeline(data)
pipeline_time = time.time()-t1

print(f"  Artistes K≥100 (royalties calculables) : {ok}")
print(f"  Artistes K<100 (exclus K-anonymité)    : {nok}")
print(f"  Couverture royalties : {ok/(ok+nok)*100:.1f}%")
print(f"  Latence pipeline : {pipeline_time*1000:.1f}ms pour {ok+nok} artistes")
print(f"  Latence par artiste : {pipeline_time*1000/(ok+nok):.3f}ms")

if results:
    true_signals = [r[1] for r in results]
    vera_signals = [r[2] for r in results]
    rho = spearman(true_signals, vera_signals)
    k_values = [r[3] for r in results]
    k_mean = sum(k_values)/len(k_values)
    k_min_eff = min(k_values)

    print(f"\nQualité du signal :")
    print(f"  Spearman ρ (signal VERA vs réel) : {rho:.4f}")
    print(f"  K effectif moyen : {k_mean:.0f} utilisateurs")
    print(f"  K effectif minimum : {k_min_eff} utilisateurs")

    sla_ok = rho >= 0.90
    print(f"\n  SLA Spearman ≥ 0.90 : {'✓ SATISFAIT' if sla_ok else '✗ ÉCHOUÉ'} (ρ={rho:.4f})")

print("\n" + "="*60 + "\n")
