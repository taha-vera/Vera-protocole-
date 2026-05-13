cat > src/main.rs << 'RUSTEOF'
use rand::rngs::OsRng;
use rand::Rng;
use sha2::{Sha256, Digest};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::collections::{HashSet, HashMap};
use std::time::{Instant, Duration};

// ─────────────────────────────────────────────
// Invariants VERA — NON MODIFIABLES
// ─────────────────────────────────────────────
const K_MIN: usize = 100;
const EPSILON_SERVER: f64 = 0.5;  // seul ε — Central DP
const EPSILON_MAX: f64 = 1.5;     // 3 agrégations max
const MAX_BUFFER_SIGNALS: usize = 10_000;
const MAX_NONCES: usize = 100_000;
const NONCE_TTL_SECS: u64 = 300;

// ─────────────────────────────────────────────
// Bruit Laplace — Central DP uniquement
// ─────────────────────────────────────────────

fn laplace_noise(scale: f64) -> f64 {
    let u: f64 = OsRng.gen::<f64>() - 0.5;
    let safe = (1.0 - 2.0 * u.abs()).max(f64::MIN_POSITIVE);
    -scale * u.signum() * safe.ln()
}

// ─────────────────────────────────────────────
// INV-2 : BoundedSignal [0,1]
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct BoundedSignal(f64);

impl BoundedSignal {
    pub fn new(v: f64) -> Result<Self, String> {
        if v.is_nan() || v.is_infinite() {
            return Err(format!("NaN/Inf interdit : {}", v));
        }
        if !(0.0..=1.0).contains(&v) {
            return Err(format!("Hors [0,1] : {}", v));
        }
        Ok(Self(v))
    }
    pub fn value(&self) -> f64 { self.0 }
}

// ─────────────────────────────────────────────
// INV-1 : EpsilonBudget — monotone
// ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EpsilonBudget {
    epsilon_max: f64,
    epsilon_used: f64,
}

impl EpsilonBudget {
    pub fn new(max: f64) -> Self {
        assert!(max > 0.0);
        Self { epsilon_max: max, epsilon_used: 0.0 }
    }
    pub fn spend(&mut self, amount: f64) -> Result<(), String> {
        if amount <= 0.0 {
            return Err(format!("amount invalide : {}", amount));
        }
        if self.epsilon_used + amount > self.epsilon_max + 1e-12 {
            return Err(format!("Budget épuisé : {:.2}+{:.2} > {:.2}",
                self.epsilon_used, amount, self.epsilon_max));
        }
        self.epsilon_used += amount;
        Ok(())
    }
    pub fn remaining(&self) -> f64 { self.epsilon_max - self.epsilon_used }
    pub fn is_exhausted(&self) -> bool { self.remaining() <= 1e-12 }
    pub fn used(&self) -> f64 { self.epsilon_used }
}

// ─────────────────────────────────────────────
// Moyenne tronquée — sensibilité 1/(n*0.8)
// ─────────────────────────────────────────────

pub fn trimmed_mean(vals: &mut Vec<f64>, trim_fraction: f64) -> f64 {
    vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = vals.len();
    let trim = (n as f64 * trim_fraction).floor() as usize;
    let trimmed = &vals[trim..n - trim];
    trimmed.iter().sum::<f64>() / trimmed.len() as f64
}

// ─────────────────────────────────────────────
// INV-3 : AncreBuffer — Central DP
// Pas de bruit client — bruit uniquement dans aggregate()
// ─────────────────────────────────────────────

pub struct AncreBuffer {
    signals: Vec<BoundedSignal>,
    budget: EpsilonBudget,
}

impl AncreBuffer {
    pub fn new() -> Self {
        Self {
            signals: Vec::with_capacity(MAX_BUFFER_SIGNALS),
            budget: EpsilonBudget::new(EPSILON_MAX),
        }
    }

    pub fn push(&mut self, raw: f64) -> Result<(), String> {
        if self.signals.len() >= MAX_BUFFER_SIGNALS {
            return Err("Buffer plein".to_string());
        }
        // Central DP : pas de bruit ici
        let signal = BoundedSignal::new(raw)?;
        self.signals.push(signal);
        Ok(())
    }

    pub fn aggregate(&mut self) -> Result<f64, String> {
        if self.signals.len() < K_MIN {
            return Err(format!("K={} < {}", self.signals.len(), K_MIN));
        }

        let mut vals: Vec<f64> = self.signals.iter().map(|s| s.value()).collect();

        // Moyenne tronquée — sensibilité = 1/(n*0.8) pour signaux dans [0,1]
        let mean = trimmed_mean(&mut vals, 0.1);

        // Bruit Laplace — scale = sensibilité / ε_server
        let n = self.signals.len() as f64;
        let sensitivity = 1.0 / (n * 0.8);
        let scale = sensitivity / EPSILON_SERVER;

        self.budget.spend(EPSILON_SERVER)?;

        let noisy = (mean + laplace_noise(scale)).clamp(0.0, 1.0);
        self.signals.clear();
        Ok(noisy)
    }

    pub fn signal_count(&self) -> usize { self.signals.len() }
    pub fn budget_remaining(&self) -> f64 { self.budget.remaining() }
    pub fn budget_used(&self) -> f64 { self.budget.used() }
}

// ─────────────────────────────────────────────
// Kill-switch — Release/Acquire
// ─────────────────────────────────────────────

#[derive(Clone)]
pub struct PolicyEngine {
    killed: Arc<AtomicBool>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self { killed: Arc::new(AtomicBool::new(false)) }
    }
    pub fn kill(&self) { self.killed.store(true, Ordering::Release); }
    pub fn is_alive(&self) -> bool { !self.killed.load(Ordering::Acquire) }
    pub fn check(&self) -> Result<(), String> {
        if self.is_alive() { Ok(()) }
        else { Err("KILL-SWITCH ACTIVÉ".to_string()) }
    }
}

// ─────────────────────────────────────────────
// Audit chain — SHA-256 complet
// ─────────────────────────────────────────────

pub struct AuditChain {
    prev_hash: String,
    entries: Vec<String>,
}

impl AuditChain {
    pub fn new() -> Self {
        Self { prev_hash: "genesis".to_string(), entries: Vec::new() }
    }
    pub fn append(&mut self, aggregate: f64, k: usize, epsilon: f64) -> String {
        let mut h = Sha256::new();
        h.update(self.prev_hash.as_bytes());
        h.update(aggregate.to_bits().to_be_bytes());
        h.update(k.to_be_bytes());
        h.update(epsilon.to_bits().to_be_bytes());
        let hash = hex::encode(h.finalize().as_slice());
        self.prev_hash = hash.clone();
        self.entries.push(format!(
            "agg={:.4} k={} ε={:.2} hash={}", aggregate, k, epsilon, hash
        ));
        hash
    }
    pub fn len(&self) -> usize { self.entries.len() }
}

// ─────────────────────────────────────────────
// TtlNonceCache — anti-replay avec TTL
// ─────────────────────────────────────────────

pub struct TtlNonceCache {
    entries: HashMap<u64, Instant>,
    ttl: Duration,
    max_size: usize,
}

impl TtlNonceCache {
    pub fn new(ttl_secs: u64, max_size: usize) -> Self {
        Self {
            entries: HashMap::new(),
            ttl: Duration::from_secs(ttl_secs),
            max_size,
        }
    }
    pub fn check_and_consume(&mut self, nonce: u64) -> Result<(), String> {
        self.purge_expired();
        if self.entries.contains_key(&nonce) {
            return Err(format!("Replay détecté : nonce={}", nonce));
        }
        if self.entries.len() >= self.max_size {
            return Err("Nonce cache plein".to_string());
        }
        self.entries.insert(nonce, Instant::now());
        Ok(())
    }
    fn purge_expired(&mut self) {
        let ttl = self.ttl;
        self.entries.retain(|_, ts| ts.elapsed() < ttl);
    }
    pub fn len(&self) -> usize { self.entries.len() }
}

// ─────────────────────────────────────────────
// device_id — SHA-256 avec sel de session
// ─────────────────────────────────────────────

pub fn derive_device_id(credential: &[u8], session_salt: u64) -> u64 {
    let mut h = Sha256::new();
    h.update(&session_salt.to_be_bytes());
    h.update(credential);
    let hash = h.finalize();
    u64::from_be_bytes(hash[..8].try_into().unwrap())
}

// ─────────────────────────────────────────────
// SecureBufferV2 — Central DP complet
// ─────────────────────────────────────────────

pub struct SecureBufferV2 {
    inner: AncreBuffer,
    policy: PolicyEngine,
    nonces: TtlNonceCache,
    device_counts: HashMap<u64, usize>,
    max_per_device: usize,
    session_salt: u64,
    aggregation_count: usize,
}

impl SecureBufferV2 {
    pub fn new(policy: PolicyEngine) -> Self {
        Self {
            inner: AncreBuffer::new(),
            policy,
            nonces: TtlNonceCache::new(NONCE_TTL_SECS, MAX_NONCES),
            device_counts: HashMap::new(),
            max_per_device: 30,
            session_salt: OsRng.gen::<u64>(),
            aggregation_count: 0,
        }
    }

    pub fn push(&mut self, raw: f64, nonce: u64, credential: &[u8]) -> Result<(), String> {
        self.policy.check()?;

        if self.inner.signal_count() >= MAX_BUFFER_SIGNALS {
            return Err("Buffer plein".to_string());
        }
        if self.inner.is_budget_exhausted() {
            return Err("Budget serveur épuisé — plus d'agrégation possible".to_string());
        }

        self.nonces.check_and_consume(nonce)?;

        let device_id = derive_device_id(credential, self.session_salt);
        let count = self.device_counts.entry(device_id).or_insert(0);
        if *count >= self.max_per_device {
            return Err("Device quota atteint".to_string());
        }
        *count += 1;

        self.inner.push(raw)
    }

    pub fn aggregate(&mut self) -> Result<(f64, f64, usize), String> {
        self.policy.check()?;

        let agg = self.inner.aggregate()?;
        let eps_used = self.inner.budget_used();
        self.aggregation_count += 1;

        // Reset session
        self.device_counts.clear();
        self.session_salt = OsRng.gen::<u64>();

        Ok((agg, eps_used, self.aggregation_count))
    }

    pub fn budget_remaining(&self) -> f64 { self.inner.budget_remaining() }
    pub fn is_budget_exhausted(&self) -> bool { self.inner.is_budget_exhausted() }
    pub fn signal_count(&self) -> usize { self.inner.signal_count() }
}

impl AncreBuffer {
    pub fn is_budget_exhausted(&self) -> bool { self.budget.is_exhausted() }
}

// ─────────────────────────────────────────────
// Métriques
// ─────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct Metrics {
    pub signals_received: usize,
    pub signals_rejected: usize,
    pub aggregations_ok: usize,
    pub kills: usize,
    pub budget_exhausted: usize,
}

impl Metrics {
    pub fn new() -> Self { Self::default() }
    pub fn record_signal(&mut self, ok: bool) {
        if ok { self.signals_received += 1; } else { self.signals_rejected += 1; }
    }
    pub fn record_agg(&mut self, ok: bool) {
        if ok { self.aggregations_ok += 1; } else { self.budget_exhausted += 1; }
    }
    pub fn report(&self) -> String {
        format!("signals={} rejected={} agg_ok={} kills={} budget_exhausted={}",
            self.signals_received, self.signals_rejected,
            self.aggregations_ok, self.kills, self.budget_exhausted)
    }
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // INV-1
    proptest! {
        #[test]
        fn inv1_epsilon_monotone(amounts in prop::collection::vec(0.001f64..0.1, 1..20)) {
            let mut budget = EpsilonBudget::new(10.0);
            let mut prev = 0.0f64;
            for amount in amounts {
                if budget.spend(amount).is_ok() {
                    assert!(budget.epsilon_used >= prev);
                    prev = budget.epsilon_used;
                }
            }
        }

        #[test]
        fn inv1_never_exceeds_max(amounts in prop::collection::vec(0.001f64..1.0, 1..50)) {
            let mut budget = EpsilonBudget::new(1.5);
            for amount in amounts {
                let _ = budget.spend(amount);
                assert!(budget.epsilon_used <= 1.5 + 1e-10);
            }
        }

        // INV-2
        #[test]
        fn inv2_bounds_enforced(v in -10.0f64..10.0) {
            let result = BoundedSignal::new(v);
            if v >= 0.0 && v <= 1.0 { assert!(result.is_ok()); }
            else { assert!(result.is_err()); }
        }

        // TMoM sensibilité
        #[test]
        fn tmom_sensitivity(
            vals in prop::collection::vec(0.0f64..=1.0, 100..200),
            idx in 0usize..100,
            replacement in 0.0f64..=1.0
        ) {
            let mut v1 = vals.clone();
            let mut v2 = vals.clone();
            let len2 = v2.len();
            v2[idx % len2] = replacement;
            let m1 = trimmed_mean(&mut v1, 0.1);
            let m2 = trimmed_mean(&mut v2, 0.1);
            let n = vals.len() as f64;
            assert!((m1 - m2).abs() <= 1.0 / (n * 0.8) + 1e-9);
        }
    }

    // INV-3
    #[test]
    fn inv3_k_min_enforced() {
        let mut buf = AncreBuffer::new();
        for i in 0..50 { buf.push(0.1 + 0.001 * i as f64).ok(); }
        assert!(buf.aggregate().is_err());
    }

    #[test]
    fn inv3_aggregate_ok() {
        let mut buf = AncreBuffer::new();
        for i in 0..120 { buf.push(0.3 + 0.001 * i as f64).ok(); }
        let result = buf.aggregate();
        assert!(result.is_ok());
        let agg = result.unwrap();
        assert!(agg >= 0.0 && agg <= 1.0);
    }

    // Budget — 3 agrégations max
    #[test]
    fn budget_3_aggregations() {
        let mut buf = AncreBuffer::new();

        for session in 0..3 {
            for i in 0..120 {
                buf.push(0.5).ok();
                let _ = i + session;
            }
            assert!(buf.aggregate().is_ok());
        }

        for _ in 0..120 { buf.push(0.5).ok(); }
        assert!(buf.aggregate().is_err());
    }

    // Kill-switch
    #[test]
    fn kill_switch_irreversible() {
        let policy = PolicyEngine::new();
        assert!(policy.is_alive());
        policy.kill();
        assert!(!policy.is_alive());
    }

    #[test]
    fn kill_switch_blocks_push() {
        let policy = PolicyEngine::new();
        let mut buf = SecureBufferV2::new(policy.clone());
        policy.kill();
        assert!(buf.push(0.5, 1, b"dev").is_err());
    }

    // Anti-replay TTL
    #[test]
    fn ttl_replay_rejected() {
        let mut cache = TtlNonceCache::new(300, 1000);
        assert!(cache.check_and_consume(42).is_ok());
        assert!(cache.check_and_consume(42).is_err());
    }

    #[test]
    fn ttl_cache_bounded() {
        let mut cache = TtlNonceCache::new(300, 3);
        assert!(cache.check_and_consume(1).is_ok());
        assert!(cache.check_and_consume(2).is_ok());
        assert!(cache.check_and_consume(3).is_ok());
        assert!(cache.check_and_consume(4).is_err());
    }

    // device_id avec sel de session
    #[test]
    fn device_id_session_salt() {
        let id1 = derive_device_id(b"cred_A", 111);
        let id2 = derive_device_id(b"cred_A", 222);
        let id3 = derive_device_id(b"cred_A", 111);
        assert_ne!(id1, id2);
        assert_eq!(id1, id3);
    }

    // Audit chain
    #[test]
    fn audit_chain_tamper_detected() {
        let mut c1 = AuditChain::new();
        let mut c2 = AuditChain::new();
        c1.append(0.42, 120, 1.5);
        c2.append(0.99, 120, 1.5);
        let h1 = c1.append(0.30, 110, 1.5);
        let h2 = c2.append(0.30, 110, 1.5);
        assert_ne!(h1, h2);
    }

    // Tests statistiques DP
    #[test]
    fn laplace_mean_near_zero() {
        let n = 10_000;
        let samples: Vec<f64> = (0..n).map(|_| laplace_noise(1.0)).collect();
        let mean = samples.iter().sum::<f64>() / n as f64;
        assert!(mean.abs() < 0.05, "Moyenne={:.4}", mean);
    }

    #[test]
    fn laplace_variance_correct() {
        let n = 10_000;
        let scale = 1.0;
        let samples: Vec<f64> = (0..n).map(|_| laplace_noise(scale)).collect();
        let mean = samples.iter().sum::<f64>() / n as f64;
        let var = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
        assert!((var - 2.0).abs() < 0.5, "Variance={:.4}", var);
    }

    #[test]
    fn central_dp_no_client_noise() {
        // Vérifie que push() ne bruite PAS le signal
        let mut buf = AncreBuffer::new();
        buf.push(0.5).unwrap();
        assert_eq!(buf.signals[0].value(), 0.5);
    }

    #[test]
    fn aggregate_adds_noise() {
        // Vérifie que aggregate() bruite le résultat
        let trials = 500;
        let results: Vec<f64> = (0..trials).map(|_| {
            let mut buf = AncreBuffer::new();
            for _ in 0..120 { buf.push(0.5).ok(); }
            buf.aggregate().unwrap()
        }).collect();
        let mean = results.iter().sum::<f64>() / trials as f64;
        let var = results.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / trials as f64;
        assert!(var > 0.0, "Aucun bruit dans aggregate()");
        assert!((mean - 0.5).abs() < 0.05, "Bruit biaisé : mean={:.4}", mean);
    }

    // Intégration complète
    #[test]
    fn integration_central_dp() {
        let policy = PolicyEngine::new();
        let mut buf = SecureBufferV2::new(policy);
        let mut chain = AuditChain::new();
        let mut metrics = Metrics::new();

        for session in 0..3 {
            for i in 0..120 {
                let cred = format!("dev_{}_{}", session, i);
                match buf.push(0.5, session * 1000 + i as u64, cred.as_bytes()) {
                    Ok(_) => metrics.record_signal(true),
                    Err(_) => metrics.record_signal(false),
                }
            }
            match buf.aggregate() {
                Ok((agg, eps, n)) => {
                    metrics.record_agg(true);
                    chain.append(agg, 120, eps);
                    println!("Session {}: agg={:.4} eps={:.2} n={}", session, agg, eps, n);
                }
                Err(e) => { metrics.record_agg(false); println!("Err: {}", e); }
            }
        }

        assert_eq!(metrics.aggregations_ok, 3);
        assert_eq!(chain.len(), 3);
        assert!(buf.is_budget_exhausted());

        println!("{}", metrics.report());
    }
}

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────

fn main() {
    println!("ANCRE v0.5 — Central DP\n");
    println!("Modèle : bruit uniquement côté serveur dans aggregate()");
    println!("Garantie : chaque agrégation est {:.1}-DP\n", EPSILON_SERVER);

    let policy = PolicyEngine::new();
    let mut buf = SecureBufferV2::new(policy);
    let mut chain = AuditChain::new();
    let mut metrics = Metrics::new();

    for session in 0..4 {
        println!("--- Session {} (budget restant: {:.1}) ---",
            session, buf.budget_remaining());

        for i in 0..120 {
            let cred = format!("dev_{}_{}", session, i);
            match buf.push(0.5, session * 10000 + i as u64, cred.as_bytes()) {
                Ok(_) => metrics.record_signal(true),
                Err(e) => { metrics.record_signal(false); println!("  Rejet: {}", e); }
            }
        }

        match buf.aggregate() {
            Ok((agg, eps, n)) => {
                metrics.record_agg(true);
                let hash = chain.append(agg, 120, eps);
                println!("  ✅ Agrégat={:.4} ε_used={:.2} n={}", agg, eps, n);
                println!("  🔗 Hash={}", &hash[..16]);
            }
            Err(e) => {
                metrics.record_agg(false);
                println!("  ❌ {}", e);
            }
        }
    }

    println!("\n📊 {}", metrics.report());
    println!("🔗 Audit chain: {} entries", chain.len());
}
RUSTEOF
cargo test 2>&1 | tail -5