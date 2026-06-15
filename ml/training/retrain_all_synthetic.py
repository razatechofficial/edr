#!/usr/bin/env python3
"""Retrain all synthetic-only models with real-data-informed generation."""
from __future__ import annotations
import json, logging, sys
from pathlib import Path
import numpy as np
import lightgbm as lgb
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parent))
from utils.evaluation import evaluate_binary_classifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(name)s: %(message)s")
logger = logging.getLogger("retrain_all")
SEED = 42
OUTPUT = Path(__file__).resolve().parent / "output"
OUTPUT.mkdir(parents=True, exist_ok=True)

# ── RANSOMWARE (10 features) ──────────────────────────────────────────────
def generate_ransomware(n=40000):
    rng = np.random.RandomState(SEED)
    X, y = [], []
    for _ in range(n):
        is_mal = rng.random() < 0.3
        f = np.zeros(10, dtype=np.float32)
        if is_mal:
            f[0] = rng.uniform(200, 1000)        # file_modifications
            f[1] = rng.uniform(0.7, 1.0)          # encryption_speed
            f[2] = 1.0 if rng.random() < 0.9 else 0.0  # ransom_note
            f[3] = rng.uniform(0.5, 1.0)          # decoy_files
            f[4] = 1.0 if rng.random() < 0.8 else 0.0  # shadow_copy_del
            f[5] = 1.0 if rng.random() < 0.7 else 0.0  # backup_removal
            f[6] = rng.uniform(0.4, 1.0)          # network_shares
            f[7] = rng.uniform(0.5, 1.0)          # persistence
            f[8] = rng.uniform(0.3, 1.0)          # priv_escalation
            f[9] = rng.uniform(0.6, 1.0)          # crypto_usage
        else:
            f[:] = rng.uniform(0, 0.15, 10)
        X.append(f)
        y.append(1 if is_mal else 0)
    return np.array(X), np.array(y)

# ── LOLBIN (64 features) ──────────────────────────────────────────────────
def generate_lolbin(n=40000):
    rng = np.random.RandomState(SEED)
    X, y = [], []
    for _ in range(n):
        is_mal = rng.random() < 0.3
        f = np.zeros(64, dtype=np.float32)
        if is_mal:
            f[0] = rng.uniform(3, 8)              # process depth
            f[1] = rng.uniform(0.7, 1.0)          # parent rarity
            f[2] = rng.uniform(0, 0.3)            # unsigned
            f[3] = 1.0 if rng.random() < 0.8 else 0.0  # exec from temp
            f[4] = rng.uniform(0.6, 1.0)          # network conn
            f[5] = rng.uniform(0.5, 1.0)          # encoded args
            f[6] = rng.uniform(0.4, 1.0)          # LOLBin match
            f[7:64] = rng.uniform(0.1, 0.7, 57)
        else:
            f[0] = rng.uniform(1, 3)
            f[1] = rng.uniform(0, 0.2)
            f[2] = rng.uniform(0.7, 1.0)
            f[3:7] = rng.uniform(0, 0.1, 4)
            f[7:64] = rng.uniform(0, 0.15, 57)
        X.append(f)
        y.append(1 if is_mal else 0)
    return np.array(X), np.array(y)

# ── SUPPLY CHAIN (32 features) ────────────────────────────────────────────
def generate_supply_chain(n=40000):
    rng = np.random.RandomState(SEED)
    X, y = [], []
    for _ in range(n):
        is_mal = rng.random() < 0.3
        f = np.zeros(32, dtype=np.float32)
        if is_mal:
            f[0] = rng.randint(1, 180)            # young package
            f[1] = rng.lognormal(2, 1)            # low downloads
            f[2] = rng.random() * 0.3             # low author rep
            f[3] = rng.randint(0, 3)              # few deps
            f[4] = rng.uniform(0.5, 1.0)          # obfuscated
            f[5] = rng.uniform(0.3, 1.0)          # suspicious imports
            f[6] = rng.uniform(0.2, 0.8)          # encoded strings
            f[7] = 1.0 if rng.random() < 0.7 else 0.0  # install hook
            f[8] = 1.0 if rng.random() < 0.6 else 0.0  # network call
            f[9] = rng.uniform(0.3, 1.0)          # entropy
            f[10] = rng.uniform(0.2, 1.0)         # domain sim
            f[11] = rng.randint(0, 5)             # typosquat
            f[12] = rng.random() < 0.5            # crypto miner
            f[13] = rng.uniform(0.1, 0.8)         # data exfil
            f[14] = rng.randint(0, 10)            # version diff
            f[15:32] = rng.uniform(0, 0.5, 17)
        else:
            f[0] = rng.randint(100, 3650)
            f[1] = rng.lognormal(8, 2)
            f[2] = rng.uniform(0.7, 1.0)
            f[3] = rng.randint(5, 50)
            f[4] = rng.uniform(0, 0.2)
            f[5] = rng.uniform(0, 0.1)
            f[6] = rng.uniform(0, 0.05)
            f[7:15] = 0.0
            f[15:32] = rng.uniform(0, 0.1, 17)
        X.append(f)
        y.append(1 if is_mal else 0)
    return np.array(X), np.array(y)

# ── IDENTITY THREAT (24 features) ─────────────────────────────────────────
def generate_identity(n=40000):
    rng = np.random.RandomState(SEED)
    X, y = [], []
    for _ in range(n):
        is_threat = rng.random() < 0.3
        f = np.zeros(24, dtype=np.float32)
        if is_threat:
            f[0:6] = rng.uniform(0.5, 1.0, 6)    # login time, auth type, role, geo, failed auth, escalation
            f[6:24] = rng.uniform(0.2, 0.8, 18)
        else:
            f[0:6] = rng.uniform(0, 0.2, 6)
            f[6:24] = rng.uniform(0, 0.15, 18)
        X.append(f)
        y.append(1 if is_threat else 0)
    return np.array(X), np.array(y)

# ── AI-GEN (48 features) ──────────────────────────────────────────────────
def generate_aigen(n=40000):
    rng = np.random.RandomState(SEED)
    X, y = [], []
    for _ in range(n):
        is_ai = rng.random() < 0.3
        f = np.zeros(48, dtype=np.float32)
        if is_ai:
            f[0] = rng.uniform(0.6, 1.0)          # low perplexity
            f[1] = rng.uniform(0.04, 0.2)         # low burstiness
            f[2] = rng.uniform(0.5, 1.0)          # repetition
            f[3] = rng.uniform(0.4, 1.0)          # generic phrasing
            f[4] = rng.uniform(0.3, 0.9)          # template match
            f[5:48] = rng.uniform(0.2, 0.8, 43)
        else:
            f[0] = rng.uniform(0, 0.4)
            f[1] = rng.uniform(0.3, 1.0)
            f[2] = rng.uniform(0, 0.3)
            f[3] = rng.uniform(0, 0.3)
            f[4] = rng.uniform(0, 0.2)
            f[5:48] = rng.uniform(0, 0.15, 43)
        X.append(f)
        y.append(1 if is_ai else 0)
    return np.array(X), np.array(y)

MODELS = [
    ("ransomware", generate_ransomware, 10),
    ("lolbin_detector", generate_lolbin, 64),
    ("supply_chain_detector", generate_supply_chain, 32),
    ("identity_threat", generate_identity, 24),
    ("aigen_detector", generate_aigen, 48),
]

def fix_onnx(onnx_path):
    """Post-process ONNX: keep only TreeEnsembleClassifier, add Gather for class 1 → score."""
    import onnx
    from onnx import helper, TensorProto
    m = onnx.load(str(onnx_path))
    ip = m.graph.input[0].name
    # Find TreeEnsembleClassifier
    tree_node = prob_tensor = None
    for n in m.graph.node:
        if n.op_type == "TreeEnsembleClassifier":
            tree_node = n
            prob_tensor = n.output[1]  # probability_tensor
            break
    if not tree_node:
        logger.warning("No TreeEnsembleClassifier found, skipping ONNX fix")
        return
    # Keep only TreeEnsembleClassifier node
    while len(m.graph.node) > 0:
        m.graph.node.pop()
    m.graph.node.extend([tree_node])
    while len(m.graph.output) > 0:
        m.graph.output.pop()
    # Add Gather for class 1 (probabilities are [N, 2])
    idx_arr = np.array([1], dtype=np.int64)
    init = helper.make_tensor("gather_idx", TensorProto.INT64, [1], idx_arr)
    m.graph.initializer.extend([init])
    gather = helper.make_node("Gather", [prob_tensor, "gather_idx"], ["score"], axis=1)
    m.graph.node.extend([gather])
    score_vi = helper.make_tensor_value_info("score", TensorProto.FLOAT, [None, 1])
    m.graph.output.extend([score_vi])
    onnx.save(m, str(onnx_path))

def train_model(name, gen_fn, dim, n=40000):
    logger.info("=== %s ===", name)
    X, y = gen_fn(n)
    logger.info("  %d samples (%d dim, %.1f%% positive)", len(y), dim, y.mean() * 100)
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=SEED)
    model = lgb.LGBMClassifier(
        n_estimators=500, learning_rate=0.03, max_depth=8,
        num_leaves=64, subsample=0.8, colsample_bytree=0.8,
        reg_alpha=0.5, reg_lambda=0.5, min_child_samples=20,
        class_weight="balanced", random_state=SEED, verbose=-1, n_jobs=-1,
    )
    model.fit(X_tr, y_tr, eval_set=[(X_te, y_te)], eval_metric="auc")
    y_pred = model.predict(X_te)
    y_prob = model.predict_proba(X_te)[:, 1]
    evaluate_binary_classifier(y_te, y_pred, y_prob, model_name=name, output_dir=OUTPUT)
    # ONNX
    onnx_path = OUTPUT / f"{name}.onnx"
    logger.info("Exporting ONNX → %s", onnx_path)
    onnx_model = onnxmltools.convert_lightgbm(
        model, initial_types=[("input", FloatTensorType([None, dim]))],
        target_opset=15, zipmap=False,
    )
    onnxmltools.utils.save_model(onnx_model, str(onnx_path))
    fix_onnx(onnx_path)
    # Validate
    import onnxruntime as ort
    sess = ort.InferenceSession(str(onnx_path))
    out_names = [o.name for o in sess.get_outputs()]
    logger.info("  ONNX outputs: %s", out_names)
    assert out_names == ["score"], f"Expected [score], got {out_names}"
    dummy = X_te[:5].astype(np.float32)
    scores = sess.run(None, {"input": dummy})[0].flatten()
    logger.info("  Score sample: %s", scores[:5].tolist())
    assert all(0 <= s <= 1 for s in scores), f"Scores out of range: {scores}"
    logger.info("  ONNX size: %d bytes ✓", onnx_path.stat().st_size)

if __name__ == "__main__":
    for name, gen_fn, dim in MODELS:
        train_model(name, gen_fn, dim)
    logger.info("All 5 models retrained!")
