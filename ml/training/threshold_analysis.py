#!/usr/bin/env python3
"""Analyze threshold optimization and find required datasets for production targets.

Targets: AUC>=0.95, Precision>=0.98, Recall>=0.98, F1>=0.98, FPR<=0.1%
"""
from __future__ import annotations
import csv, json, logging, math, sys, zipfile
from datetime import datetime
from pathlib import Path
import numpy as np
import onnxruntime as ort
from sklearn.metrics import roc_auc_score, precision_score, recall_score, f1_score, precision_recall_curve, roc_curve

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("threshold_analysis")
SEED = 42
np.random.seed(SEED)

MODELS_DIR = Path(__file__).resolve().parent.parent.parent / "models"
DATASETS_DIR = MODELS_DIR.parent / "ml" / "datasets"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from utils.features import RatC2FeatureEncoder, NetworkFeatureEncoder

# ---------- data loaders (simplified, from eval_all_models) ----------
def load_ember():
    ember_dir = DATASETS_DIR / "ember2018"
    X = np.fromfile(ember_dir / "X_test.dat", dtype=np.float32).reshape(-1, 2381)
    y_raw = np.fromfile(ember_dir / "y_test.dat", dtype=np.float32)
    y = np.where(np.abs(y_raw - 1.0) < 0.5, 1, 0).astype(np.int32)
    X_311 = np.zeros((len(X), 311), dtype=np.float32)
    for i in range(len(X)):
        x = X[i]
        X_311[i, 0:256] = x[0:256]
        X_311[i, 256:272] = x[256:272]
        X_311[i, 272] = x[272]
        X_311[i, 273] = np.float32(math.log1p(max(1, int(2**x[273] - 1))))
        X_311[i, 274:282] = x[274:282]
        X_311[i, 282] = x[292]
        X_311[i, 283] = x[295]
        X_311[i, 284] = x[296]
        X_311[i, 285] = x[298]
        X_311[i, 286] = x[299]
        X_311[i, 287] = x[300]
        X_311[i, 288] = x[302]
        X_311[i, 289] = x[303]
        X_311[i, 290:306] = x[304:320]
        X_311[i, 306] = x[321]
        X_311[i, 307] = x[322]
        X_311[i, 308] = x[323]
        X_311[i, 309] = x[324]
        X_311[i, 310] = x[325]
    return X_311, y

def load_cicids():
    csv_dir = DATASETS_DIR / "cic-ids2017" / "csv"
    files = list(sorted(csv_dir.glob("*.csv")))[:6]
    encoder = NetworkFeatureEncoder()
    X, y = [], []
    for fpath in files:
        with open(fpath) as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    dport = int(row.get(" Destination Port", row.get("Destination Port", 0)))
                    sport = int(row.get(" Source Port", row.get("Source Port", 0)))
                    proto = str(row.get(" Protocol", row.get("Protocol", ""))).lower()
                    label = (row.get(" Label") or row.get("Label") or "").strip()
                    ts_str = (row.get(" Timestamp") or row.get("Timestamp") or "").strip()
                    dest_ip = (row.get(" Destination IP") or row.get("Destination IP") or row.get(" Dst IP") or row.get("Dst IP") or "").strip()
                    src_ip = (row.get(" Source IP") or row.get("Source IP") or row.get(" Src IP") or row.get("Src IP") or "").strip()
                    tod = 0.0
                    if ts_str:
                        try:
                            dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                            tod = (dt.hour*3600 + dt.minute*60 + dt.second) / 86400.0
                        except:
                            try:
                                dt = datetime.strptime(ts_str[:19], "%d/%m/%Y %H:%M:%S")
                                tod = (dt.hour*3600 + dt.minute*60 + dt.second) / 86400.0
                            except:
                                pass
                    conn = {
                        "src_port": sport, "dest_port": dport,
                        "protocol": proto, "timestamp": tod,
                        "domain": "", "dest_ip": dest_ip,
                    }
                except: continue
                vec = encoder.encode(conn)
                X.append(vec)
                y.append(0 if label.lower() == "benign" else 1)
    X = np.array(X, dtype=np.float32)
    y = np.array(y, dtype=np.int32)
    rng = np.random.RandomState(SEED)
    ben_idx = rng.permutation(np.where(y == 0)[0])[:50000]
    atk_idx = rng.permutation(np.where(y == 1)[0])[:50000]
    idx = np.concatenate([ben_idx, atk_idx])
    return X[idx], y[idx]

def load_malmem():
    from train_memory_injection import _raw_to_features
    zip_path = DATASETS_DIR / "edr_datasets" / "cic-malmem-2022.zip"
    with zipfile.ZipFile(zip_path) as z:
        csv_name = [n for n in z.namelist() if n.endswith(".csv")][0]
        with z.open(csv_name) as f:
            reader = csv.DictReader(f.read().decode().splitlines())
            rows = list(reader)
    X, y = [], []
    for row in rows:
        cls = (row.get("Class") or "").strip().lower()
        parsed = {}
        for k, v in row.items():
            if k and k not in ("Category", "Class", "Label"):
                vc = v.strip().strip('"').strip("'") if v else "0"
                try: parsed[k] = float(vc) if vc else 0.0
                except: parsed[k] = 0.0
        X.append(_raw_to_features(parsed))
        y.append(1 if cls in ("malware", "malicious", "1") else 0)
    X = np.array(X, dtype=np.float32)
    y = np.array(y, dtype=np.int32)
    rng = np.random.RandomState(SEED)
    perm = rng.permutation(len(y))
    return X[perm[:20000]], y[perm[:20000]]

def load_ctu13():
    encoder = RatC2FeatureEncoder()
    scenarios = [
        ("ctu13_scenario_01_Neris", "bidirectional_capture20110810.binetflow"),
        ("ctu13_scenario_02_Neris", "bidirectional_capture20110811.binetflow"),
        ("ctu13_scenario_09_Neris", "bidirectional_capture20110817.binetflow"),
    ]
    X, y = [], []
    for sdir, fname in scenarios:
        fpath = DATASETS_DIR / "rat" / sdir / fname
        if not fpath.exists(): continue
        with open(fpath) as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    label = (row.get("Label") or "")
                    dport = int(row.get("Dport") or 0)
                    sport = int(row.get("Sport") or 0)
                    dur = float(row.get("Dur") or 0)
                    proto = (row.get("Proto") or "").lower().strip()
                    dst_addr = row.get("DstAddr") or ""
                    tot = int(row.get("TotBytes") or 0)
                    src_b = int(row.get("SrcBytes") or 0)
                    st = row.get("StartTime") or ""
                except: continue
                is_src_int = (dst_addr or "").startswith(("147.32.84.", "147.32.85."))
                bi = src_b if is_src_int else tot - src_b
                bo = tot - src_b if is_src_int else src_b
                tod = 0.0
                if st:
                    try:
                        dt = datetime.strptime(st.strip(), "%Y/%m/%d %H:%M:%S.%f")
                        tod = (dt.hour*3600 + dt.minute*60 + dt.second) / 86400.0
                    except: pass
                conn = {"src_port": sport, "dest_port": dport, "protocol": proto,
                        "timestamp": tod, "domain": "", "dest_ip": dst_addr,
                        "bytes_in": max(0, bi), "bytes_out": max(0, bo),
                        "duration_ms": int(dur*1000), "ja3": "", "sni": ""}
                vec = encoder.encode(conn)
                is_bot = bool(label and ("flow=from-botnet" in label.lower() or "flow=botnet" in label.lower() or "flow=cc" in label.lower()))
                X.append(vec)
                y.append(1 if is_bot else 0)
    X = np.array(X, dtype=np.float32)
    y = np.array(y, dtype=np.int32)
    rng = np.random.RandomState(SEED)
    ben_idx = rng.permutation(np.where(y == 0)[0])[:100000]
    atk_idx = rng.permutation(np.where(y == 1)[0])[:50000]
    idx = np.concatenate([ben_idx, atk_idx])
    return X[idx], y[idx]

# ---------- threshold optimization ----------
MODEL_CONFIGS = [
    ("pe_classifier", load_ember, 0.80, 311, False),
    ("network_lgbm", load_cicids, 0.50, 19, False),
    ("memory_injection", load_malmem, 0.70, 32, False),
    ("rat_c2_detector", load_ctu13, 0.50, 22, False),
]

def find_best_threshold(y_true, scores):
    precisions, recalls, thresholds = precision_recall_curve(y_true, scores)
    f1s = 2 * precisions * recalls / (precisions + recalls + 1e-10)
    best_idx = np.argmax(f1s)
    best_thr = thresholds[best_idx] if best_idx < len(thresholds) else 0.5
    return best_thr, f1s[best_idx], precisions[best_idx], recalls[best_idx]

def evaluate_at_threshold(y_true, scores, thr):
    pred = (scores >= thr).astype(int)
    tn = ((pred == 0) & (y_true == 0)).sum()
    fp = ((pred == 1) & (y_true == 0)).sum()
    fn = ((pred == 0) & (y_true == 1)).sum()
    tp = ((pred == 1) & (y_true == 1)).sum()
    fpr = fp / max(tn + fp, 1)
    prec = tp / max(tp + fp, 1)
    rec = tp / max(tp + fn, 1)
    f1 = 2 * prec * rec / max(prec + rec, 1e-10)
    auc = roc_auc_score(y_true, scores)
    return {"thr": thr, "auc": auc, "precision": prec, "recall": rec, "f1": f1, "fpr": fpr,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn, "n": len(y_true)}

logger.info("%s", "=" * 90)
logger.info("  THRESHOLD OPTIMIZATION: PRODUCTION TARGET ANALYSIS")
logger.info("%s", "=" * 90)

results = {}
for name, loader, config_thr, dim, is3d in MODEL_CONFIGS:
    logger.info("")
    logger.info("--- %s ---", name)
    X, y = loader()
    logger.info("  Loaded %d samples (%.1f%% attack)", len(y), y.mean()*100)
    # Split
    from sklearn.model_selection import train_test_split
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.3, random_state=SEED, stratify=y)
    sess = ort.InferenceSession(str(MODELS_DIR / f"{name}.onnx"))
    inp = sess.get_inputs()[0].name
    scores = sess.run(None, {inp: X_te.astype(np.float32)})[0].flatten()
    
    # Current config threshold
    cur = evaluate_at_threshold(y_te, scores, config_thr)
    
    # Best F1 threshold
    best_thr, best_f1, best_prec, best_rec = find_best_threshold(y_te, scores)
    best = evaluate_at_threshold(y_te, scores, best_thr)
    
    # Find threshold for recall >= 0.98
    rec_thrs = np.linspace(0.01, 0.99, 198)
    rec98_thr = None
    for thr in rec_thrs:
        r = evaluate_at_threshold(y_te, scores, thr)
        if r["recall"] >= 0.98 and r["precision"] >= 0.98 and r["fpr"] <= 0.01:
            rec98_thr = thr
            break
    
    # Find threshold for FPR <= 0.1%
    fpr_thrs = np.linspace(0.01, 0.99, 198)
    fpr01_thr = None
    for thr in np.flip(fpr_thrs):
        r = evaluate_at_threshold(y_te, scores, thr)
        if r["fpr"] <= 0.001:  # 0.1%
            fpr01_thr = thr
            break
    
    logger.info("  Current (config thr=%.2f): AUC=%.4f Prec=%.4f Rec=%.4f F1=%.4f FPR=%.4f%%",
                cur["thr"], cur["auc"], cur["precision"], cur["recall"], cur["f1"], cur["fpr"]*100)
    logger.info("  Best F1 (thr=%.4f):     AUC=%.4f Prec=%.4f Rec=%.4f F1=%.4f FPR=%.4f%%",
                best["thr"], best["auc"], best["precision"], best["recall"], best["f1"], best["fpr"]*100)
    
    if rec98_thr:
        r98 = evaluate_at_threshold(y_te, scores, rec98_thr)
        logger.info("  Rec>=98%%, Prec>=98%%, FPR<=1%% (thr=%.4f): AUC=%.4f Prec=%.4f Rec=%.4f F1=%.4f FPR=%.4f%% ✓",
                    rec98_thr, r98["auc"], r98["precision"], r98["recall"], r98["f1"], r98["fpr"]*100)
    else:
        logger.info("  FAIL: No threshold achieves Rec>=98%% AND Prec>=98%% simultaneously")
    
    if fpr01_thr:
        f01 = evaluate_at_threshold(y_te, scores, fpr01_thr)
        logger.info("  FPR<=0.1%% (thr=%.4f):       AUC=%.4f Prec=%.4f Rec=%.4f F1=%.4f FPR=%.4f%%",
                    fpr01_thr, f01["auc"], f01["precision"], f01["recall"], f01["f1"], f01["fpr"]*100)
    
    # Check if targets achievable with this model
    targets_achievable = []
    for thr in np.linspace(0.01, 0.99, 198):
        r = evaluate_at_threshold(y_te, scores, thr)
        if r["precision"] >= 0.98 and r["recall"] >= 0.98 and r["fpr"] <= 0.001:
            targets_achievable.append((thr, r))
    
    if targets_achievable:
        best_t = max(targets_achievable, key=lambda x: x[1]["f1"])
        logger.info("  ★ PRODUCTION TARGETS ACHIEVABLE at thr=%.4f (F1=%.4f)", best_t[0], best_t[1]["f1"])
    else:
        logger.info("  ★ PRODUCTION TARGETS NOT ACHIEVABLE with current model — needs retraining")
    
    results[name] = {"cur": cur, "best": best, "achievable": len(targets_achievable) > 0}

logger.info("")
logger.info("=" * 90)
logger.info("  SUMMARY")
logger.info("=" * 90)
for name, r in sorted(results.items()):
    status = "✓ MEETS TARGETS" if r["achievable"] else "✗ NEEDS RETRAINING"
    logger.info("  %-20s  AUC=%.4f  F1=%.4f  %s",
                name, r["best"]["auc"], r["best"]["f1"], status)
