#!/usr/bin/env python3
"""Generate small baseline ONNX models trained on synthetic data.

These serve as the initial shipped models that get replaced when operators
train on real data.  No external dataset downloads are required.

Usage:
    pip install numpy scikit-learn lightgbm xgboost torch onnx onnxruntime \
                skl2onnx onnxmltools cryptography
    python generate_baseline_models.py --output-dir ../../models
"""

from __future__ import annotations

import argparse
import logging
import math
import sys
from pathlib import Path

import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
)
log = logging.getLogger("generate_baseline")

# ---------------------------------------------------------------------------
# Feature-space constants (must match internal/detection/ml/features/*.go)
# ---------------------------------------------------------------------------
PE_FEATURE_DIM = 311
BEHAVIOR_SEQ_LEN = 50
BEHAVIOR_FEAT_DIM = 48
NETWORK_FEAT_DIM = 15
RANSOMWARE_FEAT_DIM = 10


# ===================================================================
# 1. Synthetic data generators
# ===================================================================


def _synthetic_pe_data(
    n_benign: int = 1000, n_malicious: int = 1000, seed: int = 42
) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.RandomState(seed)
    n = n_benign + n_malicious
    X = np.zeros((n, PE_FEATURE_DIM), dtype=np.float32)
    y = np.zeros(n, dtype=np.int32)

    for i in range(n):
        mal = i >= n_benign
        idx = 0

        # Byte histogram (256)
        if mal:
            hist = rng.dirichlet(np.ones(256))
        else:
            alpha = np.ones(256) * 0.01
            for pk in rng.choice(256, size=10, replace=False):
                alpha[pk] = 5.0
            hist = rng.dirichlet(alpha)
        X[i, idx:idx + 256] = hist.astype(np.float32)
        idx += 256

        # Entropy histogram (16)
        eh = rng.dirichlet(np.ones(16))
        if mal:
            eh[-1] += 0.3
            eh /= eh.sum()
        X[i, idx:idx + 16] = eh.astype(np.float32)
        idx += 16

        # Whole-file entropy + log file size
        X[i, idx] = rng.uniform(7.0, 7.99) if mal else rng.uniform(3.0, 6.5)
        idx += 1
        X[i, idx] = rng.uniform(8, 18) if mal else rng.uniform(10, 16)
        idx += 1

        # String stats (8)
        if mal:
            X[i, idx:idx + 6] = [math.log1p(rng.randint(0, 20)),
                                  math.log1p(rng.randint(0, 15)),
                                  math.log1p(rng.randint(0, 30)),
                                  math.log1p(rng.randint(5, 50)),
                                  math.log1p(rng.randint(0, 10)),
                                  math.log1p(rng.randint(20, 300))]
            X[i, idx + 6] = rng.uniform(8, 30)
            X[i, idx + 7] = rng.uniform(0.3, 1.0)
        else:
            X[i, idx:idx + 6] = [math.log1p(rng.randint(0, 5)),
                                  math.log1p(rng.randint(0, 3)),
                                  math.log1p(rng.randint(0, 5)),
                                  math.log1p(rng.randint(0, 20)),
                                  math.log1p(rng.randint(0, 3)),
                                  math.log1p(rng.randint(5, 100))]
            X[i, idx + 6] = rng.uniform(4, 15)
            X[i, idx + 7] = rng.uniform(0.0, 0.5)
        idx += 8

        # PE features (8)
        if mal:
            X[i, idx + 0] = rng.choice([1, 2, 3, 4, 8])
            X[i, idx + 1] = math.log1p(rng.randint(0, 20))
            X[i, idx + 3] = 0.0
            X[i, idx + 6] = rng.uniform(0.7, 1.0)
            X[i, idx + 7] = rng.uniform(0.6, 1.0)
        else:
            X[i, idx + 0] = rng.choice([3, 4, 5, 6, 7])
            X[i, idx + 1] = math.log1p(rng.randint(5, 200))
            X[i, idx + 3] = rng.choice([0.0, 1.0], p=[0.3, 0.7])
            X[i, idx + 6] = rng.uniform(0.3, 0.7)
            X[i, idx + 7] = rng.uniform(0.2, 0.6)
        idx += 8

        # Section entropies (16)
        n_sec = int(X[i, idx - 8])
        for s in range(min(n_sec, 16)):
            X[i, idx + s] = rng.uniform(0.8, 1.0) if mal else rng.uniform(0.2, 0.7)
        idx += 16

        # Format + header (5)
        X[i, idx] = 1.0
        idx += 3
        X[i, idx] = rng.uniform(10, 20)
        X[i, idx + 1] = rng.uniform(1.0, 3.0) if mal else rng.uniform(0.8, 1.5)

        y[i] = 1 if mal else 0

    return X, y


def _synthetic_behavior_data(
    n_benign: int = 500, n_malicious: int = 500, seed: int = 42
) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.RandomState(seed)
    n = n_benign + n_malicious
    X = np.zeros((n, BEHAVIOR_SEQ_LEN, BEHAVIOR_FEAT_DIM), dtype=np.float32)
    y = np.zeros(n, dtype=np.int32)

    # Event sub-types occupy first 25 dims, process categories next 8, etc.
    for i in range(n):
        mal = i >= n_benign
        for t in range(BEHAVIOR_SEQ_LEN):
            vec = np.zeros(BEHAVIOR_FEAT_DIM, dtype=np.float32)
            if mal:
                st = rng.choice([2, 17, 18, 24, 13, 14])  # inject, mem-ops, ptrace, registry
                vec[st] = 1.0
                vec[25 + rng.randint(0, 8)] = 1.0  # process category
                vec[33 + 2] = 1.0  # high privilege
                vec[36] = float(rng.random() > 0.4)  # network
                vec[37] = float(rng.random() > 0.3)  # file write
                vec[38] = float(rng.random() > 0.4)  # registry
            else:
                st = rng.choice([0, 1, 3, 4, 7, 8, 12])  # normal ops
                vec[st] = 1.0
                vec[25 + rng.choice([1, 2, 4, 5])] = 1.0
                vec[33] = 1.0  # low privilege
                vec[36] = float(rng.random() > 0.7)
                vec[37] = float(rng.random() > 0.6)

            vec[39] = rng.uniform(0.25, 0.75) if not mal else rng.uniform(0.0, 1.0)
            # day-of-week one-hot (7 dims at 40-46)
            vec[40 + rng.randint(0, 5)] = 1.0
            vec[47] = rng.uniform(0.0, 1.0)  # parent_score

            X[i, t] = vec
        y[i] = 1 if mal else 0

    return X, y


def _synthetic_network_data(
    n_normal: int = 2000, seed: int = 42
) -> np.ndarray:
    """Normal-only data for autoencoder training."""
    rng = np.random.RandomState(seed)
    X = np.zeros((n_normal, NETWORK_FEAT_DIM), dtype=np.float32)
    log_max = math.log1p(65535)
    normal_ports = [80, 443, 53, 22, 8080, 8443]

    for i in range(n_normal):
        dp = int(rng.choice(normal_ports))
        sp = int(rng.randint(1025, 65535))
        X[i, 0] = 0.0 if dp <= 1023 else 0.5
        X[i, 1] = math.log1p(sp) / log_max
        X[i, 2] = math.log1p(dp) / log_max
        X[i, 3] = rng.uniform(0.25, 0.75)
        X[i, 4] = float(dp == 80)
        X[i, 5] = float(dp == 443)
        X[i, 6] = float(dp == 53)
        X[i, 7] = float(dp == 22)
        X[i, 8] = 1.0 if rng.random() > 0.2 else 0.0
        X[i, 9] = 0.0 if X[i, 8] else 1.0
        X[i, 10] = float(sp > 1024)
        X[i, 11] = dp / 65535.0
        X[i, 12] = 1.0
        X[i, 13] = 1.0  # private IP
        X[i, 14] = 0.0
    return X


def _synthetic_network_test(
    n_normal: int = 200, n_anomalous: int = 200, seed: int = 99
) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.RandomState(seed)
    log_max = math.log1p(65535)
    n = n_normal + n_anomalous
    X = np.zeros((n, NETWORK_FEAT_DIM), dtype=np.float32)
    y = np.zeros(n, dtype=np.int32)

    for i in range(n):
        anom = i >= n_normal
        if anom:
            dp = int(rng.choice([4444, 5555, 31337, 12345, rng.randint(1025, 65535)]))
            sp = int(rng.randint(1025, 65535))
            X[i, 0] = 1.0 if dp > 49151 else 0.5
            X[i, 1] = math.log1p(sp) / log_max
            X[i, 2] = math.log1p(dp) / log_max
            X[i, 3] = rng.uniform(0.0, 1.0)
            X[i, 8] = float(rng.random() > 0.5)
            X[i, 9] = 1.0 - X[i, 8]
            X[i, 10] = 1.0
            X[i, 11] = dp / 65535.0
            X[i, 12] = float(rng.random() > 0.6)
            X[i, 13] = float(rng.random() > 0.7)
        else:
            dp = int(rng.choice([80, 443, 53, 22]))
            sp = int(rng.randint(1025, 65535))
            X[i, 0] = 0.0
            X[i, 1] = math.log1p(sp) / log_max
            X[i, 2] = math.log1p(dp) / log_max
            X[i, 3] = rng.uniform(0.25, 0.75)
            X[i, 4] = float(dp == 80)
            X[i, 5] = float(dp == 443)
            X[i, 6] = float(dp == 53)
            X[i, 7] = float(dp == 22)
            X[i, 8] = 1.0
            X[i, 10] = 1.0
            X[i, 11] = dp / 65535.0
            X[i, 12] = 1.0
            X[i, 13] = 1.0
        y[i] = 1 if anom else 0
    return X, y


def _synthetic_ransomware_data(
    n_benign: int = 500, n_ransomware: int = 500, seed: int = 42
) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.RandomState(seed)
    n = n_benign + n_ransomware
    X = np.zeros((n, RANSOMWARE_FEAT_DIM), dtype=np.float32)
    y = np.zeros(n, dtype=np.int32)

    for i in range(n):
        r = i >= n_benign
        if r:
            X[i] = [rng.uniform(0.5, 1.0), rng.uniform(0.3, 1.0),
                     rng.uniform(0.2, 0.8), rng.uniform(0.4, 1.0),
                     rng.uniform(0.5, 1.0), rng.uniform(0.3, 1.0),
                     rng.choice([0.0, 1.0], p=[0.3, 0.7]),
                     rng.uniform(0.3, 1.0), rng.uniform(0.2, 0.9),
                     rng.uniform(0.3, 1.0)]
        else:
            X[i] = [rng.uniform(0.0, 0.3), rng.uniform(0.0, 0.2),
                     rng.uniform(0.0, 0.15), rng.uniform(0.0, 0.2),
                     rng.uniform(0.0, 0.1), rng.uniform(0.0, 0.1),
                     0.0, rng.uniform(0.0, 0.15),
                     rng.uniform(0.0, 0.15), rng.uniform(0.0, 0.2)]
        y[i] = 1 if r else 0
    return X, y


# ===================================================================
# 2. Model builders & ONNX export
# ===================================================================


def build_pe_classifier(output_dir: Path) -> Path:
    """Train LightGBM on synthetic PE data → pe_classifier.onnx."""
    import lightgbm as lgb
    import onnx
    import onnxmltools
    from onnxmltools.convert.common.data_types import FloatTensorType

    log.info("--- PE Classifier (LightGBM, %d features) ---", PE_FEATURE_DIM)
    X, y = _synthetic_pe_data(1000, 1000, seed=42)
    log.info("  Synthetic data: %d samples", len(y))

    model = lgb.LGBMClassifier(
        n_estimators=100,
        learning_rate=0.1,
        max_depth=6,
        num_leaves=31,
        objective="binary",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
        verbose=-1,
    )
    model.fit(X, y)
    log.info("  Training accuracy: %.4f", model.score(X, y))

    initial_type = [("input", FloatTensorType([None, PE_FEATURE_DIM]))]
    onnx_model = onnxmltools.convert_lightgbm(model, initial_types=initial_type, target_opset=15)
    onnx_model.graph.input[0].name = "input"
    if len(onnx_model.graph.output) >= 2:
        onnx_model.graph.output[0].name = "label"
        onnx_model.graph.output[1].name = "probabilities"

    out_path = output_dir / "pe_classifier.onnx"
    onnx.save(onnx_model, str(out_path))
    _validate_onnx(out_path, X[:2])
    return out_path


def build_behavior_lstm(output_dir: Path) -> Path:
    """Train PyTorch LSTM on synthetic sequences → behavior_lstm.onnx."""
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset

    log.info("--- Behavior LSTM (PyTorch, %dx%d) ---", BEHAVIOR_SEQ_LEN, BEHAVIOR_FEAT_DIM)

    class BehaviorLSTM(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.lstm = nn.LSTM(
                input_size=BEHAVIOR_FEAT_DIM,
                hidden_size=64,
                num_layers=1,
                batch_first=True,
                bidirectional=True,
            )
            self.classifier = nn.Sequential(
                nn.Linear(128, 32),
                nn.ReLU(),
                nn.Linear(32, 1),
                nn.Sigmoid(),
            )

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            out, _ = self.lstm(x)
            ctx = out[:, -1, :]
            return self.classifier(ctx)

    X, y = _synthetic_behavior_data(500, 500, seed=42)
    log.info("  Synthetic data: %d sequences", len(y))

    torch.manual_seed(42)
    ds = TensorDataset(torch.from_numpy(X), torch.from_numpy(y.astype(np.float32)))
    loader = DataLoader(ds, batch_size=64, shuffle=True)

    model = BehaviorLSTM()
    criterion = nn.BCELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)

    model.train()
    for epoch in range(15):
        total = 0.0
        for xb, yb in loader:
            optimizer.zero_grad()
            pred = model(xb).squeeze(-1)
            loss = criterion(pred, yb)
            loss.backward()
            optimizer.step()
            total += loss.item() * xb.size(0)
        if (epoch + 1) % 5 == 0:
            log.info("  Epoch %2d  loss=%.4f", epoch + 1, total / len(ds))

    model.eval()
    out_path = output_dir / "behavior_lstm.onnx"
    dummy = torch.randn(1, BEHAVIOR_SEQ_LEN, BEHAVIOR_FEAT_DIM)
    torch.onnx.export(
        model, dummy, str(out_path),
        input_names=["input"],
        output_names=["score"],
        dynamic_axes={"input": {0: "batch"}, "score": {0: "batch"}},
        opset_version=15,
    )
    _validate_onnx(out_path, X[:2])
    return out_path


def build_network_anomaly(output_dir: Path) -> Path:
    """Train PyTorch autoencoder on synthetic normal traffic → network_anomaly.onnx."""
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset

    log.info("--- Network Anomaly (Autoencoder, %d features) ---", NETWORK_FEAT_DIM)

    class Autoencoder(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.encoder = nn.Sequential(
                nn.Linear(NETWORK_FEAT_DIM, 32), nn.ReLU(),
                nn.Linear(32, 16), nn.ReLU(),
                nn.Linear(16, 4), nn.ReLU(),
            )
            self.decoder = nn.Sequential(
                nn.Linear(4, 16), nn.ReLU(),
                nn.Linear(16, 32), nn.ReLU(),
                nn.Linear(32, NETWORK_FEAT_DIM), nn.Sigmoid(),
            )

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            return self.decoder(self.encoder(x))

    class AnomalyScorer(nn.Module):
        def __init__(self, ae: Autoencoder) -> None:
            super().__init__()
            self.ae = ae

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            recon = self.ae(x)
            return ((x - recon) ** 2).mean(dim=1, keepdim=True)

    X_train = _synthetic_network_data(2000, seed=42)
    log.info("  Normal training samples: %d", len(X_train))

    torch.manual_seed(42)
    ds = TensorDataset(torch.from_numpy(X_train))
    loader = DataLoader(ds, batch_size=128, shuffle=True)

    ae = Autoencoder()
    optimizer = torch.optim.Adam(ae.parameters(), lr=1e-3)
    criterion = nn.MSELoss()

    ae.train()
    for epoch in range(30):
        total = 0.0
        for (batch,) in loader:
            optimizer.zero_grad()
            loss = criterion(ae(batch), batch)
            loss.backward()
            optimizer.step()
            total += loss.item() * batch.size(0)
        if (epoch + 1) % 10 == 0:
            log.info("  Epoch %2d  mse=%.6f", epoch + 1, total / len(X_train))

    scorer = AnomalyScorer(ae)
    scorer.eval()

    out_path = output_dir / "network_anomaly.onnx"
    dummy = torch.randn(1, NETWORK_FEAT_DIM)
    torch.onnx.export(
        scorer, dummy, str(out_path),
        input_names=["input"],
        output_names=["anomaly_score"],
        dynamic_axes={"input": {0: "batch"}, "anomaly_score": {0: "batch"}},
        opset_version=15,
    )
    _validate_onnx(out_path, X_train[:2])
    return out_path


def build_ransomware(output_dir: Path) -> Path:
    """Train XGBoost on synthetic ransomware indicators → ransomware.onnx."""
    import onnx
    import onnxmltools
    from onnxmltools.convert.common.data_types import FloatTensorType
    from xgboost import XGBClassifier

    log.info("--- Ransomware (XGBoost, %d features) ---", RANSOMWARE_FEAT_DIM)
    X, y = _synthetic_ransomware_data(500, 500, seed=42)
    log.info("  Synthetic data: %d samples", len(y))

    n_pos = y.sum()
    n_neg = len(y) - n_pos
    model = XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        scale_pos_weight=n_neg / max(n_pos, 1),
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=42,
        use_label_encoder=False,
        n_jobs=-1,
        verbosity=0,
    )
    model.fit(X, y)
    log.info("  Training accuracy: %.4f", model.score(X, y))

    initial_type = [("input", FloatTensorType([None, RANSOMWARE_FEAT_DIM]))]
    onnx_model = onnxmltools.convert_xgboost(model, initial_types=initial_type, target_opset=15)
    onnx_model.graph.input[0].name = "input"
    if len(onnx_model.graph.output) >= 2:
        onnx_model.graph.output[0].name = "label"
        onnx_model.graph.output[1].name = "probabilities"

    out_path = output_dir / "ransomware.onnx"
    onnx.save(onnx_model, str(out_path))
    _validate_onnx(out_path, X[:2])
    return out_path


# ===================================================================
# 3. ONNX validation helper
# ===================================================================


def _validate_onnx(path: Path, sample: np.ndarray) -> None:
    import onnxruntime as ort

    sess = ort.InferenceSession(str(path))
    inp = sess.get_inputs()[0]
    outs = sess.get_outputs()

    feed = {inp.name: sample.astype(np.float32)}
    results = sess.run([o.name for o in outs], feed)
    log.info("  Validated %s — input %s → outputs %s",
             path.name, sample.shape,
             ", ".join(f"{o.name}{np.array(r).shape}" for o, r in zip(outs, results)))
    sz = path.stat().st_size
    log.info("  Size: %.1f KB", sz / 1024)


# ===================================================================
# 4. Ed25519 signing
# ===================================================================


def sign_models(output_dir: Path) -> str:
    """Sign all .onnx files and return the public key hex string."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    onnx_files = sorted(output_dir.glob("*.onnx"))
    for p in onnx_files:
        data = p.read_bytes()
        sig = private_key.sign(data)
        sig_path = p.with_suffix(p.suffix + ".sig")
        sig_path.write_bytes(sig)
        log.info("  Signed %s → %s (%d bytes)", p.name, sig_path.name, len(sig))

    raw_pub = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    hex_str = raw_pub.hex()

    (output_dir / "signing_pubkey.hex").write_text(hex_str + "\n")
    log.info("  Public key (hex): %s", hex_str)

    # Verify round-trip
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey as PubCls
    pub = PubCls.from_public_bytes(bytes.fromhex(hex_str))
    for p in onnx_files:
        sig = p.with_suffix(p.suffix + ".sig").read_bytes()
        pub.verify(sig, p.read_bytes())
    log.info("  All %d signatures verified", len(onnx_files))

    # Also save key pair for future re-signing
    priv_bytes = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    (output_dir / "model_signing.key").write_bytes(priv_bytes)

    return hex_str


# ===================================================================
# 5. Main
# ===================================================================


def main() -> None:
    p = argparse.ArgumentParser(description="Generate baseline ONNX models from synthetic data")
    p.add_argument("--output-dir", type=str, default="../../models",
                   help="Directory to write models into (default: ../../models)")
    args = p.parse_args()

    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    log.info("Output directory: %s", output_dir)

    paths = []
    paths.append(build_pe_classifier(output_dir))
    paths.append(build_behavior_lstm(output_dir))
    paths.append(build_network_anomaly(output_dir))
    paths.append(build_ransomware(output_dir))

    log.info("=== Signing models ===")
    pubkey = sign_models(output_dir)

    log.info("")
    log.info("=" * 60)
    log.info("Baseline models generated successfully!")
    log.info("=" * 60)
    log.info("Models directory: %s", output_dir)
    for p in paths:
        sz = p.stat().st_size / 1024
        sig_sz = p.with_suffix(p.suffix + ".sig").stat().st_size
        log.info("  %-25s  %6.1f KB  (sig: %d bytes)", p.name, sz, sig_sz)
    log.info("")
    log.info("Public key for agent config (ml.verify_pubkey):")
    log.info("  %s", pubkey)
    log.info("")
    log.info("These are lightweight baseline models trained on synthetic data.")
    log.info("Replace with production models trained on real data for deployment.")


# ===================================================================
# 6. Aliases for scripts/convert_pretrained.py baseline command
# ===================================================================

def generate_pe_model(out_path: str) -> None:
    build_pe_classifier(Path(out_path).parent)

def generate_behavior_model(out_path: str) -> None:
    build_behavior_lstm(Path(out_path).parent)

def generate_network_model(out_path: str) -> None:
    build_network_anomaly(Path(out_path).parent)

def generate_ransomware_model(out_path: str) -> None:
    build_ransomware(Path(out_path).parent)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception:
        log.exception("Failed")
        sys.exit(1)
