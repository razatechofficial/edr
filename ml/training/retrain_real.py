#!/usr/bin/env python3
"""Retrain all 5 models on real-world datasets using adapters.

Trains: ransomware, lolbin_detector, supply_chain_detector,
        identity_threat, aigen_detector

Usage:
    /opt/anaconda3/envs/ml_train/bin/python retrain_real.py [--output-dir ./output]
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import numpy as np

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(name)s: %(message)s")
log = logging.getLogger("retrain_real")


def train_ransomware(output_dir: str, args: argparse.Namespace):
    from adapters.ransomware_adapter import generate_training_data as gen_data
    from utils.datasets import split_dataset
    from utils.evaluation import evaluate_binary_classifier, plot_feature_importance
    from utils.features import RANSOMWARE_FEATURE_COUNT, RANSOMWARE_FEATURE_KEYS
    from xgboost import XGBClassifier
    import onnxmltools
    from onnxmltools.convert.common.data_types import FloatTensorType
    import onnx
    from onnx import helper, TensorProto

    log.info("=" * 60)
    log.info("Training RANSOMWARE detector on MLRan data…")
    log.info("=" * 60)

    X, y = gen_data(n_benign=args.n_benign, n_ransomware=args.n_ransomware)
    splits = split_dataset(X, y, seed=args.seed)

    n_pos = splits["y_train"].sum()
    n_neg = len(splits["y_train"]) - n_pos
    scale_pos_weight = n_neg / max(n_pos, 1)

    model = XGBClassifier(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        learning_rate=args.learning_rate,
        scale_pos_weight=scale_pos_weight,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=args.seed,
        use_label_encoder=False,
        n_jobs=-1,
    )
    model.fit(
        splits["X_train"], splits["y_train"],
        eval_set=[(splits["X_val"], splits["y_val"])],
        verbose=0,
    )

    y_pred = model.predict(splits["X_test"])
    y_prob = model.predict_proba(splits["X_test"])[:, 1]
    metrics = evaluate_binary_classifier(
        splits["y_test"], y_pred, y_prob,
        model_name="ransomware", output_dir=output_dir,
    )
    plot_feature_importance(
        model.feature_importances_,
        list(RANSOMWARE_FEATURE_KEYS),
        model_name="ransomware",
        top_n=RANSOMWARE_FEATURE_COUNT,
        save_path=Path(output_dir) / "ransomware_feature_importance.png",
    )

    # Export to ONNX
    onnx_path = Path(output_dir) / "ransomware.onnx"
    initial_type = [("input", FloatTensorType([None, RANSOMWARE_FEATURE_COUNT]))]
    onnx_model = onnxmltools.convert_xgboost(model, initial_types=initial_type, target_opset=15)
    onnx_model.graph.input[0].name = "input"

    prob_name = None
    for o in onnx_model.graph.output:
        if o.name != "label":
            prob_name = o.name
            break
    if prob_name is None:
        prob_name = onnx_model.graph.output[0].name
    original_prob_name = prob_name + "_raw"
    for o in onnx_model.graph.output:
        if o.name == prob_name:
            o.name = original_prob_name
    for node in onnx_model.graph.node:
        for i, o in enumerate(node.output):
            if o == prob_name:
                node.output[i] = original_prob_name

    indices_init = helper.make_tensor("gather_indices", TensorProto.INT64, [1], [1])
    onnx_model.graph.initializer.append(indices_init)
    gather_node = helper.make_node("Gather", [original_prob_name, "gather_indices"], ["score"],
                                    name="extract_class1_proba", axis=1)
    onnx_model.graph.node.append(gather_node)
    score_output = helper.make_tensor_value_info("score", TensorProto.FLOAT, [None, 1])
    del onnx_model.graph.output[:]
    onnx_model.graph.output.extend([score_output])
    import onnx
    onnx.save(onnx_model, str(onnx_path))
    log.info("Ransomware ONNX saved to %s (AUC=%.4f, F1=%.4f)", onnx_path,
             metrics.get("roc_auc", 0), metrics.get("f1", 0))


def train_lolbin(output_dir: str, args: argparse.Namespace):
    from adapters.lolbin_adapter import generate_training_data as gen_data
    import torch
    import torch.nn as nn

    log.info("=" * 60)
    log.info("Training LOLBIN detector on LOLBAS + Atomic Red Team data…")
    log.info("=" * 60)

    X_np, y_np = gen_data(n_benign=args.n_benign_lolbin, n_malicious=args.n_malicious_lolbin)
    split = int(len(X_np) * 0.8)

    X_train = torch.from_numpy(X_np[:split])
    y_train = torch.from_numpy(y_np[:split]).unsqueeze(1)
    X_test = torch.from_numpy(X_np[split:])
    y_test = torch.from_numpy(y_np[split:]).unsqueeze(1)

    class LOLBinNet(nn.Module):
        def __init__(self):
            super().__init__()
            self.net = nn.Sequential(
                nn.Linear(64, 128), nn.ReLU(), nn.Dropout(0.2),
                nn.Linear(128, 64), nn.ReLU(), nn.Dropout(0.1),
                nn.Linear(64, 1), nn.Sigmoid(),
            )
        def forward(self, x):
            return self.net(x)

    model = LOLBinNet()
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    criterion = nn.BCELoss()

    for epoch in range(args.epochs):
        model.train()
        optimizer.zero_grad()
        loss = criterion(model(X_train), y_train)
        loss.backward()
        optimizer.step()
        if (epoch + 1) % 10 == 0:
            model.eval()
            with torch.no_grad():
                val_loss = criterion(model(X_test), y_test).item()
                acc = ((model(X_test) > 0.5).float() == y_test).float().mean().item()
            log.info("  Epoch %d/%d val_loss=%.4f acc=%.4f", epoch + 1, args.epochs, val_loss, acc)

    onnx_path = Path(output_dir) / "lolbin_detector.onnx"
    model.eval()
    dummy = torch.randn(1, 64)
    torch.onnx.export(model, dummy, str(onnx_path),
                      input_names=["input"], output_names=["score"],
                      dynamic_axes={"input": {0: "batch"}, "score": {0: "batch"}},
                      opset_version=15)
    log.info("LOLBin ONNX saved to %s", onnx_path)


def train_supply_chain(output_dir: str, args: argparse.Namespace):
    from adapters.supply_chain_adapter import generate_training_data as gen_data
    import torch
    import torch.nn as nn

    log.info("=" * 60)
    log.info("Training SUPPLY CHAIN detector on DataDog data…")
    log.info("=" * 60)

    X_np, y_np = gen_data(n_benign=args.n_benign_sc, n_malicious=args.n_malicious_sc)
    split = int(len(X_np) * 0.8)

    X_train = torch.from_numpy(X_np[:split])
    y_train = torch.from_numpy(y_np[:split]).unsqueeze(1)
    X_test = torch.from_numpy(X_np[split:])
    y_test = torch.from_numpy(y_np[split:]).unsqueeze(1)

    class SupplyChainNet(nn.Module):
        def __init__(self):
            super().__init__()
            self.net = nn.Sequential(
                nn.Linear(32, 64), nn.ReLU(), nn.Dropout(0.2),
                nn.Linear(64, 32), nn.ReLU(),
                nn.Linear(32, 1), nn.Sigmoid(),
            )
        def forward(self, x):
            return self.net(x)

    model = SupplyChainNet()
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    criterion = nn.BCELoss()

    for epoch in range(args.epochs):
        model.train()
        optimizer.zero_grad()
        loss = criterion(model(X_train), y_train)
        loss.backward()
        optimizer.step()
        if (epoch + 1) % 10 == 0:
            model.eval()
            with torch.no_grad():
                val_loss = criterion(model(X_test), y_test).item()
                acc = ((model(X_test) > 0.5).float() == y_test).float().mean().item()
            log.info("  Epoch %d/%d val_loss=%.4f acc=%.4f", epoch + 1, args.epochs, val_loss, acc)

    onnx_path = Path(output_dir) / "supply_chain_detector.onnx"
    model.eval()
    dummy = torch.randn(1, 32)
    torch.onnx.export(model, dummy, str(onnx_path),
                      input_names=["input"], output_names=["score"],
                      dynamic_axes={"input": {0: "batch"}, "score": {0: "batch"}},
                      opset_version=15)
    log.info("Supply Chain ONNX saved to %s", onnx_path)


def train_identity(output_dir: str, args: argparse.Namespace):
    from adapters.identity_adapter import generate_training_data as gen_data
    import torch
    import torch.nn as nn

    log.info("=" * 60)
    log.info("Training IDENTITY THREAT detector on BETH data…")
    log.info("=" * 60)

    X_np, y_np = gen_data(n_benign=args.n_benign_id, n_malicious=args.n_malicious_id)
    split = int(len(X_np) * 0.8)

    X_train = torch.from_numpy(X_np[:split])
    y_train = torch.from_numpy(y_np[:split]).unsqueeze(1)
    X_test = torch.from_numpy(X_np[split:])
    y_test = torch.from_numpy(y_np[split:]).unsqueeze(1)

    class IdentityNet(nn.Module):
        def __init__(self):
            super().__init__()
            self.net = nn.Sequential(
                nn.Linear(24, 48), nn.ReLU(), nn.Dropout(0.2),
                nn.Linear(48, 24), nn.ReLU(),
                nn.Linear(24, 1), nn.Sigmoid(),
            )
        def forward(self, x):
            return self.net(x)

    model = IdentityNet()
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    criterion = nn.BCELoss()

    for epoch in range(args.epochs):
        model.train()
        optimizer.zero_grad()
        loss = criterion(model(X_train), y_train)
        loss.backward()
        optimizer.step()
        if (epoch + 1) % 10 == 0:
            model.eval()
            with torch.no_grad():
                val_loss = criterion(model(X_test), y_test).item()
                acc = ((model(X_test) > 0.5).float() == y_test).float().mean().item()
            log.info("  Epoch %d/%d val_loss=%.4f acc=%.4f", epoch + 1, args.epochs, val_loss, acc)

    onnx_path = Path(output_dir) / "identity_threat.onnx"
    model.eval()
    dummy = torch.randn(1, 24)
    torch.onnx.export(model, dummy, str(onnx_path),
                      input_names=["input"], output_names=["score"],
                      dynamic_axes={"input": {0: "batch"}, "score": {0: "batch"}},
                      opset_version=15)
    log.info("Identity Threat ONNX saved to %s", onnx_path)


def train_aigen(output_dir: str, args: argparse.Namespace):
    from adapters.droid_adapter import generate_training_data as gen_data
    import torch
    import torch.nn as nn

    log.info("=" * 60)
    log.info("Training AI-GEN DETECTOR on DroidCollection data…")
    log.info("=" * 60)

    X_np, y_np = gen_data(n_benign=args.n_benign_ai, n_malicious=args.n_malicious_ai)
    split = int(len(X_np) * 0.8)

    X_train = torch.from_numpy(X_np[:split])
    y_train = torch.from_numpy(y_np[:split]).unsqueeze(1)
    X_test = torch.from_numpy(X_np[split:])
    y_test = torch.from_numpy(y_np[split:]).unsqueeze(1)

    class AIGenNet(nn.Module):
        def __init__(self, input_dim: int = 48):
            super().__init__()
            self.net = nn.Sequential(
                nn.Linear(input_dim, 128), nn.ReLU(), nn.Dropout(0.3),
                nn.Linear(128, 64), nn.ReLU(), nn.Dropout(0.2),
                nn.Linear(64, 32), nn.ReLU(), nn.Dropout(0.1),
                nn.Linear(32, 1), nn.Sigmoid(),
            )
        def forward(self, x):
            return self.net(x)

    model = AIGenNet()
    optimizer = torch.optim.AdamW(model.parameters(), lr=5e-4, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=10, factor=0.5)
    criterion = nn.BCELoss()

    best_val_loss = float("inf")
    best_state = None
    for epoch in range(args.epochs):
        model.train()
        optimizer.zero_grad()
        loss = criterion(model(X_train), y_train)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()
        if (epoch + 1) % 10 == 0:
            model.eval()
            with torch.no_grad():
                val_loss = criterion(model(X_test), y_test).item()
                acc = ((model(X_test) > 0.5).float() == y_test).float().mean().item()
                y_prob = model(X_test).squeeze().numpy()
                from sklearn.metrics import roc_auc_score
                auc = roc_auc_score(y_test.numpy(), y_prob)
            log.info("  Epoch %d/%d val_loss=%.4f acc=%.4f auc=%.4f", epoch + 1, args.epochs, val_loss, acc, auc)
            scheduler.step(val_loss)
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                best_state = {k: v.clone() for k, v in model.state_dict().items()}

    if best_state is not None:
        model.load_state_dict(best_state)
        log.info("Restored best model (val_loss=%.4f)", best_val_loss)

    onnx_path = Path(output_dir) / "aigen_detector.onnx"
    model.eval()
    dummy = torch.randn(1, 48)
    torch.onnx.export(model, dummy, str(onnx_path),
                      input_names=["input"], output_names=["score"],
                      dynamic_axes={"input": {0: "batch"}, "score": {0: "batch"}},
                      opset_version=15)
    log.info("AI-Gen Detector ONNX saved to %s", onnx_path)


def main():
    p = argparse.ArgumentParser(description="Retrain all models on real data")
    p.add_argument("--output-dir", default="./output_real", help="Output directory")
    p.add_argument("--epochs", type=int, default=100, help="Training epochs (PyTorch models)")
    p.add_argument("--seed", type=int, default=42)
    
    # Ransomware (XGBoost)
    p.add_argument("--n-benign", type=int, default=8000)
    p.add_argument("--n-ransomware", type=int, default=5000)
    p.add_argument("--n-estimators", type=int, default=300)
    p.add_argument("--max-depth", type=int, default=6)
    p.add_argument("--learning-rate", type=float, default=0.1)
    
    # LOLBin
    p.add_argument("--n-benign-lolbin", type=int, default=30000)
    p.add_argument("--n-malicious-lolbin", type=int, default=10000)
    
    # Supply Chain
    p.add_argument("--n-benign-sc", type=int, default=16000)
    p.add_argument("--n-malicious-sc", type=int, default=4000)
    
    # Identity
    p.add_argument("--n-benign-id", type=int, default=16000)
    p.add_argument("--n-malicious-id", type=int, default=4000)
    
    # AI-gen (DroidCollection: 499K human, 558K AI-gen available)
    p.add_argument("--n-benign-ai", type=int, default=30000)
    p.add_argument("--n-malicious-ai", type=int, default=30000)
    
    args = p.parse_args()
    
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    log.info("Output directory: %s", output_dir.resolve())
    
    train_ransomware(str(output_dir), args)
    train_lolbin(str(output_dir), args)
    train_supply_chain(str(output_dir), args)
    train_identity(str(output_dir), args)
    train_aigen(str(output_dir), args)
    
    log.info("All models trained. Output in %s", output_dir.resolve())


if __name__ == "__main__":
    main()
