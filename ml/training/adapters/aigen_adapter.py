"""AI-generated code detector adapter using HC3 dataset.

Extracts 48-dim code/text structure features from human vs AI-generated text.

Features (48-dim):
  - [0:12]  Code structure entropy
  - [12:24] String literal profile
  - [24:32] API call diversity
  - [32:40] Obfuscation metrics
  - [40:48] Behavioral divergence
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import numpy as np

log = logging.getLogger("aigen_adapter")

AIGEN_FEATURE_DIM = 48


def load_hc3_jsonl(path: str, max_lines: int = 5000) -> list[dict]:
    samples = []
    with open(path) as f:
        for i, line in enumerate(f):
            if i >= max_lines:
                break
            try:
                samples.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return samples


def extract_text_features(text: str) -> np.ndarray:
    x = np.zeros(AIGEN_FEATURE_DIM, dtype=np.float32)
    
    sentences = re.split(r'[.!?]+', text)
    words = text.split()
    chars = list(text)
    
    if not words:
        return x
    
    # Code structure (0-11)
    word_lengths = [len(w) for w in words]
    if word_lengths:
        x[0] = min(1.0, np.std(word_lengths) / 5.0)  # length variance
        x[1] = min(1.0, np.mean(word_lengths) / 10.0)  # avg length
    x[2] = min(1.0, len(sentences) / 20.0)  # sentence density
    
    # Structural repetition (high = repetitive)
    if len(words) > 5:
        unique_ratio = len(set(words)) / max(len(words), 1)
        x[5] = 1.0 - unique_ratio  # repetitiveness
    
    # Comment/explanation sparsity
    explanation_words = {"because", "since", "therefore", "however", "thus", "hence", "furthermore", "moreover", "additionally", "consequently", "specifically", "generally", "typically", "usually", "often", "sometimes", "rarely", "frequently"}
    explanation_count = sum(1 for w in words if w.lower().strip(".,!?;:") in explanation_words)
    x[6] = min(1.0, explanation_count / max(len(words) * 0.1, 1))
    
    # Error handling / hedging
    hedge_words = {"might", "may", "could", "would", "should", "perhaps", "probably", "possibly", "maybe", "potentially", "typically", "generally", "often", "sometimes", "usually"}
    hedge_count = sum(1 for w in words if w.lower().strip(".,!?;:") in hedge_words)
    x[7] = min(1.0, hedge_count / max(len(words) * 0.05, 1))
    
    # String profile (12-23)
    # n-gram distribution regularity
    if len(words) > 2:
        bigrams = [f"{words[i]} {words[i+1]}" for i in range(len(words)-1)]
        unique_bigrams = len(set(bigrams))
        x[12] = min(1.0, unique_bigrams / max(len(bigrams), 1))  # bigram uniqueness
        x[13] = 1.0 - x[12]  # bigram regularity
    
    # Word length consistency
    if word_lengths:
        x[16] = 1.0 - min(1.0, np.std(word_lengths) / 5.0 if np.std(word_lengths) > 0 else 0)
    
    # Punctuation features
    punct_count = sum(1 for c in chars if c in ".,!?;:\"'()[]{}")
    x[17] = min(1.0, punct_count / max(len(chars) * 0.1, 1))
    
    # Rare character usage
    rare_chars = sum(1 for c in chars if ord(c) > 127)
    x[22] = min(1.0, rare_chars / max(len(chars) * 0.05, 1))
    
    # API diversity (24-31)
    # Surface breadth (simple heuristic)
    caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
    x[24] = min(1.0, caps_ratio * 5)  # API-like naming
    
    # Code-like patterns
    code_patterns = re.findall(r'\b\w+\(.*?\)', text)
    x[25] = min(1.0, len(code_patterns) / max(len(words) * 0.2, 1))
    
    # Variable naming entropy
    var_patterns = re.findall(r'\b[a-z_][a-z0-9_]*\b', text)
    if var_patterns:
        unique_vars = len(set(var_patterns))
        x[33] = 1.0 - min(1.0, unique_vars / max(len(var_patterns), 1))  # low entropy = AI-like
        x[34] = min(1.0, unique_vars / 20.0)  # naming diversity
    
    # Obfuscation (32-39)
    # Encoding layers
    encoded_patterns = re.findall(r'[A-Za-z0-9+/]{30,}={0,2}', text)
    x[32] = min(1.0, len(encoded_patterns) / 5.0)
    
    x[36] = min(1.0, explanation_count / max(len(words) * 0.1, 1))  # junk/logorrhea
    
    # Behavioral divergence (40-47)
    # Syscall-like words
    syscall_words = {"read", "write", "open", "close", "exec", "fork", "connect", "listen", "send", "recv"}
    syscall_count = sum(1 for w in words if w.lower() in syscall_words)
    x[40] = min(1.0, syscall_count / max(len(words) * 0.05, 1))
    
    # Permission/security words
    security_words = {"admin", "root", "sudo", "permission", "access", "bypass", "exploit", "vulnerability"}
    sec_count = sum(1 for w in words if w.lower() in security_words)
    x[41] = min(1.0, sec_count / max(len(words) * 0.03, 1))
    
    # Network words
    network_words = {"http", "https", "url", "ip", "dns", "tcp", "udp", "socket", "proxy", "server", "client"}
    net_count = sum(1 for w in words if w.lower() in network_words)
    x[42] = min(1.0, net_count / max(len(words) * 0.03, 1))
    
    return x


def generate_training_data(
    hc3_path: str | None = None,
    n_benign: int = 15000,
    n_malicious: int = 5000,
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.RandomState(seed)
    
    if hc3_path is None:
        hc3_path = str(
            Path(__file__).parent.parent.parent / "datasets" / "real_datasets" / "hc3_all.jsonl"
        )
    
    hc3_samples = []
    if Path(hc3_path).exists():
        hc3_samples = load_hc3_jsonl(hc3_path, max_lines=30000)
        log.info("Loaded %d HC3 samples", len(hc3_samples))
    
    real_human_features = []
    real_ai_features = []
    
    for s in hc3_samples:
        human_answers = s.get("human_answers", [])
        chatgpt_answers = s.get("chatgpt_answers", [])
        
        for ha in human_answers[:2]:
            fv = extract_text_features(str(ha))
            real_human_features.append(fv)
        
        for ca in chatgpt_answers[:2]:
            fv = extract_text_features(str(ca))
            real_ai_features.append(fv)
    
    log.info("Extracted %d human and %d AI features from HC3",
             len(real_human_features), len(real_ai_features))
    
    # Use real features + generated
    n_human = min(len(real_human_features), n_benign) if real_human_features else 0
    n_ai = min(len(real_ai_features), n_malicious) if real_ai_features else 0
    
    X_list = []
    y_list = []
    
    if n_human > 0:
        X_list.append(np.array(real_human_features[:n_human], dtype=np.float32))
        y_list.append(np.zeros(n_human, dtype=np.int32))
    
    if n_ai > 0:
        X_list.append(np.array(real_ai_features[:n_ai], dtype=np.float32))
        y_list.append(np.ones(n_ai, dtype=np.int32))
    
    # Fill remaining with generated data using real stats
    remaining_benign = n_benign - n_human
    remaining_ai = n_malicious - n_ai
    
    if remaining_benign > 0 or remaining_ai > 0:
        human_means, human_stds, ai_means, ai_stds = _compute_stats(
            real_human_features, real_ai_features
        )
        
        if remaining_benign > 0:
            benign_gen = _generate_from_stats(remaining_benign, human_means, human_stds, rng, is_human=True)
            X_list.append(benign_gen)
            y_list.append(np.zeros(remaining_benign, dtype=np.int32))
        
        if remaining_ai > 0:
            ai_gen = _generate_from_stats(remaining_ai, ai_means, ai_stds, rng, is_human=False)
            X_list.append(ai_gen)
            y_list.append(np.ones(remaining_ai, dtype=np.int32))
    
    X = np.concatenate(X_list, axis=0)
    y = np.concatenate(y_list, axis=0)
    
    perm = rng.permutation(len(X))
    X, y = X[perm], y[perm]
    
    log.info("Training data: %d samples (%d human, %d AI, %d real HC3 used)",
             len(X), int((y == 0).sum()), int(y.sum()),
             n_human + n_ai)
    return X, y


def _compute_stats(human_feats, ai_feats):
    dim = AIGEN_FEATURE_DIM
    if human_feats:
        h_arr = np.array(human_feats, dtype=np.float32)
        human_means = h_arr.mean(axis=0)
        human_stds = np.clip(h_arr.std(axis=0), 0.05, 0.3)
    else:
        human_means = np.zeros(dim)
        human_stds = np.ones(dim) * 0.1
    
    if ai_feats:
        a_arr = np.array(ai_feats, dtype=np.float32)
        ai_means = a_arr.mean(axis=0)
        ai_stds = np.clip(a_arr.std(axis=0), 0.05, 0.3)
    else:
        ai_means = np.ones(dim) * 0.5
        ai_stds = np.ones(dim) * 0.15
    
    return human_means, human_stds, ai_means, ai_stds


def _generate_from_stats(n, means, stds, rng, is_human=True):
    X = np.zeros((n, AIGEN_FEATURE_DIM), dtype=np.float32)
    for i in range(n):
        x = rng.normal(means, stds)
        if is_human:
            x[8] = rng.uniform(0.0, 0.3)    # low code-to-comment ratio
            x[12] = rng.uniform(0.5, 0.9)   # high n-gram diversity
        else:
            x[8] = rng.uniform(0.6, 0.9)    # high code-to-comment ratio
            x[12] = rng.uniform(0.1, 0.4)   # low n-gram diversity
            x[32] = rng.uniform(0.2, 0.6)   # some obfuscation
        x = np.clip(x, 0.0, 1.0).astype(np.float32)
        X[i] = x
    return X


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    X, y = generate_training_data(n_benign=1000, n_malicious=500)
    print(f"X shape: {X.shape}, y shape: {y.shape}")
    print(f"AI-gen: {int(y.sum())}, Human: {int(len(y) - y.sum())}")
