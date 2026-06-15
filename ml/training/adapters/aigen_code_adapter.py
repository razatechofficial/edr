"""AI-generated code detector adapter using HumanVsAICode dataset.

Extracts 48-dim code structure features from real Python/Java source code
(human-written vs ChatGPT/DeepSeek-Coder/Qwen-Coder generated).

Features (48-dim):
  - [0:8]   Code structure entropy (line length variance, blank lines, etc.)
  - [8:16]  Comment & docstring profile
  - [16:24] Code complexity metrics (indentation depth, branching)
  - [24:32] Naming conventions and API patterns
  - [32:40] Obfuscation & encoding indicators
  - [40:48] Behavioral & keyword patterns
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import numpy as np

log = logging.getLogger("aigen_code_adapter")

AIGEN_FEATURE_DIM = 48

PYTHON_KEYWORDS = {"for", "while", "if", "elif", "else", "try", "except", "finally", "with", "as", "def", "class", "return", "yield", "import", "from", "raise", "pass", "break", "continue", "and", "or", "not", "in", "is", "lambda", "async", "await"}
JAVA_KEYWORDS = {"for", "while", "if", "else", "try", "catch", "finally", "throw", "throws", "class", "interface", "extends", "implements", "return", "new", "import", "package", "public", "private", "protected", "static", "final", "abstract", "synchronized", "volatile", "transient", "native", "strictfp", "assert", "enum", "default", "break", "continue", "switch", "case"}

RESERVED_WORDS = PYTHON_KEYWORDS | JAVA_KEYWORDS

SECURITY_SENSITIVE = {"exec", "eval", "compile", "__import__", "getattr", "setattr", "delattr", "subprocess", "os.system", "os.popen", "shutil", "pickle", "marshal", "shelve", "ctypes", "pyobjc", "win32api", "socket", "requests", "urllib", "ftplib", "telnetlib", "paramiko"}

EXPLANATION_WORDS = {"because", "since", "therefore", "however", "thus", "hence", "furthermore", "moreover", "additionally", "consequently", "specifically", "generally", "typically", "usually", "often", "sometimes", "rarely", "frequently", "note", "hint", "tip", "warning", "important"}

HEDGE_WORDS = {"might", "may", "could", "would", "should", "perhaps", "probably", "possibly", "maybe", "potentially", "typically", "generally", "often", "sometimes", "usually"}

NETWORK_WORDS = {"http", "https", "url", "ip", "dns", "tcp", "udp", "socket", "proxy", "server", "client", "connect", "bind", "listen", "accept", "send", "recv"}

SYSALL_WORDS = {"read", "write", "open", "close", "exec", "fork", "connect", "listen", "send", "recv", "mmap", "brk", "ioctl", "fcntl", "stat", "lstat", "access", "chmod", "chown"}


def extract_code_features(code: str) -> np.ndarray:
    x = np.zeros(AIGEN_FEATURE_DIM, dtype=np.float32)

    lines = code.split("\n")
    non_blank = [l for l in lines if l.strip()]
    words = code.split()
    chars = list(code)

    if not words or not non_blank:
        return x

    # [0:8] Code structure entropy
    line_lengths = [len(l) for l in non_blank]
    if line_lengths:
        x[0] = min(1.0, np.std(line_lengths) / 30.0)
        x[1] = min(1.0, np.mean(line_lengths) / 80.0)

    blank_ratio = len([l for l in lines if not l.strip()]) / max(len(lines), 1)
    x[2] = min(1.0, blank_ratio * 3)

    if line_lengths:
        max_len_ratio = max(line_lengths) / max(np.mean(line_lengths) + 1, 1)
        x[3] = min(1.0, max_len_ratio / 5.0)

    # Indentation depth
    indents = [len(l) - len(l.lstrip()) for l in non_blank if l.strip()]
    if indents:
        x[4] = min(1.0, np.mean(indents) / 20.0)
        x[5] = min(1.0, np.std(indents) / 10.0)

    # [8:16] Comment profile
    comment_lines = sum(1 for l in non_blank if l.strip().startswith(("#", "//", "/*", "*", "///")))
    x[8] = min(1.0, comment_lines / max(len(non_blank) * 0.3, 1))

    docstring_lines = sum(1 for l in lines if '"""' in l or "'''" in l or "/**" in l or "///" in l)
    x[9] = min(1.0, docstring_lines / max(len(lines) * 0.1, 1))

    explanation_count = sum(1 for w in words if w.lower().strip(".,!?;:()[]{}") in EXPLANATION_WORDS)
    x[10] = min(1.0, explanation_count / max(len(words) * 0.05, 1))

    # Comment-to-code ratio
    code_lines = len(non_blank) - comment_lines
    x[11] = min(1.0, comment_lines / max(code_lines, 1)) if code_lines > 0 else 0

    # [16:24] Code complexity
    control_keywords = {"for", "while", "if", "elif", "else", "try", "except", "catch", "switch", "case"}
    branch_count = sum(1 for w in words if w.strip("():") in control_keywords)
    x[16] = min(1.0, branch_count / max(len(non_blank) * 0.2, 1))

    func_defs = re.findall(r'\b(def |function |public|private|protected).*\(', code)
    x[17] = min(1.0, len(func_defs) / max(len(non_blank) * 0.05, 1))

    unique_tokens = len(set(w.lower().strip(".,!?;:()[]{}<>'\"") for w in words))
    x[18] = min(1.0, unique_tokens / max(len(words), 1))

    bracket_depth = 0
    max_depth = 0
    for c in chars:
        if c in "({[":
            bracket_depth += 1
            max_depth = max(max_depth, bracket_depth)
        elif c in ")}]":
            bracket_depth = max(0, bracket_depth - 1)
    x[19] = min(1.0, max_depth / 10.0)

    # [24:32] Naming conventions
    camel_case = len(re.findall(r'\b[A-Z][a-z]+(?:[A-Z][a-z]+)*\b', code))
    snake_case = len(re.findall(r'\b[a-z]+(?:_[a-z]+)+\b', code))
    upper_case = len(re.findall(r'\b[A-Z_]{2,}\b', code))
    total_names = camel_case + snake_case + upper_case + 1
    x[24] = min(1.0, camel_case / max(total_names, 1))
    x[25] = min(1.0, snake_case / max(total_names, 1))
    x[26] = min(1.0, upper_case / max(total_names, 1))

    # Short variable names (1-2 chars)
    short_vars = len(re.findall(r'\b[a-z]{1,2}\b', code))
    x[27] = min(1.0, short_vars / max(len(words) * 0.1, 1))

    # Function calls
    func_calls = re.findall(r'\b\w+(?=\s*\()', code)
    x[28] = min(1.0, len(func_calls) / max(len(non_blank) * 0.5, 1))

    # [32:40] Obfuscation indicators
    encoded_patterns = re.findall(r'[A-Za-z0-9+/]{30,}={0,2}', code)
    x[32] = min(1.0, len(encoded_patterns) / 5.0)

    hex_patterns = re.findall(r'\\x[0-9a-fA-F]{2}', code)
    x[33] = min(1.0, len(hex_patterns) / max(len(chars) * 0.02, 1))

    # Line length consistency (low = more obfuscated/homogeneous)
    if line_lengths and np.std(line_lengths) > 0:
        x[34] = min(1.0, np.mean(line_lengths) / (np.std(line_lengths) + 1))

    # Rare characters (non-ASCII)
    rare_chars = sum(1 for c in chars if ord(c) > 127)
    x[35] = min(1.0, rare_chars / max(len(chars) * 0.02, 1))

    # [40:48] Behavioral & keyword patterns
    security_count = sum(1 for w in words if w.strip("(),;") in SECURITY_SENSITIVE)
    x[40] = min(1.0, security_count / max(len(words) * 0.05, 1))

    syscall_count = sum(1 for w in words if w.lower().strip("(),;") in SYSALL_WORDS)
    x[41] = min(1.0, syscall_count / max(len(words) * 0.05, 1))

    network_count = sum(1 for w in words if w.lower().strip("(),;") in NETWORK_WORDS)
    x[42] = min(1.0, network_count / max(len(words) * 0.03, 1))

    hedge_count = sum(1 for w in words if w.lower().strip(".,!?;:()[]{}") in HEDGE_WORDS)
    x[43] = min(1.0, hedge_count / max(len(words) * 0.03, 1))

    # Unique token ratio (low = more repetitive = more AI-like)
    if words:
        x[44] = 1.0 - min(1.0, unique_tokens / max(len(words), 1))

    # Line length coefficient of variation
    if line_lengths and np.mean(line_lengths) > 0:
        x[45] = min(1.0, np.std(line_lengths) / np.mean(line_lengths))

    return x


def load_humanvsai_jsonl(
    path: str,
    max_entries: int = 50000,
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Load HumanVsAICode dataset. Returns (human_samples, ai_samples)."""
    human_samples = []
    ai_samples = []

    with open(path) as f:
        for i, line in enumerate(f):
            if i >= max_entries:
                break
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue

            human_code = d.get("human_code", "")
            if len(human_code) > 20:
                # Extract the docstring for context
                docstring = d.get("docstring", "")
                human_samples.append((human_code, docstring))

            for key in ("chatgpt_code", "dsc_code", "qwen_code"):
                ai_code = d.get(key, "")
                if ai_code and len(ai_code) > 20:
                    ai_samples.append((ai_code, docstring))

    log.info("  Loaded %d human + %d AI samples", len(human_samples), len(ai_samples))
    return human_samples, ai_samples


def generate_training_data(
    n_benign: int = 15000,
    n_malicious: int = 5000,
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.RandomState(seed)

    dataset_dir = Path(__file__).parent.parent.parent / "datasets" / "humanvsai"
    real_human_features = []
    real_ai_features = []

    for fname in ["python_dataset.jsonl", "java_dataset.jsonl"]:
        fpath = dataset_dir / fname
        if not fpath.exists():
            log.warning("File not found: %s", fpath)
            continue

        log.info("Loading %s ...", fpath)
        human_samples, ai_samples = load_humanvsai_jsonl(
            str(fpath), max_entries=50000
        )

        for code, _doc in human_samples:
            fv = extract_code_features(code)
            real_human_features.append(fv)

        for code, _doc in ai_samples:
            fv = extract_code_features(code)
            real_ai_features.append(fv)

    log.info("Extracted %d human and %d AI code features",
             len(real_human_features), len(real_ai_features))

    n_human = min(len(real_human_features), n_benign) if real_human_features else 0
    n_ai = min(len(real_ai_features), n_malicious) if real_ai_features else 0

    X_list, y_list = [], []

    if n_human > 0:
        X_list.append(np.array(real_human_features[:n_human], dtype=np.float32))
        y_list.append(np.zeros(n_human, dtype=np.int32))

    if n_ai > 0:
        X_list.append(np.array(real_ai_features[:n_ai], dtype=np.float32))
        y_list.append(np.ones(n_ai, dtype=np.int32))

    remaining_benign = n_benign - n_human
    remaining_ai = n_malicious - n_ai

    if remaining_benign > 0 or remaining_ai > 0:
        hf = np.array(real_human_features, dtype=np.float32) if real_human_features else None
        af = np.array(real_ai_features, dtype=np.float32) if real_ai_features else None
        human_means = hf.mean(axis=0) if hf is not None else np.zeros(AIGEN_FEATURE_DIM)
        human_stds = np.clip(hf.std(axis=0), 0.05, 0.3) if hf is not None else np.ones(AIGEN_FEATURE_DIM) * 0.1
        ai_means = af.mean(axis=0) if af is not None else np.ones(AIGEN_FEATURE_DIM) * 0.5
        ai_stds = np.clip(af.std(axis=0), 0.05, 0.3) if af is not None else np.ones(AIGEN_FEATURE_DIM) * 0.15

        if remaining_benign > 0:
            gen = _generate_from_stats(remaining_benign, human_means, human_stds, rng, is_human=True)
            X_list.append(gen)
            y_list.append(np.zeros(remaining_benign, dtype=np.int32))

        if remaining_ai > 0:
            gen = _generate_from_stats(remaining_ai, ai_means, ai_stds, rng, is_human=False)
            X_list.append(gen)
            y_list.append(np.ones(remaining_ai, dtype=np.int32))

    X = np.concatenate(X_list, axis=0)
    y = np.concatenate(y_list, axis=0)
    perm = rng.permutation(len(X))
    X, y = X[perm], y[perm]

    log.info("Training data: %d samples (%d human, %d AI, %d real code used)",
             len(X), int((y == 0).sum()), int(y.sum()), n_human + n_ai)
    return X, y


def _generate_from_stats(n, means, stds, rng, is_human=True):
    X = np.zeros((n, AIGEN_FEATURE_DIM), dtype=np.float32)
    for i in range(n):
        x = rng.normal(means, stds)
        if is_human:
            x[8] = rng.uniform(0.0, 0.25)
            x[12] = rng.uniform(0.5, 0.9)
        else:
            x[8] = rng.uniform(0.5, 0.85)
            x[12] = rng.uniform(0.1, 0.35)
            x[32] = rng.uniform(0.15, 0.5)
        x = np.clip(x, 0.0, 1.0).astype(np.float32)
        X[i] = x
    return X


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    X, y = generate_training_data(n_benign=2000, n_malicious=1000)
    print(f"X shape: {X.shape}, y shape: {y.shape}")
    print(f"AI-gen: {int(y.sum())}, Human: {int(len(y) - y.sum())}")
