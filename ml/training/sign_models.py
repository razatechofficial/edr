#!/usr/bin/env python3
"""Sign ONNX model files with Ed25519 and verify signatures.

Each ``.onnx`` file in the model directory gets a ``.onnx.sig`` companion
containing the raw 64-byte Ed25519 signature.  The public key is emitted as
a hex string for embedding in the agent configuration.

Usage:
    # Generate a new key pair and sign all models:
    python sign_models.py sign --model-dir ./output --key-dir ./keys

    # Sign with an existing private key:
    python sign_models.py sign --model-dir ./output --key-dir ./keys --existing-key

    # Verify signatures:
    python sign_models.py verify --model-dir ./output --public-key-hex <hex>
    python sign_models.py verify --model-dir ./output --key-dir ./keys
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger("sign_models")


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------


def generate_key_pair(key_dir: Path) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    key_dir.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_path = key_dir / "model_signing.key"
    pub_path = key_dir / "model_signing.pub"
    hex_path = key_dir / "model_signing_pubkey.hex"

    priv_bytes = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    priv_path.write_bytes(priv_bytes)
    logger.info("Private key saved → %s", priv_path)

    pub_bytes = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    pub_path.write_bytes(pub_bytes)
    logger.info("Public key saved → %s", pub_path)

    raw_pub = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    hex_str = raw_pub.hex()
    hex_path.write_text(hex_str + "\n")
    logger.info("Public key (hex) → %s", hex_str)
    logger.info("Hex saved → %s", hex_path)

    return private_key, public_key


def load_private_key(key_dir: Path) -> Ed25519PrivateKey:
    priv_path = key_dir / "model_signing.key"
    if not priv_path.exists():
        raise FileNotFoundError(f"Private key not found: {priv_path}")
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    priv_bytes = priv_path.read_bytes()
    key = load_pem_private_key(priv_bytes, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("Key is not Ed25519")
    logger.info("Loaded private key from %s", priv_path)
    return key


def load_public_key_from_hex(hex_str: str) -> Ed25519PublicKey:
    raw = bytes.fromhex(hex_str.strip())
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey as PubCls

    return PubCls.from_public_bytes(raw)


def load_public_key_from_dir(key_dir: Path) -> Ed25519PublicKey:
    hex_path = key_dir / "model_signing_pubkey.hex"
    if hex_path.exists():
        return load_public_key_from_hex(hex_path.read_text().strip())
    pub_path = key_dir / "model_signing.pub"
    if pub_path.exists():
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        key = load_pem_public_key(pub_path.read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("Key is not Ed25519")
        return key
    raise FileNotFoundError(f"No public key found in {key_dir}")


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def sign_model(model_path: Path, private_key: Ed25519PrivateKey) -> Path:
    data = model_path.read_bytes()
    signature = private_key.sign(data)
    sig_path = model_path.with_suffix(model_path.suffix + ".sig")
    sig_path.write_bytes(signature)
    logger.info("Signed %s → %s (%d bytes)", model_path.name, sig_path.name, len(signature))
    return sig_path


def verify_model(model_path: Path, public_key: Ed25519PublicKey) -> bool:
    sig_path = model_path.with_suffix(model_path.suffix + ".sig")
    if not sig_path.exists():
        logger.error("Signature file not found: %s", sig_path)
        return False

    data = model_path.read_bytes()
    signature = sig_path.read_bytes()

    try:
        public_key.verify(signature, data)
        logger.info("  %s — signature valid ✓", model_path.name)
        return True
    except Exception as exc:
        logger.error("  %s — signature INVALID: %s", model_path.name, exc)
        return False


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_sign(args: argparse.Namespace) -> None:
    model_dir = Path(args.model_dir)
    key_dir = Path(args.key_dir)
    onnx_files = sorted(model_dir.glob("*.onnx"))
    if not onnx_files:
        logger.error("No .onnx files found in %s", model_dir)
        sys.exit(1)

    if args.existing_key:
        private_key = load_private_key(key_dir)
        public_key = private_key.public_key()
    else:
        logger.info("Generating new Ed25519 key pair …")
        private_key, public_key = generate_key_pair(key_dir)

    for p in onnx_files:
        sign_model(p, private_key)

    raw_pub = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    hex_str = raw_pub.hex()
    logger.info("\n=== Agent Configuration ===")
    logger.info("Add to configs/agent.yaml under ml.model_signing_key:")
    logger.info("  model_signing_key: \"%s\"", hex_str)

    # Verify all just-signed models.
    logger.info("\nVerifying signatures …")
    all_ok = True
    for p in onnx_files:
        if not verify_model(p, public_key):
            all_ok = False

    if all_ok:
        logger.info("All %d models signed and verified ✓", len(onnx_files))
    else:
        logger.error("Some signatures failed verification")
        sys.exit(1)


def cmd_verify(args: argparse.Namespace) -> None:
    model_dir = Path(args.model_dir)
    onnx_files = sorted(model_dir.glob("*.onnx"))
    if not onnx_files:
        logger.error("No .onnx files found in %s", model_dir)
        sys.exit(1)

    if args.public_key_hex:
        public_key = load_public_key_from_hex(args.public_key_hex)
    elif args.key_dir:
        public_key = load_public_key_from_dir(Path(args.key_dir))
    else:
        logger.error("Provide --public-key-hex or --key-dir")
        sys.exit(1)

    all_ok = True
    for p in onnx_files:
        if not verify_model(p, public_key):
            all_ok = False

    if all_ok:
        logger.info("All %d models verified ✓", len(onnx_files))
    else:
        logger.error("Verification failed for one or more models")
        sys.exit(1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    p = argparse.ArgumentParser(description="Sign and verify ONNX models with Ed25519")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("sign", help="Sign all .onnx files in a directory")
    s.add_argument("--model-dir", type=str, required=True, help="Directory containing .onnx files")
    s.add_argument("--key-dir", type=str, required=True, help="Directory for key storage")
    s.add_argument("--existing-key", action="store_true", help="Use existing key pair instead of generating new")

    v = sub.add_parser("verify", help="Verify signatures of .onnx files")
    v.add_argument("--model-dir", type=str, required=True, help="Directory containing .onnx + .onnx.sig files")
    v.add_argument("--public-key-hex", type=str, default=None, help="Ed25519 public key as hex string")
    v.add_argument("--key-dir", type=str, default=None, help="Directory containing public key files")

    args = p.parse_args()
    dispatch = {"sign": cmd_sign, "verify": cmd_verify}
    dispatch[args.command](args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception:
        logger.exception("Failed")
        sys.exit(1)
