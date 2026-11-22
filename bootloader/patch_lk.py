#!/usr/bin/env python3
"""Build or dry-check the unlock-serial lk.img for Moto G Power 2026 (XT2617V).

Wraps val-protocol's lk_auto_patch.py and tools/verify_mtk_image.py so all
analysis artifacts stay in work/ rather than the backup directory. Supports
--check for dry-run compatibility checks on newer firmware or related MTK
Motorola devices without writing to work/.

The only hash-pinned lk is April W1WEOS36.48-22-3-3-4-2. June
W1WEOS36.48-22-3-3-4-3 uses the same dynamic analysis and is not hash-pinned.
A CERT-valid image on June is a candidate, not a flashed result.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile


KNOWN_STOCK_LK_SHA256 = "136bf0132fdd028458bb863b39480420badd09259dac99b0f7eba9d4f28bdbdf"
KNOWN_STOCK_LK_TRIMMED_SHA256 = "b6e5a74fd121f9e414b8c00bda5de0a58f37d39f7d3ea99714c2f5eede7934d6"
KNOWN_STOCK_LK_EOF = 3476784
KNOWN_PATCHED_LK_SHA256 = "914acfce78939c61a744294ecb686a0865424c36c397878ab6e919be9513eed1"
KNOWN_PATCHED_LK_SIZE = 3477904
DEFAULT_SECRET = "Valeria"
VERIFIED_BUILD = "W1WEOS36.48-22-3-3-4-2"
JUNE_BUILD = "W1WEOS36.48-22-3-3-4-3"


def sha256_bytes(data: bytes) -> str:
    """Return lowercase SHA-256 hex digest."""
    return hashlib.sha256(data).hexdigest()


def check_dependencies() -> None:
    """Fail fast with install hint if required third-party modules are missing."""
    missing: list[str] = []
    for mod in ("capstone", "pyasn1"):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    if missing:
        raise RuntimeError(
            f"Missing Python packages ({', '.join(missing)}). Run: pip install -r requirements.txt"
        )


def validate_input_lk(input_path: Path) -> bytes:
    """Validate input lk image isn't empty, all-zero (lk_b), or already patched."""
    if not input_path.is_file():
        raise FileNotFoundError(f"Input lk image not found: {input_path}")
    data = input_path.read_bytes()
    if not data:
        raise ValueError(f"Input lk image is empty: {input_path}")
    if not data.rstrip(b"\x00"):
        raise ValueError(
            f"{input_path.name} is all zeros (normal for inactive lk_b.img). Pass stock lk_a.img instead."
        )

    prefix_hash = sha256_bytes(data[:KNOWN_PATCHED_LK_SIZE])
    if len(data) >= KNOWN_PATCHED_LK_SIZE and prefix_hash == KNOWN_PATCHED_LK_SHA256:
        raise ValueError(
            f"{input_path.name} already contains the patched unlock-serial lk image "
            f"(first {KNOWN_PATCHED_LK_SIZE} bytes match {KNOWN_PATCHED_LK_SHA256}). "
            "Pass your pre-unlock stock lk_a.img dump instead."
        )
    return data


def is_known_stock_lk(data: bytes, full_hash: str) -> bool:
    """Return True if data matches either full 16MB or MKIMG-trimmed stock April lk."""
    if full_hash in (KNOWN_STOCK_LK_SHA256, KNOWN_STOCK_LK_TRIMMED_SHA256):
        return True
    return len(data) >= KNOWN_STOCK_LK_EOF and sha256_bytes(data[:KNOWN_STOCK_LK_EOF]) == KNOWN_STOCK_LK_TRIMMED_SHA256


def run_patch_and_verify(
    bootloader_dir: Path,
    input_path: Path,
    output_path: Path,
    analysis_dir: Path,
    secret: str,
) -> tuple[bool, bytes]:
    """Run lk_auto_patch.py + verify_mtk_image.py and return (ok, output_bytes)."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    analysis_dir.mkdir(parents=True, exist_ok=True)

    patch_cmd = [
        sys.executable,
        str(bootloader_dir / "lk_auto_patch.py"),
        str(input_path),
        "-o",
        str(output_path),
        "--analysis-dir",
        str(analysis_dir),
        "--preset",
        "unlock-serial",
        "--key-token-secret",
        secret,
    ]
    res = subprocess.run(patch_cmd)
    if res.returncode != 0 or not output_path.is_file():
        print("ERROR: lk_auto_patch.py failed (this lk image may not be compatible).", file=sys.stderr)
        return False, b""

    verify_cmd = [
        sys.executable,
        str(bootloader_dir / "tools" / "verify_mtk_image.py"),
        str(output_path),
        "-n",
        "lk",
    ]
    v_res = subprocess.run(verify_cmd, text=True, capture_output=True)
    print(v_res.stdout.strip())
    if v_res.returncode != 0 or "Result: VALID" not in v_res.stdout:
        if v_res.stderr:
            print(v_res.stderr.strip(), file=sys.stderr)
        print("ERROR: Generated lk image failed CERT verification.", file=sys.stderr)
        return False, b""
    return True, output_path.read_bytes()


def main() -> int:
    bootloader_dir = Path(__file__).resolve().parent
    repo_root = bootloader_dir.parent
    default_out = repo_root / "work" / "lk.unlock-serial.img"

    parser = argparse.ArgumentParser(
        description="Generate or compatibility-check lk.unlock-serial.img from a stock lk image."
    )
    parser.add_argument("input_lk", type=Path, help="Path to stock lk_a.img / lk.img / lk.bin")
    parser.add_argument("-o", "--output", type=Path, default=default_out,
                        help=f"Output patched image path (default: {default_out})")
    parser.add_argument("--work-dir", type=Path, default=None,
                        help="Directory for static analysis intermediates (default: <output dir>/lk_analysis)")
    parser.add_argument("--secret", default=DEFAULT_SECRET,
                        help=f"Key-token secret (default: {DEFAULT_SECRET})")
    parser.add_argument("--check", action="store_true",
                        help="Dry-run compatibility check in a temp directory without writing to work/")
    args = parser.parse_args()

    input_path = args.input_lk.resolve()
    try:
        check_dependencies()
        data = validate_input_lk(input_path)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    full_hash = sha256_bytes(data)
    known_stock = is_known_stock_lk(data, full_hash)
    print(f"Input : {input_path} ({len(data)} bytes)")
    print(f"SHA256: {full_hash}")
    if known_stock:
        print(f"Status: Matches verified stock XT2617V ({VERIFIED_BUILD}) lk_a.img")
    else:
        print(f"Status: Not the hash-pinned {VERIFIED_BUILD} lk.")
        print(f"        {JUNE_BUILD} is a candidate: dynamic val-protocol analysis still runs.")
        print("        CERT-valid output is not a flashed result. See modem/profiles/vegas-june.json.")

    if args.check:
        with tempfile.TemporaryDirectory(prefix="lk_check_") as tmp:
            tmp_dir = Path(tmp)
            ok, out_bytes = run_patch_and_verify(
                bootloader_dir, input_path, tmp_dir / "lk.check.img", tmp_dir / "analysis", args.secret
            )
            if not ok:
                print("Result: INCOMPATIBLE")
                return 1
            out_hash = sha256_bytes(out_bytes)
            print()
            if known_stock:
                print(f"Result: COMPATIBLE (VERIFIED-LIVE {VERIFIED_BUILD}, test sha256={out_hash})")
            else:
                print(
                    "Result: LIKELY COMPATIBLE (candidate — analysis, patch, repack, and CERT verify passed; "
                    f"test sha256={out_hash})"
                )
                print(f"To generate the image in work/, run: python bootloader/patch_lk.py \"{args.input_lk}\"")
            return 0

    output_path = args.output.resolve()
    analysis_dir = (args.work_dir or (output_path.parent / "lk_analysis")).resolve()
    ok, out_bytes = run_patch_and_verify(bootloader_dir, input_path, output_path, analysis_dir, args.secret)
    if not ok:
        return 1

    out_hash = sha256_bytes(out_bytes)
    print()
    print(f"Patched LK ready : {output_path}")
    print(f"Size             : {len(out_bytes)} bytes")
    print(f"SHA256           : {out_hash}")
    if out_hash == KNOWN_PATCHED_LK_SHA256:
        print(f"Verified         : Exact match to tested XT2617V {VERIFIED_BUILD} lk.unlock-serial.img")
    elif not known_stock:
        print(f"Candidate        : Not the {VERIFIED_BUILD} output hash. Do not treat {JUNE_BUILD} as verified-live.")

    print()
    print("Next steps:")
    print("  1. adb reboot bootloader")
    print("  2. fastboot devices")
    print(f"  3. fastboot flash lk \"{output_path}\"")
    print("  4. fastboot reboot bootloader")
    print("  5. fastboot getvar serialno")
    print(f"  6. python \"{bootloader_dir / 'lk_keygen.py'}\" --secret {args.secret} --serialno <SERIALNO> --count 1")
    print("  7. fastboot oem unlock <KEY>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
