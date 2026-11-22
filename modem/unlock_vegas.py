#!/usr/bin/env python3
"""Build, check, and audit the SIM/network-unlocked md1img_a for XT2617V (vegas).

Default 'build' is strictly pinned to verified-live W1WEOS36.48-22-3-3-4-2
(modem/profiles/vegas.json). The June candidate
W1WEOS36.48-22-3-3-4-3 lives in modem/profiles/vegas-june.json and has no
static offsets: pass that profile with --experimental-relocate. 'check'
inspects stock/newer images read-only using md1_dbginfo CATI symbols and
opcode patterns. Relocation is allowed only when all 3 CATI symbols, all 8
microMIPS32 signatures, compare_built, and CERT2 audit pass.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import lzma
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

MODEM_DIR = Path(__file__).resolve().parent
if str(MODEM_DIR) not in sys.path:
    sys.path.insert(0, str(MODEM_DIR))

import imageaudit  # noqa: E402
import sign_mtk_cert as SMC  # noqa: E402


KNOWN_SIGNED_SHA256 = "f6bd718ffb5c734cdab9e3c9c8c83987bf8e7b71299adb372cf678940b27046a"
DEFAULT_PROFILE = MODEM_DIR / "profiles" / "vegas.json"
JUNE_PROFILE = MODEM_DIR / "profiles" / "vegas-june.json"
MD1ROM_BASE_VA = 0x90000000

CATI_PROLOGUE_SPECS = (
    ("force-legal", "custom_check_link_sml_legal_sim_rule", "141e4412", "01d2e0db",
     "custom_check_link_sml_legal_sim_rule entry returns LEGAL(1)."),
    ("sl-check-force", "sml_sl_Check", "491e0821", "01d2e0db",
     "sml_sl_Check entry returns pass(1)."),
)

SMU_GATE_SPECS = (
    ("gate-e6ba", 0x00, "90c89c08", "08900890", "BNEIC a0,1 early gate -> fall through."),
    ("gate-e6e2", 0x28, "70ca5b0f", "08900890", "BNEIC s3,1 per-cat verdict -> fall through."),
    ("gate-e6e8", 0x2E, "f0c87009", "08900890", "BNEIC a3,1 status-byte gate -> fall through."),
    ("gate-e6f0", 0x36, "90c87008", "08900890", "BNEIC a0,1 cat-choice gate -> fall through."),
    ("gate-e6f4", 0x3A, "a0ca6c38", "08900890", "BEQIC s5,7 cat-accounting gate -> fall through."),
    ("gate-e6f8", 0x3E, "608ae000", "08900890", "BEQC zero,s3 verdict-zero gate -> fall through."),
)


def sha256_bytes(data: bytes) -> str:
    """Return lowercase SHA-256 hex digest."""
    return hashlib.sha256(data).hexdigest()


def load_profile(profile_path: Path) -> dict:
    """Load JSON profile and ensure it exists."""
    if not profile_path.is_file():
        raise FileNotFoundError(f"Profile not found: {profile_path}")
    return json.loads(profile_path.read_text(encoding="utf-8"))


def profile_build_id(profile: dict) -> str:
    """Return the firmware id this profile claims, or the verified April id."""
    return str(profile.get("build_id") or "W1WEOS36.48-22-3-3-4-2")


def profile_is_verified(profile: dict) -> bool:
    """True only for a profile whose status is verified-live."""
    return str(profile.get("status") or "verified-live") == "verified-live"


def stock_expectation(profile: dict) -> tuple[int | None, str | None]:
    """Return pinned (size, sha256) or (None, None) when the profile is not filled in."""
    stock = profile.get("stock_md1img") or {}
    size = stock.get("size")
    sha = stock.get("sha256")
    size_i = int(size) if isinstance(size, int) and size > 0 else None
    sha_s = sha.lower() if isinstance(sha, str) and len(sha) == 64 else None
    return size_i, sha_s


def is_exact_stock(trimmed_len: int, trimmed_sha: str, profile: dict) -> bool:
    """True when the trimmed image matches a hash actually stored in the profile."""
    exp_size, exp_sha = stock_expectation(profile)
    if exp_size is None or exp_sha is None:
        return False
    return trimmed_len == exp_size and trimmed_sha == exp_sha


def trim_to_mkimg_eof(raw: bytes, quiet: bool = False) -> bytes:
    """Trim trailing zero padding past the last MKIMG entry (e.g. raw 200 MB dd dumps)."""
    parts = SMC.parse_part_headers(raw)
    if not parts:
        raise ValueError("Input file has no parseable MTK MKIMG headers (not a valid md1img).")

    eof = parts[-1][3]
    if len(raw) < eof:
        raise ValueError(f"Truncated md1img: file size {len(raw)} < MKIMG EOF {eof}.")
    if len(raw) == eof:
        return raw

    tail = raw[eof:]
    if tail.rstrip(b"\x00"):
        raise ValueError(
            f"Non-zero bytes found past MKIMG EOF ({eof} vs file size {len(raw)}); refusing to trim."
        )
    if not quiet:
        print(f"Trimmed zero-padding: {len(raw)} -> {eof} bytes")
    return raw[:eof]


def decompress_dbginfo(raw_dbg: bytes) -> bytes:
    """Decompress LZMA-packed md1_dbginfo CATI symbol table."""
    for off in range(min(64, len(raw_dbg))):
        if raw_dbg[off:off + 3] == b"\x5d\x00\x00":
            try:
                return lzma.decompress(raw_dbg[off:])
            except lzma.LZMAError:
                continue
    raise ValueError("Unable to LZMA-decompress md1_dbginfo CATI symbol table.")


def find_cati_symbol(blob: bytes, name: str) -> tuple[int, int] | None:
    """Locate unique (va_start, va_end) record for a CATI symbol in md1_dbginfo."""
    needle = name.encode("ascii") + b"\x00"
    matches: list[tuple[int, int]] = []
    idx = 0
    while True:
        hit = blob.find(needle, idx)
        if hit < 0:
            break
        if hit >= 9 and blob[hit - 9] == 0 and hit + len(needle) + 8 <= len(blob):
            _prev, start = struct.unpack_from("<II", blob, hit - 8)
            start2, end = struct.unpack_from("<II", blob, hit + len(needle))
            if start == start2 and MD1ROM_BASE_VA <= start < end < 0x94000000:
                matches.append((start, end))
        idx = hit + 1
    if len(matches) != 1:
        return None
    return matches[0]


def va_to_file_off(va: int, rom_doff: int, rom_end: int) -> int:
    """Convert md1rom virtual address to trimmed md1img file offset."""
    off = (va - MD1ROM_BASE_VA) + rom_doff
    if not (rom_doff <= off < rom_end):
        raise ValueError(f"CATI VA {va:#x} -> offset {off:#x} outside md1rom [{rom_doff:#x}, {rom_end:#x}).")
    return off


def parse_file_map(trimmed: bytes, parts: list) -> dict[str, str]:
    """Extract optional key=value metadata from md1_file_map."""
    for _idx, _off, doff, _noff, hdr in parts:
        if hdr.name == "md1_file_map":
            txt = trimmed[doff:doff + hdr.dsize].decode("utf-8", errors="replace")
            out: dict[str, str] = {}
            for line in txt.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip()
            return out
    return {}


def relocate_patches_via_cati(trimmed: bytes) -> tuple[bool, dict, list[dict]]:
    """Dynamically locate all 8 patch points using md1_dbginfo CATI + opcodes."""
    parts = SMC.parse_part_headers(trimmed)
    by_name = {hdr.name: (doff, hdr.dsize) for _idx, _off, doff, _noff, hdr in parts}
    file_map = parse_file_map(trimmed, parts)

    report: dict = {
        "dbginfo_name": file_map.get("md1_dbginfo", "(unknown)"),
        "cati_found": {},
        "checks": [],
        "errors": [],
    }
    if "md1rom" not in by_name or "md1_dbginfo" not in by_name:
        report["errors"].append("Missing md1rom or md1_dbginfo sub-partition.")
        return False, report, []

    rom_doff, rom_dsize = by_name["md1rom"]
    rom_end = rom_doff + rom_dsize
    dbg_doff, dbg_dsize = by_name["md1_dbginfo"]

    try:
        blob = decompress_dbginfo(trimmed[dbg_doff:dbg_doff + dbg_dsize])
    except ValueError as exc:
        report["errors"].append(str(exc))
        return False, report, []

    patches: list[dict] = []
    all_ok = True

    for label, sym, exp_old, new_hex, why in CATI_PROLOGUE_SPECS:
        bounds = find_cati_symbol(blob, sym)
        if not bounds:
            report["errors"].append(f"CATI symbol not uniquely found: {sym}")
            all_ok = False
            continue
        va_s, va_e = bounds
        report["cati_found"][sym] = (hex(va_s), hex(va_e))
        try:
            foff = va_to_file_off(va_s, rom_doff, rom_end)
        except ValueError as exc:
            report["errors"].append(str(exc))
            all_ok = False
            continue
        actual_hex = trimmed[foff:foff + 4].hex()
        matched = actual_hex == exp_old
        if not matched:
            all_ok = False
        report["checks"].append({
            "label": label, "offset": hex(foff), "va": hex(va_s),
            "expected": exp_old, "actual": actual_hex, "matched": matched,
        })
        patches.append({
            "label": label, "offset": hex(foff), "old": exp_old, "new": new_hex,
            "why": f"{why} CATI VA {va_s:#x}.",
        })

    smu_bounds = find_cati_symbol(blob, "smu_check_sml")
    if not smu_bounds:
        report["errors"].append("CATI symbol not uniquely found: smu_check_sml")
        return False, report, []

    smu_va_s, smu_va_e = smu_bounds
    report["cati_found"]["smu_check_sml"] = (hex(smu_va_s), hex(smu_va_e))
    try:
        smu_off = va_to_file_off(smu_va_s, rom_doff, rom_end)
        smu_end = va_to_file_off(smu_va_e - 1, rom_doff, rom_end) + 1
    except ValueError as exc:
        report["errors"].append(str(exc))
        return False, report, []

    smu_slice = trimmed[smu_off:smu_end]
    anchor_pat = bytes.fromhex(SMU_GATE_SPECS[0][2])
    cluster_hits: list[int] = []
    scan_pos = 0
    while True:
        rel = smu_slice.find(anchor_pat, scan_pos)
        if rel < 0:
            break
        if all(
            rel + delta + 4 <= len(smu_slice)
            and smu_slice[rel + delta:rel + delta + 4].hex() == exp_hex
            for _lab, delta, exp_hex, _new, _why in SMU_GATE_SPECS
        ):
            cluster_hits.append(rel)
        scan_pos = rel + 1

    if len(cluster_hits) != 1:
        report["errors"].append(
            f"Expected 1 unique 6-gate microMIPS32 cluster inside smu_check_sml, found {len(cluster_hits)}."
        )
        return False, report, []

    cluster_off = smu_off + cluster_hits[0]
    for lab, delta, exp_hex, new_hex, why in SMU_GATE_SPECS:
        goff = cluster_off + delta
        gva = MD1ROM_BASE_VA + (goff - rom_doff)
        actual_hex = trimmed[goff:goff + 4].hex()
        report["checks"].append({
            "label": lab, "offset": hex(goff), "va": hex(gva),
            "expected": exp_hex, "actual": actual_hex, "matched": True,
        })
        patches.append({"label": lab, "offset": hex(goff), "old": exp_hex, "new": new_hex, "why": why})

    return all_ok and len(patches) == 8, report, patches


def apply_patch_table(stock_bytes: bytes, patches: list[dict]) -> tuple[bytes, list[tuple[str, int, bytes, bytes]]]:
    """Validate old bytes at each offset and apply declared patches."""
    buf = bytearray(stock_bytes)
    table: list[tuple[str, int, bytes, bytes]] = []
    for entry in patches:
        label = entry["label"]
        off = int(entry["offset"], 16) if isinstance(entry["offset"], str) else int(entry["offset"])
        old = bytes.fromhex(entry["old"])
        new = bytes.fromhex(entry["new"])
        if len(old) != len(new):
            raise ValueError(f"Patch '{label}' length mismatch: old={len(old)} new={len(new)}")
        if off + len(old) > len(buf):
            raise ValueError(f"Patch '{label}' offset {off:#x} exceeds image size {len(buf)}")
        actual = bytes(buf[off:off + len(old)])
        if actual != old:
            raise ValueError(
                f"Patch '{label}' at {off:#x}: expected {old.hex()}, found {actual.hex()}. "
                "Wrong firmware or already patched image."
            )
        buf[off:off + len(old)] = new
        table.append((label, off, old, new))
    return bytes(buf), table


def sign_and_audit(
    trimmed: bytes,
    patches: list[dict],
    out_path: Path,
    work_dir: Path,
) -> tuple[bytes, int]:
    """Patch, verify byte-exact diff, CERT2-sign, and audit resulting md1img."""
    work_dir.mkdir(parents=True, exist_ok=True)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    trimmed_path = work_dir / "md1img_stock_trimmed.img"
    trimmed_path.write_bytes(trimmed)

    ok_stock, rep_stock = imageaudit.audit_image(trimmed_path)
    if not ok_stock:
        print("ERROR: Stock md1img structural audit failed:", file=sys.stderr)
        print(imageaudit.render(rep_stock), file=sys.stderr)
        return b"", 1

    patched_raw, table = apply_patch_table(trimmed, patches)
    ok_cmp, rep_cmp = imageaudit.compare_built(trimmed, patched_raw, table)
    if not ok_cmp:
        print(f"ERROR: compare_built audit failed: {rep_cmp['unexplained']}", file=sys.stderr)
        return b"", 1

    raw_patched_path = work_dir / "md1img_patched.raw.img"
    raw_patched_path.write_bytes(patched_raw)

    sign_cmd = [sys.executable, str(MODEM_DIR / "sign_mtk_cert.py"), "-w", str(raw_patched_path), "-o", str(out_path)]
    sign_res = subprocess.run(sign_cmd, text=True, capture_output=True)
    if sign_res.returncode != 0 or not out_path.is_file():
        print(sign_res.stdout)
        print(sign_res.stderr, file=sys.stderr)
        print("ERROR: sign_mtk_cert.py failed.", file=sys.stderr)
        return b"", sign_res.returncode or 1

    ok_out, rep_out = imageaudit.audit_image(out_path)
    print(f"Audit result: {imageaudit.render(rep_out).splitlines()[0]}")
    if not ok_out:
        print("ERROR: Signed md1img audit failed:", file=sys.stderr)
        print(imageaudit.render(rep_out), file=sys.stderr)
        return b"", 1
    return out_path.read_bytes(), 0


def cmd_check(args: argparse.Namespace) -> int:
    profile = load_profile(args.profile.resolve())
    in_path = args.input_md1img.resolve()
    if not in_path.is_file():
        print(f"ERROR: Input file not found: {in_path}", file=sys.stderr)
        return 1

    raw = in_path.read_bytes()
    if not raw:
        print(f"ERROR: Input file is empty: {in_path}", file=sys.stderr)
        return 1
    if sha256_bytes(raw) == KNOWN_SIGNED_SHA256:
        print("Status: Already signed/patched verified-live vegas md1img_a.")
        return 0

    trimmed = trim_to_mkimg_eof(raw)
    trimmed_sha = sha256_bytes(trimmed)
    build_id = profile_build_id(profile)
    exact = is_exact_stock(len(trimmed), trimmed_sha, profile)

    with tempfile.TemporaryDirectory(prefix="md1_chk_") as tmp:
        tmp_img = Path(tmp) / "trimmed.img"
        tmp_img.write_bytes(trimmed)
        ok_aud, rep_aud = imageaudit.audit_image(tmp_img)

    print(f"Trimmed size  : {len(trimmed)} bytes")
    print(f"Trimmed SHA256: {trimmed_sha}")
    print(f"Stock audit   : {imageaudit.render(rep_aud).splitlines()[0]}")
    if not ok_aud:
        print("ERROR: Stock image failed structural/CERT audit:", file=sys.stderr)
        print(imageaudit.render(rep_aud), file=sys.stderr)
        return 1

    ok_reloc, rep_reloc, _patches = relocate_patches_via_cati(trimmed)
    print(f"md1_dbginfo   : {rep_reloc['dbginfo_name']}")
    for sym, bounds in rep_reloc["cati_found"].items():
        print(f"  CATI {sym}: VA [{bounds[0]}, {bounds[1]})")
    for chk in rep_reloc["checks"]:
        mark = "OK" if chk["matched"] else "MISMATCH"
        print(f"  [{mark}] {chk['label']:<15} off={chk['offset']} old={chk['actual']} (expected={chk['expected']})")
    for err in rep_reloc["errors"]:
        print(f"  [ERROR] {err}")

    if exact and profile_is_verified(profile):
        print()
        print(f"Result: COMPATIBLE (VERIFIED-LIVE XT2617V {build_id})")
        print(f"Run   : python modem/unlock_vegas.py build --profile \"{args.profile}\" \"{args.input_md1img}\"")
        return 0

    print()
    if ok_reloc:
        if not profile_is_verified(profile):
            print(f"Result: CANDIDATE MATCH ({profile.get('id', 'profile')} / {build_id})")
            print("Status: profile is not verified-live. Opcode patterns matched; hardware is unproven.")
            print(f"Measured trimmed size  : {len(trimmed)}")
            print(f"Measured trimmed SHA256: {trimmed_sha}")
            print("Record those only after a flashed modem is confirmed. Do not copy the April hash.")
            print(
                "Test build: python modem/unlock_vegas.py build --experimental-relocate "
                f"--profile \"{args.profile}\" \"{args.input_md1img}\""
            )
        else:
            print("Result: CANDIDATE MATCH (UNTESTED ON HARDWARE — 8/8 CATI + microMIPS32 patterns found)")
            print(f"Note  : This is not the verified {build_id} image (newer OTA or a related MTK Moto).")
            print(
                "Test build (experimental): python modem/unlock_vegas.py build "
                f"--experimental-relocate \"{args.input_md1img}\""
            )
        return 0

    print("Result: INCOMPATIBLE (CATI symbols or microMIPS32 opcodes differ; manual reverse engineering required)")
    return 1


def cmd_build(args: argparse.Namespace) -> int:
    profile = load_profile(args.profile.resolve())
    in_path = args.input_md1img.resolve()
    if not in_path.is_file():
        print(f"ERROR: Input file not found: {in_path}", file=sys.stderr)
        return 1

    raw = in_path.read_bytes()
    if not raw:
        print(f"ERROR: Input file is empty: {in_path}", file=sys.stderr)
        return 1
    if sha256_bytes(raw) == KNOWN_SIGNED_SHA256:
        print("ERROR: Input is already the signed patched vegas md1img_a image.", file=sys.stderr)
        return 1

    trimmed = trim_to_mkimg_eof(raw)
    trimmed_sha = sha256_bytes(trimmed)
    build_id = profile_build_id(profile)
    exact_stock = is_exact_stock(len(trimmed), trimmed_sha, profile)
    patches = list(profile.get("modem_unlock", {}).get("patches") or [])

    if not profile_is_verified(profile) and not exact_stock and not args.experimental_relocate:
        print(
            f"ERROR: Profile {profile.get('id')} ({build_id}) is {profile.get('status')}.\n"
            "  No pinned stock md1img hash, so the April patch table must not be applied.\n"
            f"  Tip: python modem/unlock_vegas.py check --profile \"{args.profile}\" \"{args.input_md1img}\"\n"
            "  Then, only if that reports CANDIDATE MATCH:\n"
            "  python modem/unlock_vegas.py build --experimental-relocate "
            f"--profile \"{args.profile}\" \"{args.input_md1img}\"",
            file=sys.stderr,
        )
        return 1

    if not patches and not args.experimental_relocate:
        print(
            f"ERROR: Profile {profile.get('id')} has no static modem patches.\n"
            "  Pass --experimental-relocate so offsets come from this image's CATI table.",
            file=sys.stderr,
        )
        return 1

    if not exact_stock and not args.experimental_relocate:
        exp_size, exp_sha = stock_expectation(profile)
        print(
            f"ERROR: Trimmed stock md1img_a does not match pinned {build_id} image.\n"
            f"  Expected: {exp_size} bytes, sha256={exp_sha}\n"
            f"  Got     : {len(trimmed)} bytes, sha256={trimmed_sha}\n"
            f"  Tip     : python modem/unlock_vegas.py check \"{args.input_md1img}\"",
            file=sys.stderr,
        )
        return 1

    experimental = False
    if (not exact_stock or not patches) and args.experimental_relocate:
        ok_reloc, rep_reloc, patches = relocate_patches_via_cati(trimmed)
        print(f"EXPERIMENTAL RELOCATE: dbginfo={rep_reloc['dbginfo_name']}")
        if not ok_reloc:
            for err in rep_reloc["errors"]:
                print(f"ERROR: {err}", file=sys.stderr)
            for chk in rep_reloc["checks"]:
                if not chk["matched"]:
                    print(
                        f"ERROR: {chk['label']} at {chk['offset']} had {chk['actual']} (expected {chk['expected']})",
                        file=sys.stderr,
                    )
            return 1
        experimental = True

    repo_root = MODEM_DIR.parent
    default_out = repo_root / "work" / (
        "md1img_experimental_patched.signed.img" if experimental else "md1img_vegas_patched.signed.img"
    )
    out_path = (args.output or default_out).resolve()
    work_dir = (args.work_dir or (out_path.parent / "modem_work")).resolve()

    out_bytes, rc = sign_and_audit(trimmed, patches, out_path, work_dir)
    if rc != 0:
        return rc

    if experimental:
        reloc_prof = {
            "schema": 1,
            "id": profile.get("id"),
            "build_id": build_id,
            "status": "experimental-cati-relocated-unproven-on-hardware",
            "dbginfo": rep_reloc["dbginfo_name"],
            "stock_md1img": {"size": len(trimmed), "sha256": trimmed_sha},
            "modem_unlock": {"slot": "md1img_a", "patches": patches},
        }
        (work_dir / "relocated_profile.json").write_text(json.dumps(reloc_prof, indent=2) + "\n", encoding="utf-8")

    out_sha = sha256_bytes(out_bytes)
    print()
    print(f"Patched signed modem ready : {out_path}")
    print(f"Size                       : {len(out_bytes)} bytes")
    print(f"SHA256                     : {out_sha}")
    if out_sha == KNOWN_SIGNED_SHA256:
        print("Verified                   : Exact match to verified-live XT2617V md1img_vegas_patched.signed.img")
    elif experimental:
        print("WARNING                    : EXPERIMENTAL UNTESTED BUILD — keep stock backup and verify revert works!")

    slot = profile["modem_unlock"]["slot"]
    print()
    print("Next steps (bootloader MUST be unlocked):")
    print("  1. adb reboot bootloader")
    print("  2. fastboot getvar securestate        (confirm: flashing_unlocked)")
    print(f"  3. fastboot flash {slot} \"{out_path}\"")
    print("  4. fastboot reboot")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    target = args.image.resolve()
    if not target.is_file():
        print(f"ERROR: File not found: {target}", file=sys.stderr)
        return 1
    ok, rep = imageaudit.audit_image(target)
    print(imageaudit.render(rep))
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Build, check, and audit XT2617V (vegas) SIM-unlocked md1img_a.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_check = sub.add_parser("check", help="Check md1img compatibility (exact match or CATI/opcode relocation).")
    p_check.add_argument("input_md1img", type=Path, help="Path to stock md1img_a.img / md1img.img / md1img.bin")
    p_check.add_argument("--profile", type=Path, default=DEFAULT_PROFILE,
                         help=f"Baseline profile JSON (default: {DEFAULT_PROFILE}; June candidate: {JUNE_PROFILE})")

    p_build = sub.add_parser("build", help="Trim (if raw 200MB dump), patch, CERT2-sign, and audit md1img_a.")
    p_build.add_argument("input_md1img", type=Path, help="Path to backed-up stock md1img_a.img")
    p_build.add_argument("-o", "--output", type=Path, default=None,
                         help="Output signed image path (default: work/md1img_vegas_patched.signed.img)")
    p_build.add_argument("--work-dir", type=Path, default=None,
                         help="Intermediate directory (default: <output dir>/modem_work)")
    p_build.add_argument("--profile", type=Path, default=DEFAULT_PROFILE,
                         help=f"Device profile JSON (default: {DEFAULT_PROFILE}; June candidate: {JUNE_PROFILE})")
    p_build.add_argument("--experimental-relocate", action="store_true",
                         help="Relocate patches from this image's CATI table. Required for vegas-june.json.")

    p_audit = sub.add_parser("audit", help="Run structural + CERT2 digest audit on an md1img file.")
    p_audit.add_argument("image", type=Path, help="Path to md1img image")

    args = parser.parse_args()
    try:
        if args.cmd == "check":
            return cmd_check(args)
        if args.cmd == "build":
            return cmd_build(args)
        if args.cmd == "audit":
            return cmd_audit(args)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
