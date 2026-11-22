# vegas-freedom

Bootloader unlock and SIM/network unlock scripts for the **Motorola Moto G Power 2026 (`XT2617V` / `vegas`)**.

## Supported Device and Starting State

Two builds are recognized. Only April is hash-pinned. June is a candidate profile with no static modem offsets.

| | April (verified-live) | June (candidate, not verified) |
| --- | --- | --- |
| Profile | `modem/profiles/vegas.json` | `modem/profiles/vegas-june.json` |
| Model / SKU | `moto g power - 2026` (`vegas26`) / `XT2617V` | same |
| Carrier seen | Tracfone | Straight Talk |
| Android / patch | Android `16` / `2026-04-01` | Android `16` / `2026-06-01` |
| Build ID | `W1WEOS36.48-22-3-3-4-2` | `W1WEOS36.48-22-3-3-4-3` |
| Fingerprint | (April stock) | `motorola/vegas_og_sys/vegas26:16/W1WEOS36.48-22-3-3-4-3/7806ed-c4dcce:user/release-keys` |
| Kernel | (April stock) | `5.15.189-android13-8-00018-g9c82b71884fd-ab14885418` |
| Baseband | `MT6835O_NR17.RC.MP.V18.6.6.P107.02.309R` | not pinned |
| Slot | `_a` | `_a` |
| Modem patches | 8 static offsets | none — relocate from the image, or refuse |

Newer OTAs can still move `lk` or `md1img` and break either path.

This guide assumes your device is already:

1. Running `W1WEOS36.48-22-3-3-4-2`, or the June candidate `W1WEOS36.48-22-3-3-4-3` with the extra flags below.
2. Activated or activation-bypassed.
3. Rooted using **DirtyFrag** + **KernelSU** (or an equivalent `uid=0` shell).

**Factory / Rescue Firmware:** If you have a stock factory/rescue firmware package for `W1WEOS36.48-22-3-3-4-2` containing `lk` (`lk.img`/`lk.bin`) and `md1img` (`md1img.img`/`md1img.bin`) you can skip DirtyFrag, KernelSU, and Step 1, and pass those extracted files directly to Step 2 and Step 3. 

## Disclaimer

> Your warranty is now void. You are choosing to make these modifications—I am not responsible for bricked devices, data loss, carrier/service issues, or damaged hardware. Intended strictly for devices you own; no proprietary Motorola/MediaTek firmware binaries, serial numbers, or OEM signing keys are included in this repository.

## Safety Warnings

- **Unlocking the bootloader wipes `userdata`.** Back up any personal data first.
- **Only flash `lk` (active slot `lk_a`) and `md1img_a`.** Never flash `md1img_b`, `preloader`, `gpt`, `pgpt`, `efuse`, `seccfg`, `nvram`, `nvdata`, `protect1`, `protect2`, or `persist`.
- **Do not re-flash stock `lk` after unlocking** (`seccfg` / verified boot behavior depends on the unlock flow; keeping your stock backup offline is for recovery reference only).
- Leave files under `backups/` untouched; generated files are written to `work/`.

---

## Requirements

Install these on your PC before starting:

1. **Python 3.10+** (tested on Python `3.12.10`)
2. **Python packages** (required by `bootloader/` scripts; `scripts/` and `modem/` use stdlib only):
   - `capstone>=5.0,<6.0`
   - `pyasn1>=0.5.0`
3. **Android SDK Platform Tools** (`adb` and `fastboot` on `PATH`)
4. **Motorola USB Drivers** (Windows: install Motorola Mobile Drivers / Motorola Device Manager so Windows detects both `adb` and `fastboot` interfaces)
5. **~13 GB free disk space** on PC for a full stock partition dump (~12.5 GB across 96 files, including `super.img`)

Install Python dependencies from the repo root (`vegas-freedom/`):

```bash
pip install -r requirements.txt
```

Verify PC tools:

```bash
python --version
adb version
fastboot --version
```

---

## Phone Setup: USB Debugging and KernelSU Shell Root

1. Enable Developer Options: **Settings -> About phone -> tap Build number 7 times**.
2. Enable USB Debugging: **Settings -> System -> Developer options -> USB debugging** -> **ON**.
3. Connect the phone to your PC via USB, run:

   ```bash
   adb devices
   ```

   Tap **Allow** (`Always allow from this computer`) on the phone's RSA prompt so `adb devices` lists `device` (not `unauthorized`).
4. Grant root to `adb shell` in KernelSU:
   - Open the **KernelSU** app on the phone.
   - Open the **Superuser** tab.
   - Enable superuser access for **`Shell`**.
5. Confirm root works over ADB:

   ```bash
   adb shell su -c id
   ```

   Expected output contains `uid=0(root)`.

---

## Step 1: Back Up All Stock Partitions

Run the cross-platform Python backup script (recommended on Windows, macOS, and Linux):

```bash
python scripts/backup_partitions.py
```

*(Git Bash / Linux alternative: `bash scripts/backup_partitions.sh`. Do not use PowerShell `>` redirection manually with `adb exec-out`, as PowerShell corrupts binary dumps.)*

What this saves into `backups/stock_YYYYMMDD_HHMMSS/`:

- All unique partitions under `/dev/block/by-name/` (skips `userdata` and whole-disk `sdc`), verified via on-device `sha256sum`
- `gpt_sdc_head_1M.bin` and `gpt_sdc_tail_1M.bin`
- `getprop.txt`, `partitions_by-name.txt`, `proc_partitions.txt`, `name_map.txt`, `SHA256SUMS`

Note the output folder name (referred to as `<BACKUP_DIR>` below, e.g. `stock_20261115_120000`) and confirm `lk_a.img` and `md1img_a.img` are present inside `backups/<BACKUP_DIR>/`.

Optional build check before patching:

```bash
adb shell getprop ro.build.display.id
adb shell getprop gsm.version.baseband
```

April expects `W1WEOS36.48-22-3-3-4-2` and `MT6835O_NR17.RC.MP.V18.6.6.P107.02.309R`.

June expects `W1WEOS36.48-22-3-3-4-3`, security patch `2026-06-01`, and fingerprint `motorola/vegas_og_sys/vegas26:16/W1WEOS36.48-22-3-3-4-3/7806ed-c4dcce:user/release-keys`. Confirm with:

```bash
adb shell getprop ro.build.version.security_patch
adb shell getprop ro.build.fingerprint
adb shell uname -r
```

---

## Step 2: Patch `lk` and Unlock Bootloader

1. Generate and CERT-verify the unlock-capable `lk` image from your stock `lk_a.img` backup:

   ```bash
   python bootloader/patch_lk.py backups/<BACKUP_DIR>/lk_a.img
   ```

   Output:
   - File: `work/lk.unlock-serial.img` (`3,477,904` bytes)
   - Verified `Result: VALID` via `bootloader/tools/verify_mtk_image.py`
   - On stock `W1WEOS36.48-22-3-3-4-2` `lk_a.img`, SHA-256 is `914acfce78939c61a744294ecb686a0865424c36c397878ab6e919be9513eed1`.

2. Reboot into the bootloader and confirm Fastboot sees the phone:

   ```bash
   adb reboot bootloader
   fastboot devices
   ```

   If `fastboot devices` prints nothing on Windows, verify **Motorola USB Drivers** are installed and check Device Manager while the phone is in bootloader mode.

3. Flash `work/lk.unlock-serial.img` to active slot `lk` (`lk_a`) and reboot back into the bootloader so the patched `lk` loads:

   ```bash
   fastboot flash lk work/lk.unlock-serial.img
   fastboot reboot bootloader
   ```

4. Read `serialno`, generate your 20-character unlock key, and run `oem unlock`:

   ```bash
   fastboot getvar serialno
   python bootloader/lk_keygen.py --secret Valeria --serialno <SERIALNO> --count 1
   fastboot oem unlock <KEY>
   ```

   Confirm the unlock prompt on the phone screen if shown (Volume keys + Power). The device will wipe `userdata`.

5. Verify bootloader unlock state (in bootloader):

   ```bash
   fastboot getvar securestate
   ```

   Expected: `securestate: flashing_unlocked`.

---

## Step 3: Build and Flash Network-Unlocked Modem (`md1img_a`)

Use the **stock `md1img_a.img` dumped in Step 1** (`backups/<BACKUP_DIR>/md1img_a.img`).

1. Build, CERT2-sign, and audit the unlocked modem image:

   ```bash
   python modem/unlock_vegas.py build backups/<BACKUP_DIR>/md1img_a.img
   ```

   What this does automatically:
   - Trims trailing `0x00` partition padding (`209,715,200` -> `76,088,352` bytes) and saves the trimmed stock copy to `work/modem_work/md1img_stock_trimmed.img`
   - Verifies stock trimmed SHA-256 (`dab9e69e3bbb009dd2a7907f3603df101e15b11c3f34e1461745b1699c7d4757`)
   - Applies the 8 verified-live `vegas` patches from `modem/profiles/vegas.json` and runs `compare_built`
   - Re-signs CERT2 via `modem/sign_mtk_cert.py`
   - Audits all 23 MKIMG entries (`layout_ok=True integrity=True`)
   - Writes `work/md1img_vegas_patched.signed.img` (`76,088,448` bytes, SHA-256 `f6bd718ffb5c734cdab9e3c9c8c83987bf8e7b71299adb372cf678940b27046a`)

2. Enter bootloader mode (stay in bootloader from Step 2, or after booting Android, re-enable USB Debugging and run `adb reboot bootloader`):

   ```bash
   fastboot getvar securestate
   ```

   Confirm `flashing_unlocked` before flashing.

3. Flash **only `md1img_a`** (never `md1img_b`) and reboot:

   ```bash
   fastboot flash md1img_a work/md1img_vegas_patched.signed.img
   fastboot reboot
   ```

4. Insert a non-Tracfone SIM and verify carrier registration and lock state in Android (with USB Debugging re-enabled):

   ```bash
   adb shell getprop gsm.sim.state
   adb shell getprop gsm.sim.operator.alpha
   adb shell getprop vendor.gsm.sim.slot.lock.device.lock.remain.count
   ```

   Expected with a non-Tracfone SIM:
   - `gsm.sim.state`: `LOADED` (or `LOADED,NOT_READY` if a second slot is empty; a locked modem reports `NETWORK_LOCKED`)
   - `vendor.gsm.sim.slot.lock.device.lock.remain.count`: `5` (unchanged)

---

## Reverting Modem to Stock (Optional)

Flash the trimmed stock `md1img_a` generated during Step 3 (`work/modem_work/md1img_stock_trimmed.img`, `76,088,352` bytes):

```bash
adb reboot bootloader
fastboot flash md1img_a work/modem_work/md1img_stock_trimmed.img
fastboot reboot
```

---

## Implementing the June build (`W1WEOS36.48-22-3-3-4-3`)

June is wired in and **fails closed**. `vegas-june.json` has `status: candidate-unverified`, `stock_md1img.sha256: null`, and an empty patch list. The April offsets are not applied to it.

What is already known from one Straight Talk `XT2617V` on this build, and what is not:

- `lk` dynamic analysis (`unlock-serial`) produced a CERT-valid image. That image was **not flashed**. Do not treat it as verified-live.
- Modem offsets for June are **not known**. Do not paste the April `vegas.json` patch table into the June profile.

To implement it on a dump from this build:

```bash
python bootloader/patch_lk.py --check backups/<BACKUP_DIR>/lk_a.img
python modem/unlock_vegas.py check --profile modem/profiles/vegas-june.json backups/<BACKUP_DIR>/md1img_a.img
```

- `lk` `--check` printing `LIKELY COMPATIBLE` means analysis, repack, and CERT verify passed. It does not mean the phone was unlocked.
- Modem `check` must print `CANDIDATE MATCH`. `INCOMPATIBLE` means stop.
- Only then build a modem image, still unproven on hardware:

```bash
python modem/unlock_vegas.py build --experimental-relocate --profile modem/profiles/vegas-june.json backups/<BACKUP_DIR>/md1img_a.img
```

`build` without `--experimental-relocate` exits. A passing build writes `work/md1img_experimental_patched.signed.img` and `work/modem_work/relocated_profile.json`.

Promote `vegas-june.json` to `verified-live` only after that image is flashed to `md1img_a` and a non-carrier SIM reports `LOADED`. Then copy the measured trimmed size, SHA-256, and the relocated patch list into the profile. Until that happens, leave the hashes null.

## Checking Newer Firmware or Similar MTK Moto Devices

If your device is on a newer OTA build or is a closely related MediaTek Motorola model:

1. **Check `lk` compatibility (dry-run in temp dir, does not write `work/`):**

   ```bash
   python bootloader/patch_lk.py --check <path_to_lk.img>
   ```

   `bootloader/` disassembles `lk` dynamically (`capstone`), so `patch_lk.py` can still work across `lk` revisions when `--check` reports `COMPATIBLE` / `LIKELY COMPATIBLE` (`Result: VALID`).

2. **Check `md1img` compatibility (read-only CATI + opcode scan):**

   ```bash
   python modem/unlock_vegas.py check <path_to_md1img.img>
   ```

   - Default `build` strictly rejects non-`W1WEOS36.48-22-3-3-4-2` modems to prevent flashing wrong offsets.
   - `check` reads `md1_dbginfo` (CATI symbol table) inside the modem image, relocates `custom_check_link_sml_legal_sim_rule`, `sml_sl_Check`, and `smu_check_sml`, and checks whether all 8 microMIPS32 instruction signatures exist at unique verified positions.
   - If `check` reports `CANDIDATE MATCH` (all 8 signatures relocated cleanly) and you choose to test an **unproven/experimental** build at your own risk:

     ```bash
     python modem/unlock_vegas.py build --experimental-relocate <path_to_md1img.img>
     ```

     This writes `work/md1img_experimental_patched.signed.img`, logs the relocated table to `work/modem_work/relocated_profile.json`, and keeps `work/modem_work/md1img_stock_trimmed.img` ready to revert. If `check` reports mismatches (`INCOMPATIBLE`), do not flash.

---

## Repository Layout

```text
vegas-freedom/
├── README.md
├── LICENSE
├── LICENSE-NOTICE.md
├── requirements.txt
├── scripts/
│   ├── backup_partitions.py
│   └── backup_partitions.sh
├── bootloader/
│   ├── LICENSE
│   ├── ACKNOWLEDGEMENTS.md
│   ├── patch_lk.py
│   ├── lk_auto_patch.py
│   ├── lk_keygen.py
│   ├── lk_patch_partition.py
│   ├── lk_repack_signed.py
│   ├── lk_static_analyzer.py
│   ├── liblk/
│   └── tools/
└── modem/
    ├── LICENSE
    ├── unlock_vegas.py
    ├── imageaudit.py
    ├── sign_mtk_cert.py
    ├── parse_mtk_certs.py
    ├── verify_mtk_image.py
    └── profiles/
        ├── vegas.json
        └── vegas-june.json
```

## Credits and Licenses

- **Repository License ([LICENSE](LICENSE)):** GNU Affero General Public License v3.0 (**AGPL-3.0**) to cover combined redistribution with `bootloader/`.
- **Bootloader unlock (`bootloader/`):** Adapted from [crabcakes97/Valhalla](https://github.com/crabcakes97/Valhalla) (built on [Maikyxd/val-protocol](https://github.com/Maikyxd/val-protocol), `AGPL-3.0`, and [R0rt1z2/liblk](https://github.com/R0rt1z2/liblk), `GPL-3.0-or-later`). See [bootloader/LICENSE](bootloader/LICENSE) and [bootloader/ACKNOWLEDGEMENTS.md](bootloader/ACKNOWLEDGEMENTS.md).
- **Modem unlock (`modem/`):** Adapted from [Articfox291/kansas-modem-unlock](https://github.com/Articfox291/kansas-modem-unlock) with the verified `vegas` patch profile (`MIT`, see [modem/LICENSE](modem/LICENSE)).
- See [LICENSE-NOTICE.md](LICENSE-NOTICE.md) for details.
