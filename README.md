# Galaxy Tab S10 FE — ADB root (CVE-2026-43499 / GhostLock + KernelSU)

One-command root for the **Samsung Galaxy Tab S10 FE (Wi-Fi, SM-X520,
Exynos 1580)** via `adb`, with **no bootloader unlock, no Odin flash, and no
Knox-tripping boot-image modification**. Works on the locked, stock,
enforcing firmware.

Uses the Root My Galaxy port of the CVE-2026-43499 ("GhostLock") kernel
exploit — a ~15-year-old rtmutex/futex-PI stack use-after-free fixed
upstream only in 2026 — followed by a late-loaded KernelSU module built
with the exact target vermagic and Samsung KDP/RKP/DEFEX handling.

## Supported device

| Requirement | Value |
| --- | --- |
| Model | `SM-X520` (Galaxy Tab S10 FE, Wi-Fi) |
| Firmware (AP/PDA) | `X520XXSACZH6` (Aug 2026, Android 16, One UI 8) |
| Kernel | `6.6.102-android15-8-abX520XXSACZH6-4k` |

The payload is **pinned to this exact build**: kernel symbol offsets differ
between firmware builds. `root.sh` refuses to run on anything else. If you
updated to a newer build, re-derive the payload for it by following
[PORTING.md](PORTING.md) — the complete step-by-step procedure with the
tools in `tools/`.

## Usage

```sh
./root.sh                 # from any machine with adb + the tablet connected
ATTEMPTS=16 ./root.sh     # more race attempts if the first session misses
```

Requirements: USB debugging enabled + authorized, `adb` in PATH.

What it does:

1. pushes the shell exploit payload, the root helper, and the patched
   `ksud` to `/data/local/tmp`;
2. runs the GhostLock chain from the adb-shell context (KASLR leak →
   PI-futex stack reclamation → fake fops → configfs arbitrary kernel R/W →
   uid 0);
3. stages the KernelSU loader through the DEFEX-safe path and loads the
   KernelSU module (`kernelsu … Live`, SELinux stays **Enforcing**);
4. verifies the module in `/proc/modules`.

After it completes, install the [KernelSU Manager](https://github.com/tiann/KernelSU/releases)
(v3.2.5, versionCode 32525) to grant superuser to apps.

**Root is per-boot.** No boot image is modified, so every reboot reverts to
fully stock — re-run `./root.sh` (or `adb shell /data/local/tmp/root-x520.sh`,
which the script leaves on the tablet) after each boot.

## Troubleshooting

- **Exploit attempt fails** (clean abort, no crash): reboot the tablet and
  run again — the race is probabilistic and the second boot succeeded on
  attempt 1 during validation. Do not stack many attempts on one boot after
  a waiter-write stage failure.
- **`device unauthorized`**: accept the USB-debugging RSA prompt on the
  tablet (or revoke authorizations and replug).
- **OTA updates**: do not accept a firmware update with a new kernel build
  until the payload is re-ported for it — see
  [PORTING.md](PORTING.md) for the full re-porting procedure.

## Porting to other firmware versions / devices

Everything needed to re-derive this payload for a new build (after an OTA,
or for other Samsung devices on kernel 5.10+ with BTF) is documented in
[PORTING.md](PORTING.md): firmware identification and download, kernel
extraction, symbol/BTF recovery, offset derivation (`tools/derive_offsets.py`),
P0 fingerprint generation, the exploit build, the vermagic-exact KernelSU
module rebuild, on-device validation, and the gotchas learned from the
hardware bring-up.

## Provenance & credits

- Port, builds, and hardware validation record for this device:
  [docs/SM-X520-X520XXSACZH6.md](https://github.com/quillfinch/Root-My-Galaxy-Payloads/blob/main/docs/SM-X520-X520XXSACZH6.md)
  in the payloads fork.
- Exploit chain and per-target build system:
  [BuSung-dev/Root-My-Galaxy](https://github.com/BuSung-dev/Root-My-Galaxy)
  and [BuSung-dev/Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads)
  (Apache-2.0).
- Original CVE-2026-43499 exploit research: Nebula Security
  ("IonStack"/GhostLock), whose public exploit this chain is ported from.
- [KernelSU](https://github.com/tiann/KernelSU) (GPL-3.0 for kernel parts)
  with the Samsung KDP/RKP/DEFEX late-load patches from the payloads repo;
  `ksud` here additionally accepts `late-load --ephemeral` as passed by the
  Root My Galaxy root helper.

Binaries in `bin/` were built from the sources above with NDK r29 and the
android15-6.6 DDK:

- `bin/x520.so` — the `essi-X520XXSACZH6` shell payload, SHA-256
  `fcc7bb493841ad96677fbe66262d8af360149a166750f78de55410af5be1a14d`
- `bin/cve-2026-43499-root` — the root helper / umh daemon / late-load guard
- `bin/ksud` — embeds the vermagic-exact
  `6.6.102-android15-8-abX520XXSACZH6-4k` KernelSU module (no-patch-text
  Samsung build, plus `late-load --ephemeral`)

Use only on devices you own or are explicitly authorized to test.

## License

Apache-2.0, inherited from Root-My-Galaxy / Root-My-Galaxy-Payloads
(see `LICENSE`). KernelSU components remain under their own GPL-3.0 terms.
