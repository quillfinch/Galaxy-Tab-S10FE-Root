# Porting this root payload to a new firmware version

This guide documents the exact pipeline that produced the
`X520XXSACZH6` payload in this repo. Follow it whenever:

- the tablet accepts an **OTA update with a new kernel build** (any change
  to `ro.build.version.incremental` means a new `ab…` kernel build string
  and potentially shifted symbol offsets — the payload must be re-derived),
- you want to target a **different SM-X520 regional build**, or
- you want to port the method to a **different Samsung device** whose
  kernel is 5.10 or newer with BTF (for older kernels like the Note10+'s
  4.14 this is a research project, not a port — the page/slab and
  rt_mutex_waiter primitives differ).

**Never run a payload on a firmware build it was not derived from.** Wrong
symbol offsets make the kernel-write stages target wrong memory. `root.sh`
guards against this by pinning the model and build string.

The port splits into two halves: the **exploit payload** (offsets from the
new kernel) and the **KernelSU module** (exact vermagic for the new kernel).
Both are required.

## 0. Tooling you need once

```sh
# Samsung firmware downloader (FUS)
cargo install --git https://github.com/topjohnwu/samloader-rs

# Symbol recovery + LZ4 + ELF/BTF parsing
python3 -m venv venv && venv/bin/pip install vmlinux-to-elf lz4 pyelftools

# Android NDK r29 (clang, llvm-nm, llvm-objdump, llvm-strip)
curl -LO https://dl.google.com/android/repository/android-ndk-r29-linux.zip

# bpftool (distro package) and docker, for the KernelSU module build

# Clone the payloads repo (build system + Samsung KernelSU patches)
git clone https://github.com/quillfinch/Root-My-Galaxy-Payloads.git
cd Root-My-Galaxy-Payloads
```

## 1. Identify the exact on-device firmware

With the tablet connected:

```sh
adb shell "getprop ro.product.model; getprop ro.build.version.incremental; \
            getprop ril.official_cscver; uname -r"
```

- `ro.product.model` — must be `SM-X520` for this profile family.
- `ro.build.version.incremental` — the AP/PDA build, e.g. `X520XXSACZH6`.
- `ril.official_cscver` — the exact CSC string for the download request.
- `uname -r` — must stay the same three-part kernel version (`6.6.102`).
  A different kernel version line (e.g. `6.6.112` after an OTA) also
  changes structure layouts — re-derive everything and check the BTF
  layouts in step 3, not just the symbol offsets.

## 2. Download the matching firmware

```sh
samloader download -m SM-X520 -r XAC \
  -v "X520XXSACZH6/X520OXMACZH6/X520XXSACZH6/X520XXSACZH6" -j 16 -d fw
```

The four-part version is `AP/CSC/CP/AP` — build it from the two getprop
values above (`AP` = incremental, `CSC` = official_cscver). If FUS answers
`Info request invalid`, the version string is wrong — never guess, read it
off the device. The download is ~10 GB.

Extract the AP archive's `boot.img.lz4` and carve the kernel:

```sh
unzip fw/*.zip 'AP_*' -d fw && \
python3 tools/extract_kernel.py fw/AP_*.tar.md5 work/
```

`tools/extract_kernel.py` prints the kernel banner (the full
`UTS_RELEASE`), the Image hashes, and writes `work/kernel`,
`work/boot.img`, and `work/vmlinux.btf`. Record the SHA-256s — they are
the payload's provenance.

## 3. Recover symbols and derive every offset

```sh
venv/bin/vmlinux-to-elf work/kernel work/vmlinux.elf
llvm-nm --numeric-sort work/vmlinux.elf > work/vmlinux.nm
venv/bin/python tools/derive_offsets.py work/ > work/offsets.txt
```

`derive_offsets.py` reads `vmlinux.nm` + `vmlinux.btf` and prints every
firmware-dependent constant for `target.h`: ashmem/configfs/workqueue
symbol offsets, the `nfulnl_logger` leak objects, the `random_table`
boot-id entry, `selinux_state.enforcing`, BTF structure layouts
(`file_operations`, `task_struct`, `page`/`slab`, `rt_mutex_waiter`,
`configfs_buffer`, …), and the `sched:sched_blocked_reason` trace-event
index. The recovered ELF base (`0xffffffc080000000` for this device
family) is `KIMAGE_TEXT_BASE`.

Three constants need extra steps:

1. **`SLIDE_TRACEFS_WORKER_CALLER_OFF`** — disassemble `worker_thread`
   and take the instruction *after* the blocking `bl schedule` in the
   idle path (the one right after `worker_enter_idle` /
   `_raw_spin_unlock_irq`):
   ```sh
   llvm-objdump -d --disassemble-symbols=worker_thread work/vmlinux.elf | grep -B1 'bl.*<schedule>'
   ```
   (For both `ZH6` and `ZI2` this came out as `0x000d98dc`.)
2. **`SLIDE_TRACEFS_EVENT_ID`** — `20 + trace-event index` printed by the
   tool (`__TRACE_LAST_TYPE` is 20 in this kernel family). On-device you
   can verify with
   `cat /sys/kernel/tracing/events/sched/sched_blocked_reason/id` once
   you have a root shell.
3. **`SLIDE_PSELECT_WORD_SHIFT`** — qword shift between the pselect6
   fd-set copy and the reclaimed waiter; keep the family value (`0`)
   unless the kernel version line changed.

## 4. Create the target and build the exploit payload

```sh
cd Root-My-Galaxy-Payloads
mkdir -p src/targets/essi-X520<NEWWUILD>
```

Copy `src/targets/essi-X520XXSACZH6/target.h` and replace, per
`work/offsets.txt`:

- the firmware identity block (model, AP/CSC, display build, fingerprint,
  kernel release, boot/kernel SHA-256s);
- every `*_OFF` symbol constant (they almost always shift between
  builds — that is the entire point of re-porting);
- `P0_FINGERPRINT_HEADER` to the new target directory name.

The BTF layout constants (`SIZEOF_FILE_OPERATIONS`, `TASK_*`, `PAGE_*`,
`FAKE_WAITER_*`, `CFG_*`, workqueue structs, `MM_STRUCT_SZ`) and the
family tuning block (`SLIDE_*` strategy values, `P0_ORACLE_*` geometry)
carry over **within the same kernel version family** — but verify each
against the new BTF dump; the tool prints them all.

Generate the P0 fingerprint table from the new raw Image:

```sh
perl tools/generate_p0_fingerprint.pl <workdir>/kernel 0x1f0000 \
  src/targets/essi-X520<NEWBUILD>/p0_fingerprint.h
```

Build:

```sh
make TARGET=essi-X520<NEWBUILD> ANDROID_NDK_HOME=<ndk-r29> all release
```

The release artifact must pass the fixed 104128-byte size gate (the
Makefile enforces it). Use `build/<target>/cve-2026-43499` (the shell
variant) for the ADB flow in this repo.

## 5. Rebuild the KernelSU module with the exact vermagic

The vermagic must match the running kernel's full `UTS_RELEASE` from the
banner, e.g. `6.6.102-android15-8-abX520<NEWBUILD>-4k`.

```sh
git clone https://github.com/tiann/KernelSU.git kernelsu-src
cd kernelsu-src && git checkout b0bc817b4e966aa6aa830834eaf6ef765d821d40
git apply <payloads-repo>/kernelsu/patches/KernelSU-v3.2.5-samsung-kdp-rkp-defex.patch
git apply <payloads-repo>/kernelsu/patches/ksud-v3.2.5-late-load-ephemeral.patch
```

Build the module in the android15-6.6 DDK container (each `docker run`
starts from the pristine image — always sed from the *default* release
string, not a previous run's replacement):

```sh
docker run --rm -v "$PWD:/workspace" -w /workspace/kernel \
  ghcr.io/ylarod/ddk-min:android15-6.6-20260313 bash -lc '
    set -e
    sed -i "s/6\.6\.127-4k-g46a034eca005-dirty/6.6.102-android15-8-abX520<NEWBUILD>-4k/g" \
      "$KDIR/include/generated/utsrelease.h" "$KDIR/include/config/kernel.release"
    make clean >/dev/null 2>&1 || true
    CONFIG_KSU=m CONFIG_KSU_SAMSUNG_KDP=y CONFIG_KSU_SAMSUNG_RKP=y \
    CONFIG_KSU_SAMSUNG_DEFEX=y CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT=y \
    CC=clang make -j$(nproc)
    modinfo ./kernelsu.ko | grep vermagic
    ./check_symbol ./kernelsu.ko <workdir>/vmlinux.elf && echo check_symbol-PASS
  '
```

`CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT=y` is mandatory on Exynos 1580: live
text patching panics in Samsung/Exynos EL2 (documented on the A56 port).
`check_symbol` must pass against **your recovered target ELF**, not just
the DDK's. Then audit every undefined import resolves by name in the
target `vmlinux.nm` (see `kernelsu/tools/audit_module_against_target.py`
or a plain `llvm-nm -u` + diff), `llvm-strip -d` the module, copy it to
`userspace/ksud/bin/aarch64/android15-6.6_kernelsu.ko`, and rebuild ksud
for the device (cargo, NDK r29, `aarch64-linux-android` target — set
`LIBCLANG_PATH` to the NDK's `…/prebuilt/linux-x86_64/lib`, not `bin`).

## 6. Update this repo and validate on hardware

1. Replace `bin/x520.so` (shell payload), `bin/cve-2026-43499-root`, and
   `bin/ksud`, and update the firmware pin + hashes in `root.sh` and
   `README.md`.
2. Test on a **freshly booted** device (wait ≥1 minute after boot), one
   attempt first: a clean miss aborts without crashing; **reboot before
   retrying** after a failure that reached the waiter-write stage.
3. Success criteria, in order: tracefs caller resolves at
   `base + SLIDE_TRACEFS_WORKER_CALLER_OFF`; `uid=2000 -> 0` in the
   payload log; `-c id` returns `uid=0`; `--late-load` exits 0;
   `/proc/modules` shows `kernelsu … Live`; SELinux ends **Enforcing**.
4. Only then update the support feed (`support/targets-v3.json` in the
   payloads repo) and record the run in a `docs/SM-X520-*.md` note.

## Hard-won gotchas

- **DEFEX Safeplace** kills any direct exec of a `/data` binary by a
  system shell (`[DEFEX] Safeplace violation [task=sh …]`). The root
  helper's `--late-load` exists precisely to bind-mount the staged ksud
  over `/system/bin/logcat` and exec that path — never exec the loader
  directly. The helper expects it at `/data/local/tmp/ksud-s25u-kdp`
  (`KSU_LOADER_PATH`) and `.ksud-stage`; both must hold the current build.
- The race is probabilistic. First validated boot: one attempt missed
  cleanly; after a reboot the very first attempt rooted the device. Expect
  1–8 attempts and treat a stacked-failure boot as stale.
- `/data/adb` is DEFEX-protected for non-KernelSU contexts; do not
  interpret `Permission denied` there as a failed install — check
  `/proc/modules` instead.
- The exploit sets SELinux permissive while it works; KernelSU restores
  enforcing during late-load. Ending states other than Enforcing mean
  something is wrong.
