#!/usr/bin/env python3
"""Extract and identify the kernel Image from Samsung firmware.

Usage: extract_kernel.py <AP tar.md5 or boot.img.lz4> <outdir>

From an AP tar: pulls boot.img.lz4, decompresses it, carves the kernel
(header v4: u32 kernel_size @ 0x08, kernel at 0x1000), locates the raw BTF
blob, and prints the boot identity (banner, sizes, SHA-256s).

Requires: pip install lz4
"""
import hashlib
import lz4.frame
import re
import struct
import subprocess
import sys
import tarfile
from pathlib import Path

src, outdir = Path(sys.argv[1]), Path(sys.argv[2])
outdir.mkdir(parents=True, exist_ok=True)

if src.name.endswith(".tar.md5"):
    with tarfile.open(src) as tf:
        member = next(m for m in tf.getmembers() if m.name.endswith("boot.img.lz4"))
        with tf.extractfile(member) as fh:
            compressed = fh.read()
else:
    compressed = src.read_bytes()

boot = lz4.frame.decompress(compressed)
(outdir / "boot.img").write_bytes(boot)

kernel_size = struct.unpack_from("<I", boot, 0x08)[0]
kernel = boot[0x1000:0x1000 + kernel_size]
(outdir / "kernel").write_bytes(kernel)

text_off, image_size, flags = struct.unpack_from("<QQQ", boot, 0x1008)
banner = re.search(rb"Linux version [^\x00]+", boot).group(0).decode()

# Raw BTF blob: validate the complete header, not just the magic bytes.
image = kernel
prefix = b"\x9f\xeb\x01\x00"
candidates, cursor = [], 0
while True:
    start = image.find(prefix, cursor)
    if start < 0:
        break
    cursor = start + 1
    if start + 24 > len(image):
        continue
    magic, version, btf_flags, header_len, type_off, type_len, str_off, str_len = \
        struct.unpack_from("<HBBIIIII", image, start)
    if magic != 0xEB9F or version != 1 or btf_flags != 0 or header_len < 24:
        continue
    end = start + header_len + max(type_off + type_len, str_off + str_len)
    if end > len(image) or image[start + header_len + str_off] != 0:
        continue
    candidates.append((start, end))
if len(candidates) == 1:
    s, e = candidates[0]
    (outdir / "vmlinux.btf").write_bytes(image[s:e])
    btf = f"vmlinux.btf ({e - s} bytes) at image [{hex(s)}, {hex(e)})"
else:
    btf = f"WARNING: {len(candidates)} BTF candidates, none written"

print(f"banner      : {banner}")
print(f"boot.img    : {len(boot)} bytes  SHA-256 {hashlib.sha256(boot).hexdigest().upper()}")
print(f"kernel      : {len(kernel)} bytes  SHA-256 {hashlib.sha256(kernel).hexdigest().upper()}")
print(f"Image header: text_offset={hex(text_off)} image_size={hex(image_size)} flags={hex(flags)}")
print(f"BTF         : {btf}")
