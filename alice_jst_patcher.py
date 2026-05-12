#!/usr/bin/env python3
"""

AI Usage Disclaimer
------------
I'd like to note that most of this code was written using a custom harness with Gwen 3.6 35B for IDA along with most of the generation of code here.
This just shows how powerful LLMs can be for automating reverse engineering with an proper harness and tool kit.


alice_jst_patcher.py - Universal JST timezone patcher for Alicesoft games

Patches the statically-linked MSVC CRT in Alicesoft (System4 / NSystem) game
executables to force the C runtime timezone to JST (UTC+9, no DST) regardless
of the system timezone. Removes the "must set PC clock to Japan time"
requirement that breaks some titles outside Japan.

How it works
------------
The CRT's `tzset_from_system_nolock` reads Windows TIME_ZONE_INFORMATION via
GetTimeZoneInformation and stores Bias * 60 in the global `_timezone`. The
game script reads local time through SystemService.GetDate() / GetTime(),
which fan out to __localtime64_s -> _timezone. Wrong timezone = wrong local
time = script crash.

Patch 1 (20 bytes): replace the dynamic `mov [ebp-4], ecx` + StandardBias
conditional with a hardcoded `mov [ebp-4], -32400` followed by NOPs.
Patch 2 (1 byte):  change the DaylightDate `jz short` to `jmp short`,
forcing `_daylight = 0` and `_dstbias = 0` (Japan has no DST).

Targets
-------
- 32-bit PE executables (i386) built with statically-linked MSVC CRT.
- Verified on a 2020-era Alicesoft title. Likely works on most modern
  Alicesoft titles built with the same CRT version.

Usage
-----
    python alice_jst_patcher.py game.exe
    python alice_jst_patcher.py --dry-run game.exe
    python alice_jst_patcher.py --verbose game1.exe game2.exe
    python alice_jst_patcher.py --no-backup game.exe
    python alice_jst_patcher.py --restore game.exe   # revert from .bak

Exit codes
----------
    0  success (patched or already patched)
    1  invalid arguments
    2  I/O or file format error
    3  signature not found / ambiguous
"""

from __future__ import annotations

import argparse
import os
import shutil
import struct
import sys
from datetime import datetime
from pathlib import Path
from typing import Iterator

__version__ = "1.0.0"

# JST is UTC+9, so _timezone (seconds WEST of UTC) = -32400.
# As a signed little-endian 32-bit int: 0x70 0x81 0xFF 0xFF.
JST_TIMEZONE_LE = bytes([0x70, 0x81, 0xFF, 0xFF])  # = -32400

# Patch 1 replacement: `mov dword ptr [ebp-4], -32400` + 13 NOPs = 20 bytes.
PATCH1_NEW = bytes([0xC7, 0x45, 0xFC]) + JST_TIMEZONE_LE + bytes([0x90] * 13)
PATCH1_LEN = len(PATCH1_NEW)
assert PATCH1_LEN == 20

# First 7 bytes of patch 1 (used to detect already-patched binaries).
PATCH1_HEAD = PATCH1_NEW[:7]

# Patch 2: single byte change, 0x74 (jz short) -> 0xEB (jmp short).
PATCH2_OLD = 0x74
PATCH2_NEW = 0xEB

# Anchor signature: the original 28-byte sequence at the patch site, plus
# the first byte of the DST jz. This is highly distinctive - two
# `mov [ebp-4], ecx` instructions separated by an `imul eax, edx, 0x3C`
# block, followed by another `cmp [mem], bx; jz` is essentially unique
# to tzset_from_system_nolock.
#
# Bytes (None = wildcard):
#   89 4D FC                   mov [ebp-4], ecx           [patch 1 starts here]
#   66 39 1D ?? ?? ?? ??       cmp word ptr [mem], bx     (StandardDate.wMonth)
#   74 08                      jz +8
#   6B C2 3C                   imul eax, edx, 0x3C
#   03 C8                      add ecx, eax
#   89 4D FC                   mov [ebp-4], ecx           [patch 1 ends here]
#   66 39 1D ?? ?? ?? ??       cmp word ptr [mem], bx     (DaylightDate.wMonth)
#   74                         jz short ??                [patch 2 byte]
ANCHOR_SIG: list[int | None] = [
    0x89, 0x4D, 0xFC,
    0x66, 0x39, 0x1D, None, None, None, None,
    0x74, 0x08,
    0x6B, 0xC2, 0x3C,
    0x03, 0xC8,
    0x89, 0x4D, 0xFC,
    0x66, 0x39, 0x1D, None, None, None, None,
    0x74,
]
ANCHOR_LEN = len(ANCHOR_SIG)
assert ANCHOR_LEN == 28
PATCH2_REL_OFF = ANCHOR_LEN - 1  # 27: offset within match of the `74` byte

# Already-patched signature: same site but with patches applied. Used so the
# tool can recognize and report on binaries that were patched previously
# (whether by this tool or a prior IDA patch session).
#
#   C7 45 FC 70 81 FF FF       mov dword ptr [ebp-4], -32400
#   90 x 13                    NOPs
#   66 39 1D ?? ?? ?? ??       cmp word ptr [mem], bx     (DaylightDate.wMonth, untouched)
#   EB                         jmp short                  (changed from jz)
PATCHED_SIG: list[int | None] = (
    list(PATCH1_NEW)
    + [0x66, 0x39, 0x1D, None, None, None, None, PATCH2_NEW]
)
assert len(PATCHED_SIG) == ANCHOR_LEN

# IMAGE_SCN_MEM_EXECUTE
SCN_EXECUTE = 0x20000000

_USE_COLOR = sys.stdout.isatty() and os.name != "nt" or os.environ.get("FORCE_COLOR")


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _USE_COLOR else s


def info(msg: str) -> None:
    print(msg)


def ok(msg: str) -> None:
    print(_c("32", f"  OK   {msg}"))


def warn(msg: str) -> None:
    print(_c("33", f"  WARN {msg}"))


def err(msg: str) -> None:
    print(_c("31", f"  ERR  {msg}"), file=sys.stderr)


def step(msg: str) -> None:
    print(f"  ...  {msg}")


class PESection:
    __slots__ = ("name", "vaddr", "vsize", "roff", "rsize", "chars")

    def __init__(self, name: str, vaddr: int, vsize: int, roff: int, rsize: int, chars: int):
        self.name = name
        self.vaddr = vaddr
        self.vsize = vsize
        self.roff = roff
        self.rsize = rsize
        self.chars = chars

    @property
    def is_exec(self) -> bool:
        return bool(self.chars & SCN_EXECUTE)


class PEInfo:
    __slots__ = ("image_base", "is_32bit", "sections")

    def __init__(self, image_base: int, is_32bit: bool, sections: list[PESection]):
        self.image_base = image_base
        self.is_32bit = is_32bit
        self.sections = sections

    def file_off_to_va(self, off: int) -> int | None:
        for s in self.sections:
            if s.roff <= off < s.roff + s.rsize:
                return self.image_base + s.vaddr + (off - s.roff)
        return None

    def exec_ranges(self) -> list[tuple[int, int]]:
        return [(s.roff, s.roff + s.rsize) for s in self.sections if s.is_exec]


def parse_pe(data: bytes) -> PEInfo | None:
    """Parse a PE file. Returns None if invalid or unsupported."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 0x18 > len(data) or data[pe_off : pe_off + 4] != b"PE\x00\x00":
        return None
    machine = struct.unpack_from("<H", data, pe_off + 4)[0]
    if machine not in (0x014C, 0x8664):
        return None
    is_32bit = machine == 0x014C

    num_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_hdr_size = struct.unpack_from("<H", data, pe_off + 0x14)[0]
    opt_hdr_off = pe_off + 0x18
    if opt_hdr_off + opt_hdr_size > len(data):
        return None

    opt_magic = struct.unpack_from("<H", data, opt_hdr_off)[0]
    if opt_magic == 0x10B:  # PE32
        image_base = struct.unpack_from("<I", data, opt_hdr_off + 0x1C)[0]
    elif opt_magic == 0x20B:  # PE32+
        image_base = struct.unpack_from("<Q", data, opt_hdr_off + 0x18)[0]
    else:
        return None

    sect_off = opt_hdr_off + opt_hdr_size
    if sect_off + num_sections * 40 > len(data):
        return None

    sections: list[PESection] = []
    for i in range(num_sections):
        s = sect_off + i * 40
        name = bytes(data[s : s + 8]).rstrip(b"\x00").decode("ascii", "replace")
        vsize = struct.unpack_from("<I", data, s + 8)[0]
        vaddr = struct.unpack_from("<I", data, s + 12)[0]
        rsize = struct.unpack_from("<I", data, s + 16)[0]
        roff = struct.unpack_from("<I", data, s + 20)[0]
        chars = struct.unpack_from("<I", data, s + 36)[0]
        sections.append(PESection(name, vaddr, vsize, roff, rsize, chars))

    return PEInfo(image_base, is_32bit, sections)


def find_signature(
    data: bytes, sig: list[int | None], start: int, end: int
) -> Iterator[int]:
    """Yield offsets in [start, end) where `sig` matches. None = wildcard."""
    sig_len = len(sig)
    last = end - sig_len
    if last < start:
        return
    # Quick reject using the first concrete byte.
    first = sig[0]
    i = start
    while i <= last:
        if first is not None and data[i] != first:
            i += 1
            continue
        match = True
        for j in range(1, sig_len):
            sb = sig[j]
            if sb is not None and data[i + j] != sb:
                match = False
                break
        if match:
            yield i
        i += 1


class PatchLocation:
    __slots__ = ("file_off", "va", "already_patched", "jz_disp")

    def __init__(self, file_off: int, va: int | None, already_patched: bool, jz_disp: int):
        self.file_off = file_off
        self.va = va
        self.already_patched = already_patched
        self.jz_disp = jz_disp

    @property
    def patch2_file_off(self) -> int:
        return self.file_off + PATCH2_REL_OFF


def find_patch_locations(data: bytes, pe: PEInfo, verbose: bool = False) -> list[PatchLocation]:
    """Locate every position in the file matching the tzset signature.

    Also matches already-patched binaries so we can report "already patched"
    instead of "signature not found" when re-running on a patched EXE.
    """
    ranges = pe.exec_ranges() or [(0, len(data))]
    unpatched_hits: list[int] = []
    patched_hits: list[int] = []
    for start, end in ranges:
        unpatched_hits.extend(find_signature(data, ANCHOR_SIG, start, end))
        patched_hits.extend(find_signature(data, PATCHED_SIG, start, end))

    if verbose:
        step(
            f"scan: {len(unpatched_hits)} unpatched / "
            f"{len(patched_hits)} already-patched anchor(s)"
        )

    locs: list[PatchLocation] = []
    seen: set[int] = set()

    for off in sorted(set(unpatched_hits)):
        if off in seen:
            continue
        # Validate: JZ displacement at offset 28 should be plausible (0x10-0x20).
        # The inner DST block is ~22 bytes; this filters false positives.
        jz_disp_off = off + PATCH2_REL_OFF + 1
        if jz_disp_off >= len(data):
            continue
        jz_disp = data[jz_disp_off]
        if not (0x10 <= jz_disp <= 0x20):
            if verbose:
                step(f"reject 0x{off:x}: jz disp 0x{jz_disp:02x} outside expected range")
            continue
        # Verify both memory operands point into the same struct (same 256-byte
        # window). They reference fields of TIME_ZONE_INFORMATION.
        m1 = struct.unpack_from("<I", data, off + 6)[0]
        m2 = struct.unpack_from("<I", data, off + 23)[0]
        if abs(m2 - m1) > 0x100:
            if verbose:
                step(f"reject 0x{off:x}: mem operands not co-located (0x{m1:x} / 0x{m2:x})")
            continue
        va = pe.file_off_to_va(off)
        locs.append(PatchLocation(off, va, already_patched=False, jz_disp=jz_disp))
        seen.add(off)

    for off in sorted(set(patched_hits)):
        if off in seen:
            continue
        jz_disp_off = off + PATCH2_REL_OFF + 1
        if jz_disp_off >= len(data):
            continue
        jz_disp = data[jz_disp_off]
        if not (0x10 <= jz_disp <= 0x20):
            continue
        # Only validate the trailing cmp memory operand (the first half of the
        # patched region is NOPs / immediate, no useful operand there).
        m2 = struct.unpack_from("<I", data, off + 23)[0]
        if not (0x400000 <= m2 < 0x10000000):  # plausible in-image address
            if verbose:
                step(f"reject patched 0x{off:x}: implausible mem operand 0x{m2:x}")
            continue
        va = pe.file_off_to_va(off)
        locs.append(PatchLocation(off, va, already_patched=True, jz_disp=jz_disp))
        seen.add(off)

    locs.sort(key=lambda l: l.file_off)
    return locs


def verify_patch_in_buffer(data: bytes, loc: PatchLocation) -> bool:
    if data[loc.file_off : loc.file_off + len(PATCH1_HEAD)] != PATCH1_HEAD:
        return False
    if data[loc.patch2_file_off] != PATCH2_NEW:
        return False
    return True


def apply_patch(data: bytearray, loc: PatchLocation) -> None:
    data[loc.file_off : loc.file_off + PATCH1_LEN] = PATCH1_NEW
    data[loc.patch2_file_off] = PATCH2_NEW


def make_backup(path: Path, backup_dir: Path | None) -> Path:
    if backup_dir is not None:
        backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest = backup_dir / f"{path.name}.{stamp}.bak"
    else:
        dest = path.with_suffix(path.suffix + ".bak")
        if dest.exists():
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest = path.with_suffix(path.suffix + f".{stamp}.bak")
    shutil.copy2(path, dest)
    return dest


def write_atomic(path: Path, data: bytes) -> None:
    """Write to a tmp file in the same directory, then replace. Avoids
    leaving a half-written EXE if interrupted."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    

def process_file(path: Path, args: argparse.Namespace) -> int:
    info(f"=== {path} ===")
    try:
        raw = path.read_bytes()
    except OSError as e:
        err(f"cannot read file: {e}")
        return 2

    pe = parse_pe(raw)
    if pe is None:
        err("not a valid PE executable")
        return 2
    if not pe.is_32bit:
        err("64-bit PE not supported (CRT layout differs)")
        return 2

    step(f"image_base=0x{pe.image_base:x}  sections={len(pe.sections)}  size={len(raw):,} bytes")

    locs = find_patch_locations(raw, pe, verbose=args.verbose)

    if not locs:
        err("no patch location found - this binary doesn't match the expected CRT pattern")
        err("(might be a different CRT version, a non-MSVC build, or already heavily modified)")
        return 3

    if len(locs) > 1:
        warn(f"found {len(locs)} candidate locations")
        for i, loc in enumerate(locs):
            tag = "patched" if loc.already_patched else "unpatched"
            warn(f"  [{i}] file=0x{loc.file_off:x}  va=0x{loc.va or 0:x}  ({tag})")

    needs = [l for l in locs if not l.already_patched]
    done = [l for l in locs if l.already_patched]

    for loc in done:
        info(f"  --   va=0x{loc.va or 0:x} already patched")

    targets = list(locs) if args.force else needs
    if not targets:
        ok("nothing to do (already patched)")
        return 0

    for loc in targets:
        info(
            f"  +    patch va=0x{loc.va or 0:x}  "
            f"(file=0x{loc.file_off:x})  "
            f"jz disp=0x{loc.jz_disp:02x}"
        )

    if args.dry_run:
        info(_c("36", "  --   dry run: no changes written"))
        return 0

    data = bytearray(raw)
    for loc in targets:
        apply_patch(data, loc)

    # Sanity: verify our edits actually landed in the buffer.
    for loc in targets:
        if not verify_patch_in_buffer(bytes(data), loc):
            err(f"internal error: post-patch verification failed at 0x{loc.file_off:x}")
            return 2

    if not args.no_backup:
        try:
            backup = make_backup(path, args.backup_dir)
            step(f"backup -> {backup}")
        except OSError as e:
            err(f"failed to create backup: {e}")
            return 2

    try:
        write_atomic(path, bytes(data))
    except OSError as e:
        err(f"failed to write patched file: {e}")
        err("(make sure the game is not running and the file isn't read-only)")
        return 2

    ok(f"patched {len(targets)} location(s) - game should now run on any timezone")
    return 0


def restore_file(path: Path, args: argparse.Namespace) -> int:
    info(f"=== {path} (restore) ===")
    # Look for the most recent .bak file matching this name.
    candidates: list[Path] = []
    direct = path.with_suffix(path.suffix + ".bak")
    if direct.exists():
        candidates.append(direct)
    candidates.extend(sorted(path.parent.glob(path.name + ".*.bak")))
    if args.backup_dir:
        bd = Path(args.backup_dir)
        if bd.exists():
            candidates.extend(sorted(bd.glob(path.name + ".*.bak")))
    if not candidates:
        err("no backup found")
        return 2
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    src = candidates[0]
    step(f"restoring from {src}")
    try:
        shutil.copy2(src, path)
    except OSError as e:
        err(f"restore failed: {e}")
        return 2
    ok("restored")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="alice_jst_patcher",
        description="Universal JST timezone patcher for Alicesoft games.",
        epilog=(
            "Forces the CRT _timezone to -32400 (UTC+9) and disables DST so games "
            "that require Japan timezone work on any system."
        ),
    )
    ap.add_argument("files", nargs="+", help="Executable(s) to patch")
    ap.add_argument("--dry-run", action="store_true", help="Show what would be patched; write nothing")
    ap.add_argument("--no-backup", action="store_true", help="Skip creating .bak file (not recommended)")
    ap.add_argument("--backup-dir", help="Directory for backups (default: alongside input)")
    ap.add_argument("--force", action="store_true", help="Re-apply patch even if already patched")
    ap.add_argument("--restore", action="store_true", help="Restore from most recent backup (.bak)")
    ap.add_argument("--verbose", "-v", action="store_true", help="Verbose scan output")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args(argv)

    if args.backup_dir:
        args.backup_dir = Path(args.backup_dir)

    rc = 0
    for raw_path in args.files:
        p = Path(raw_path)
        if not p.exists():
            err(f"{p}: not found")
            rc = max(rc, 2)
            print()
            continue
        if not p.is_file():
            err(f"{p}: not a regular file")
            rc = max(rc, 2)
            print()
            continue
        action = restore_file if args.restore else process_file
        rc = max(rc, action(p, args))
        print()
    return rc


if __name__ == "__main__":
    sys.exit(main())
