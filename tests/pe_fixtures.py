"""Generate a pair of real binaries for the opt-in integration test.

The pair is a pristine copy of a small system binary plus a copy whose entry
point code has been overwritten with NOPs. Both stay valid executables (no byte
shifts, no size changes), so Ghidra analyses them normally and a real diff
reports at least one *modified* function.
"""

from __future__ import annotations

import os
import shutil
import struct
import sys
from pathlib import Path

PATCH_LEN = 24
NOP_X86 = b"\x90" * PATCH_LEN
NOP_ARM64 = b"\x1f\x20\x03\xd5" * (PATCH_LEN // 4)


def default_source() -> Path | None:
    """Pick a small, self-contained executable to patch."""
    if sys.platform == "win32":
        root = Path(os.environ.get("SYSTEMROOT", r"C:\Windows"))
        for name in ("winver.exe", "where.exe", "help.exe", "cmd.exe"):
            candidate = root / "System32" / name
            if candidate.is_file():
                return candidate
        return None
    for name in ("/bin/true", "/usr/bin/true", "/bin/ls", "/usr/bin/env"):
        candidate = Path(name)
        if candidate.is_file():
            return candidate
    return None


class FixtureError(RuntimeError):
    """Raised when a fixture binary cannot be patched."""


def entry_point_offset(data: bytes) -> int:
    """Return the file offset of the entry point for a PE or ELF image."""
    if data[:2] == b"MZ":
        return _pe_entry_offset(data)
    if data[:4] == b"\x7fELF":
        return _elf_entry_offset(data)
    raise FixtureError("Unsupported executable format (expected PE or ELF).")


def _pe_entry_offset(data: bytes) -> int:
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise FixtureError("Missing PE signature")
    coff = e_lfanew + 4
    (num_sections,) = struct.unpack_from("<H", data, coff + 2)
    (opt_size,) = struct.unpack_from("<H", data, coff + 16)
    opt = coff + 20
    (magic,) = struct.unpack_from("<H", data, opt)
    if magic not in (0x10B, 0x20B):
        raise FixtureError(f"Unsupported optional header magic 0x{magic:x}")
    (entry_rva,) = struct.unpack_from("<I", data, opt + 16)

    section_table = opt + opt_size
    for index in range(num_sections):
        off = section_table + index * 40
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
            "<IIII", data, off + 8
        )
        if virtual_address <= entry_rva < virtual_address + max(virtual_size, raw_size):
            return raw_pointer + (entry_rva - virtual_address)
    raise FixtureError(f"Entry RVA 0x{entry_rva:x} is not mapped by any section")


def _elf_entry_offset(data: bytes) -> int:
    elf_class = data[4]
    if elf_class == 2:
        (entry,) = struct.unpack_from("<Q", data, 0x18)
        (phoff,) = struct.unpack_from("<Q", data, 0x20)
        (phentsize,) = struct.unpack_from("<H", data, 0x36)
        (phnum,) = struct.unpack_from("<H", data, 0x38)
        fmt, vaddr_index, offset_index = "<IIQQQQQQ", 2, 1
    elif elf_class == 1:
        (entry,) = struct.unpack_from("<I", data, 0x18)
        (phoff,) = struct.unpack_from("<I", data, 0x1C)
        (phentsize,) = struct.unpack_from("<H", data, 0x2A)
        (phnum,) = struct.unpack_from("<H", data, 0x2C)
        fmt, vaddr_index, offset_index = "<IIIIIIII", 2, 1
    else:
        raise FixtureError(f"Unsupported ELF class {elf_class}")

    for index in range(phnum):
        fields = struct.unpack_from(fmt, data, phoff + index * phentsize)
        p_type = fields[0]
        if p_type != 1:  # PT_LOAD
            continue
        p_offset = fields[offset_index]
        p_vaddr = fields[vaddr_index]
        p_filesz = fields[5] if elf_class == 2 else fields[4]
        if p_vaddr <= entry < p_vaddr + p_filesz:
            return p_offset + (entry - p_vaddr)
    raise FixtureError(f"Entry point 0x{entry:x} is not inside a PT_LOAD segment")


def make_pair(dest: Path, source: Path | None = None) -> tuple[Path, Path]:
    """Write ``<dest>/old.bin`` and ``<dest>/new.bin`` and return both paths."""
    source = source or default_source()
    if source is None or not source.is_file():
        raise FixtureError("No suitable system binary found to build fixtures from.")

    dest.mkdir(parents=True, exist_ok=True)
    suffix = source.suffix or ".bin"
    old_path = dest / f"old{suffix}"
    new_path = dest / f"new{suffix}"
    shutil.copyfile(source, old_path)

    raw = source.read_bytes()
    offset = entry_point_offset(raw)
    machine = struct.unpack_from("<H", raw, 0x3C + 4 + 2)[0] if raw[:2] == b"MZ" else None
    patched = bytearray(raw)
    replacement = NOP_ARM64 if machine == 0xAA64 else NOP_X86
    end = min(offset + len(replacement), len(patched))
    if end - offset < 4:
        raise FixtureError("Entry point is too close to the end of the file to patch.")
    patched[offset:end] = replacement[: end - offset]
    new_path.write_bytes(bytes(patched))
    return old_path, new_path
