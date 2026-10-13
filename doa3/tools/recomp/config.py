"""Recompiler configuration: selects the per-XBE data for one release.
DOA3_REGION picks the release (default usa):"""

import os

REGION = os.environ.get("DOA3_REGION", "usa").lower()

if REGION == "usa":
    from .config_usa import *  # noqa: F401,F403
elif REGION == "jpn":
    from .config_jpn import *  # noqa: F401,F403
else:
    raise SystemExit(f"DOA3_REGION={REGION!r}: expected usa or jpn")

_TOOLS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SUFFIX = "" if REGION == "usa" else "_" + REGION

DISASM_OUTPUT_DIR = os.path.join(_TOOLS, "disasm", "output" + _SUFFIX)
FUNC_ID_OUTPUT_DIR = os.path.join(_TOOLS, "func_id", "output" + _SUFFIX)
ABI_OUTPUT_DIR = os.path.join(_TOOLS, "abi_analysis", "output" + _SUFFIX)
RECOMP_OUTPUT_DIR = os.path.join(_TOOLS, "recomp", "output" + _SUFFIX)
GEN_DIR = os.path.join(os.path.dirname(_TOOLS), "src", "game", "recomp", "gen" + _SUFFIX)


def va_to_file_offset(va):
    """Convert virtual address to XBE file offset."""
    for _, sec_va, sec_size, sec_raw in SECTIONS:
        if sec_va <= va < sec_va + sec_size:
            return va - sec_va + sec_raw
    return None


def is_code_address(va):
    """Check if VA is in an executable section (.text or XDK library sections)."""
    if TEXT_VA_START <= va < TEXT_VA_END:
        return True
    # XDK library sections also contain executable code
    for name, sec_va, sec_size, _ in SECTIONS:
        if name in (".text", ".rdata", ".data", "$$XTIMAGE"):
            continue  # skip data sections
        if sec_va <= va < sec_va + sec_size:
            return True
    return False


def is_data_address(va):
    """Check if VA is in .rdata or .data (including BSS)."""
    return RDATA_VA_START <= va <= DATA_VA_END
