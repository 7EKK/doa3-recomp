"""Per-XBE recompiler data: Dead or Alive 3 (Japan) (En,Ja,Fr,De,Es,It).
Target:"""

SECTIONS = [
    # (name, va_start, raw_size, raw_addr)
    (".text",     0x00011000, 0x001CB330, 0x00001000),
    ("D3D",       0x001DC340, 0x0000E9FC, 0x001CD000),
    ("D3DX",      0x001EE0A0, 0x00002EA0, 0x001DC000),
    ("XGRPH",     0x001F0F60, 0x000002FC, 0x001DF000),
    ("DSOUND",    0x001F1260, 0x0001B214, 0x001E0000),
    ("PSGSFD00",  0x0020C6C0, 0x00003390, 0x001FC000),
    ("PSGSFD_I",  0x0020FA60, 0x000001F0, 0x00200000),
    ("PSGSFD_B",  0x0020FC60, 0x000006C0, 0x00201000),
    ("PSGSFD_P",  0x00210320, 0x00000430, 0x00202000),
    ("XPP",       0x00210760, 0x0000729C, 0x00203000),
    (".rdata",    0x00217A00, 0x0003A650, 0x0020B000),
    (".data",     0x00252060, 0x001B5040, 0x00246000),
    ("DOLBY",     0x00CA2560, 0x00006D84, 0x003FC000),
    ("$$XTIMAGE", 0x00CA9300, 0x00002800, 0x00403000),
]

TEXT_VA_START = 0x00011000
TEXT_VA_END = 0x001DC340     # end of .text = start of D3D section
RDATA_VA_START = 0x00217A00
RDATA_VA_END = 0x00252060    # start of .data
DATA_VA_START = 0x00252060
DATA_VA_END = 0x00CABB00     # base (0x10000) + image size (0xC9BB00)
KERNEL_THUNK_ADDR = 0x00217A00
ENTRY_POINT = 0x0018CB89

# CRT _ftol2 (float -> int64 in edx:eax, truncating).
FTOL2_ADDR = 0x001B8B98

# __SEH_prolog4 / __SEH_epilog4 (the lifter reloads ebp after calls to them).
SEH_PROLOG = 0x001B84A4
SEH_EPILOG = 0x001B84DD

# D3D masks guest physical addresses to 26 bits (64 MB); the port's low heap
# is 80 MB, so those masks are widened to 27 bits.
PHYS_MASK_REWRITE = {0x03FFFFFF: 0x07FFFFFF}
PHYS_MASK_RANGE = (0x001DC340, 0x001EE0A0)   # D3D section

# Dropped fall-throughs are restored in every code section. USA restores the
# XDK ones at listed sites (FALLTHROUGH_KEEP_XDK:
FALLTHROUGH_RANGES = [(0x00011000, 0x001DC340),    # .text
                      (0x001DC340, 0x001EE0A0),    # D3D
                      (0x001EE0A0, 0x001F0F60),    # D3DX
                      (0x001F0F60, 0x001F125C),    # XGRPH
                      (0x001F1260, 0x0020C474),    # DSOUND
                      (0x0020C6C0, 0x00210750),    # PSGSFD00/_I/_B/_P
                      (0x00210760, 0x002179FC)]    # XPP
FALLTHROUGH_KEEP_XDK = set()

LEGACY_ICALL_FUNCS = set()
LEGACY_FTOL2_CALL_FUNCS = set()
LEGACY_FNSTSW_AH_FUNCS = set()
BUG14_LATCH_FUNCS = set()
LEGACY_CONDTAIL_SYNC_FUNCS = set()
LEGACY_NO_JT_EXTEND_FUNCS = set()

# config_usa's hand fall-through and carrier entries, located here by their
# instructions (the library code moved by 0x296C0);
FALLTHROUGH_EXTRA = {
    0x001B401E: (0x001B4143, True),
}
FALLTHROUGH_SKIP = {0x0005DB59, 0x0019E2B6, 0x001A99CE}
FALLTHROUGH_RET = {}
FALLTHROUGH_SYNC = {0x0017F4EF: True, 0x001B7BF8: False}

CARRIER_HOLD_FUNCS = set()
# Fragments with no frame of their own that call out and then hand off to a
# fragment reading ebp from g_seh_ebp:
CARRIER_INHERIT_FUNCS = {
    0x0006F889, 0x0006FA33, 0x00077870, 0x00097FF6, 0x00098F9D, 0x00099333,
    0x0009EA62, 0x000ABFEB, 0x000AE7C0, 0x000B11B4, 0x000BAED0, 0x00137464,
    0x0015EE06, 0x0016E740, 0x00177A03, 0x0017AE5E, 0x0017F4EF, 0x0018AA69,
    0x0018AAE0, 0x0018AB07, 0x0018AE04, 0x0018B007, 0x0018FF97, 0x00197A50,
    0x0019B66C, 0x001B7370, 0x001B837B, 0x001BFC80, 0x001DDBB0, 0x001E1680,
    0x001F3D82, 0x001F46E2, 0x001F6CD3, 0x001F6FD5, 0x001F6FF7, 0x002121B7,
    0x002129BE, 0x00213BA0, 0x00214792,
}
CARRIER_SPLIT_PROLOGUE = set()
CARRIER_SPLIT_EPILOGUE = set()

CMPXCHG_UNFIXED = set()
FTOL2_TAIL_INLINE_FUNCS = set()
SHARED_JCC_UNFIXED = set()
SHARED_JCC_ARITH_UNFIXED = set()
ENTRY_FLAGS_UNFIXED = set()
DEFERRED_CMP_UNFIXED = set()
CLOBBERED_FLAGS_UNFIXED = set()

# How the generated tree names bodies that recomp_manual_jpn.c replaces or
# wraps (address -> name suffix), and the overridden bodies it keeps under #if 0.
BODY_SUFFIX = {
    0x00190B00: '_gen',   # ADXF mount poll (recomp_manual_jpn.c)
    0x000A47E0: '_gen', 0x000A4C10: '_gen',   # movie start / leave (recomp_manual_jpn.c)
    0x0019EA30: '_gen',   # movie frame blit -> host presenter
    # Sofdec guards ported from USA (recomp_manual_jpn.c)
    0x001B03C0: '_gen', 0x001A5340: '_gen', 0x001A0E00: '_gen', 0x001A65B0: '_gen',
    0x001A6680: '_gen', 0x001A6690: '_gen',
    0x000A4680: '_gen',   # movie frame blit: only while playing
    0x001A0BD0: '_gen',   # sfdec create: attach the type-5 picture index
    0x001F42B6: '_gen',   # DirectSound deferred-command list walk: null this
    0x001E982D: '_gen', 0x001E57ED: '_gen', 0x001E52E6: '_gen', 0x001E56F2: '_gen', 0x001E2E00: '_gen', 0x0017BCE0: '_gen',   # ESP_FIX (USA list)
    0x00196D80: '_gen',   # ADX stream refill: uninitialised stream (channel field 0)
    0x001A3380: '_gen',   # sfdec video unit loop: bad handle / queue index
    # callee-saved register restore (recomp_manual_jpn.c BOOT_MARK2_ABI_ESI)
    0x00049560: '_gen', 0x0006DF00: '_gen', 0x0006DF70: '_gen', 0x0006DFE0: '_gen',
    0x0006E1A0: '_gen', 0x0006F6D0: '_gen', 0x00083290: '_gen', 0x00084C10: '_gen',
    0x00087310: '_gen', 0x001A7840: '_gen', 0x001A80C0: '_gen', 0x001A81E0: '_gen',
    0x001A8240: '_gen', 0x001C6AE0: '_gen', 0x001C79F0: '_gen', 0x001DC3F0: '_gen',
    0x001DC5E0: '_gen', 0x001DCE10: '_gen', 0x001DD210: '_gen', 0x001DE150: '_gen',
    0x001DE470: '_gen', 0x001DE590: '_gen', 0x001DF690: '_gen', 0x001DFF50: '_gen',
    0x001E0310: '_gen', 0x001E05A0: '_gen', 0x001E44C0: '_gen', 0x001E926C: '_gen',
    0x001E927A: '_gen', 0x001E9B7E: '_gen', 0x001F13E4: '_gen', 0x001F1F01: '_gen',
    0x001F2084: '_gen', 0x001F2AA7: '_gen', 0x001F3810: '_gen', 0x001F39A7: '_gen',
    0x001F4964: '_gen', 0x001F54A6: '_gen', 0x001F765C: '_gen', 0x001F77E4: '_gen',
    0x001F7973: '_gen', 0x001F7C1F: '_gen', 0x001F7F66: '_gen', 0x001F8BF2: '_gen',
    0x001F8C5F: '_gen', 0x001F8CC7: '_gen', 0x001F8E18: '_gen', 0x001F8E72: '_gen',
    0x001A0D10: '_gen', 0x001A77C0: '_gen',   # sfdec state machine guard, substream broadcast
    0x00211A96: '_xppgen', 0x00211B07: '_xppgen',   # XInput state (recomp_manual_jpn.c)
    # D3D push buffer (recomp_manual_jpn.c): KickOff, SetFence, fence wait,
    # make-space core.
    0x001E27C0: '_gen', 0x001E28B0: '_gen', 0x001E2960: '_gen', 0x001E2A50: '_gen',
    0x0007D5C0: '_gen',
    0x00083510: '_gen',
    0x00084FD0: '_gen',
    0x00085820: '_gen',
    0x00085D70: '_gen',
    0x00086980: '_gen',
    0x000869A0: '_gen',
    0x00086F50: '_gen',
    0x00089AC0: '_gen',
    0x0008A240: '_gen',
    0x000A4D40: '_gen',
    0x000A5B40: '_gen',
    0x000A65B0: '_gen',
    0x000A6680: '_gen',
    0x0017C3A0: '_gen',
    0x00180490: '_gen',
    0x0018A4F0: '_gen',
    0x0018AB51: '_gen',
    0x0018B090: '_gen',
    0x0018B83A: '_gen',
    0x0018BDD1: '_gen',
    0x0018BEB9: '_gen',
    0x0018C934: '_gen',
    0x0018C9C0: '_gen',
    0x0018C9D3: '_gen',
    0x0018EA60: '_unused',
    0x001907A0: '_gen',
    0x00190EF0: '_gen',
    0x00192400: '_gen',
    0x00192C10: '_gen',
    0x001931E0: '_gen',
    0x001938E0: '_gen',
    0x00193F40: '_gen',
    0x00194530: '_gen',
    0x001946A0: '_gen',
    0x00194750: '_gen',
    0x001947F0: '_gen',
    0x00195180: '_gen',
    0x00195510: '_gen',
    0x00195670: '_gen',
    0x00198C60: '_gen',
    0x0019A330: '_gen',
    0x0019A5E0: '_gen',
    0x0019A660: '_gen',
    0x0019A690: '_gen',
    0x0019B040: '_gen',
    0x0019B0F0: '_gen',
    0x0019B380: '_gen',
    0x0019BD40: '_gen',
    0x0019BF30: '_gen',
    0x0019C120: '_gen',
    0x0019C4E0: '_gen',
    0x0019E640: '_gen',
    0x0019E9B0: '_gen',
    0x0019EAB0: '_gen',
    0x0019ED00: '_gen',
    0x0019EFC0: '_gen',
    0x0019F460: '_gen',
    0x0019F7D0: '_gen',
    0x001A0010: '_gen',
    0x001A0260: '_gen',
    0x001A0310: '_gen',
    0x001A0390: '_gen',
    0x001A06F0: '_gen',
    0x001A0A70: '_gen',
    0x001A0B60: '_gen',
    0x001A0CB0: '_gen',
    0x001A1730: '_gen',
    0x001A1770: '_gen',
    0x001A2630: '_gen',
    0x001A3480: '_gen',
    0x001A4E70: '_gen',
    0x001A5DC0: '_gen',
    0x001A6020: '_gen',
    0x001A6030: '_gen',
    0x001A6220: '_gen',
    0x001A6300: '_oldcf',
    0x001A7680: '_gen',
    0x001A77B0: '_gen',
    0x001A7C00: '_gen',
    0x001A7F10: '_gen',
    0x001A7FC0: '_gen',
    0x001A89D0: '_gen',
    0x001A8AC0: '_gen',
    0x001A8B30: '_gen',
    0x001A9860: '_gen',
    0x001A99B0: '_gen',
    0x001A9E80: '_gen',
    0x001AA0F0: '_gen',
    0x001AA1E0: '_gen',
    0x001AA4B0: '_gen',
    0x001AAEE0: '_gen',
    0x001AB510: '_gen',
    0x001AFA30: '_gen',
    0x001AFA80: '_gen',
    0x001B0980: '_gen',
    0x001B72AE: '_gen',
    0x001B73D0: '_gen',
    0x001B7C48: '_gen',
    0x001B7CB0: '_oldjt',
    0x001B8F50: '_gen',
    0x001BA00F: '_gen',
    0x001BA0AF: '_gen',
    0x001BA0EC: '_gen',
    0x001BA214: '_gen',
    0x001C63EB: '_gen',
    0x001C650C: '_gen',
    0x001C65D8: '_gen',
    0x001C663F: '_gen',
    0x001C66A2: '_gen',
    0x001DC340: '_gen',
    0x001E0570: '_gen',
    0x001E0900: '_gen',
    0x001E24B0: '_gen',
    0x001E96A5: '_gen',
    0x001EE0A0: '_gen',
    0x001EEA0C: '_gen',
    0x001F13AF: '_gen',
    0x001F1D89: '_gen',
    0x001F1DF9: '_gen',
    0x001F1E95: '_gen',
    0x001F1ED1: '_gen',
    0x001F2227: '_gen',
    0x001F2A27: '_gen',
    0x001F2CAB: '_gen',
    0x001F91CD: '_gen',
    0x0020FCA0: '_gen',
    0x0021157D: '_xppgen',
    0x0021159F: '_xppgen',
    0x00211823: '_xppgen',
    0x00211898: '_xppgen',
    0x002118A4: '_xppgen',
}

IF0_BODIES = {0x0018DEBA, 0x0018E2DE, 0x000A5C60, 0x0018FDF5, 0x001926B0, }   # CRT heap creator + allocator (recomp_manual_jpn.c), repeated _initterm(__xi), CRI watchdog

# Dispatch table (recomp_lookup): None searches the whole table.
DISPATCH_SEARCH_LIMIT = None
DISPATCH_EXCLUDE = set()

# CRT static initializers run by main.c's _initterm walk (doa3_crt_lookup),
# from __xi_a..__xi_z (0x00252060..0x0025206C) and __xc_a..__xc_z...
CRT_INIT_FUNCS = [
    0x001BB70A, 0x001BD480, 0x001DDD90, 0x001F708A, 0x001F7095, 0x001DC2D0,
    0x001DC2B0, 0x001DBDC0, 0x001DBDE0, 0x001DBC90, 0x001DBCA0, 0x001DBCE0,
    0x001DBD30, 0x001DBD50, 0x001D9200, 0x001DB490, 0x001DBC70, 0x001D79D0,
    0x001D7A30, 0x001D8B70, 0x001D91E0, 0x001D6E80, 0x001D7420, 0x001D7530,
    0x001D7650, 0x001D1180, 0x001D3410, 0x001D6E60, 0x001CE000, 0x001CE9A0,
    0x001D03D0, 0x001D0470, 0x001CB390, 0x001CBD10, 0x001CD280, 0x001CD2F0,
    0x001CB360, 0x001CB340, 0x001CB350, 0x001CB270, 0x001CABD0, 0x001CAC30,
    0x001CACA0, 0x001CAD00, 0x001CAD40, 0x001CADA0, 0x001CADE0, 0x001CAE50,
    0x001CAEB0, 0x001CAF10, 0x001CAF50, 0x001CAFC0, 0x001CB000, 0x001CB090,
    0x001CB110, 0x001CB1B0, 0x001CB210, 0x001CABC0, 0x001CABA0, 0x001CAA20,
    0x001CAA10, 0x001CA9E0, 0x001CA690,
]

# In functions.json but never emitted into the tree.
NOT_EMITTED = set()

# Hand-written bodies for entry points only data refers to.
SEED_BODIES = {}

# Hand edits no rule produces: function -> [(lifted lines, edited lines, occurrence)].
HAND_EDITS = {}
