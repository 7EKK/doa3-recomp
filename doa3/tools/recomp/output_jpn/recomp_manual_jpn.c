/*
 * Suggested port of recomp_manual.c to the Japanese release, written by
 * tools/recomp/port_manual.py (src/game/recomp/recomp_manual_jpn.c is the
 * hand-maintained file). Addresses are translated to the Japanese build;
 * port_manual.txt lists every item left out. Comments keep USA addresses
 * where none maps.
 */
/**
 * Dead or Alive 3 - Manually implemented / overridden recompiled functions
 *
 * Functions the automatic recompiler can't handle correctly (mid-function
 * entry points, hardware register polls, SEH continuations, etc.) are
 * hand-written here using the same register model and calling conventions
 * as the generated code, then registered in g_manual_funcs[] so RECOMP_ICALL
 * and the dispatch chain pick them up ahead of the generated versions.
 *
 * This starts empty. Add overrides during boot bring-up; record each one in
 * doa3/NOTES.md under "Runtime Architecture" so it survives a regen.
 */

#define RECOMP_GENERATED_CODE
#include "recomp_funcs.h"
#include <stddef.h>
#include <stdio.h>
#include <intrin.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "online/netplay_session.h"
#include "online/netplay.h"

   /* CaptureStackBackTrace (SBH alloc-loop diagnostics) */

extern uint32_t xbox_HeapAlloc(uint32_t size, uint32_t alignment);
extern void xbox_fiber_yield(void);
extern int  xbox_fiber_active(void);
extern void xbox_fiber_wake(uint32_t event_va);

/* ── XAPI fiber API → host fibers ─────────────────────────────────────────
 * DOA3 runs its game tasks (boot screens, intro, menus — sub_001C66A2-registered
 * handlers) as XAPI fibers switched from the per-frame dispatcher sub_001C652B.
 * The recompiled SwitchToFiber (sub_0018C9D3) swaps the Xbox stack pointer but
 * its `ret` maps to a C return — control can NEVER transfer to the fiber, so no
 * game task ever ran. Back the three XAPI entry points with the host cooperative
 * fiber layer (xbox_fiber.c direct-switch coroutines). Handles are encoded as
 * 0xF1BE0000|index; any foreign handle (e.g. the ConvertThreadToFiber main-fiber
 * pointer stored at 0x0073C640) means "switch back to the dispatcher fiber". */
extern int  xbox_fiber_create_dormant(uint32_t routine_va, uint32_t param,
                                      uint32_t stack_size);
extern void xbox_fiber_destroy(int idx);
extern void xbox_fiber_switch_direct(int idx);
/* SwitchToFiber(handle) — stdcall ret 4. Completes the call frame FIRST, then
 * transfers; when something switches back here, we return normally. */
#define XFIBER_TAG  0xF1BE0000u

/* CreateFiber(stack_size, start_routine, param) â€” stdcall ret 12. */
void sub_0018C934(void)
{
    extern uint32_t g_eax, g_esp;
    uint32_t stack_sz = MEM32(g_esp + 4);   /* arg0: the size the game asked for */
    uint32_t routine = MEM32(g_esp + 8);
    uint32_t param   = MEM32(g_esp + 0xC);
    int idx = xbox_fiber_create_dormant(routine, param, stack_sz);
    g_eax = (idx > 0) ? (XFIBER_TAG | (uint32_t)idx) : 0;
    g_esp += 16;
}

/* DeleteFiber(handle) â€” stdcall ret 4. */
void sub_0018C9C0(void)
{
    extern uint32_t g_esp;
    uint32_t h = MEM32(g_esp + 4);
    if ((h & 0xFFFF0000u) == XFIBER_TAG)
        xbox_fiber_destroy((int)(h & 0xFFFF));
    g_esp += 8;
}

void sub_0018C9D3(void)
{
    extern uint32_t g_esp;
    uint32_t h = MEM32(g_esp + 4);
    g_esp += 8;                                  /* finish the call (stdcall ret 4) */
    if ((h & 0xFFFF0000u) == XFIBER_TAG) {
        xbox_fiber_switch_direct((int)(h & 0xFFFF));
    } else {
        /* Foreign handle = the "main fiber" (dispatcher). We are a task fiber
         * yielding back: our creator/switcher resumes via the trampoline path. */
        extern void xbox_fiber_yield_back(void);
        xbox_fiber_yield_back();
    }
}

/* Boot-progress markers: the four init calls after sub_000A5DC0 in sub_000A6400.
 * One of them loops forever (frame-pumping wait); the markers show which. */
#define BOOT_MARK(name) \
    void name(void) { \
        extern void name##_gen(void); \
        static int n = 0; \
        int log = (n < 4); n++; \
        if (log) {   } \
        name##_gen(); \
        if (log) {   } \
    }
BOOT_MARK(sub_000A4D40)
BOOT_MARK(sub_001C63EB)
#undef BOOT_MARK

/* sub_001F2A27 — DSOUND stream play/start (IDirectSoundStream-style; pumps the ADX
 * PCM-supply callback synchronously into the sound buffer and waits on the APU
 * voice — which our APU emulation doesn't advance, hanging the boot inside
 * sub_000A5DC0's final ADX stream start). Stub: report success without playing
 * (silent audio). RENDERING FIRST — restore when the APU voice path works.
 * stdcall ret 12 (gen does esp += 16 including the dummy). */
void sub_001F2A27(void)
{
    extern void sub_001F2A27_gen(void);
    extern uint32_t g_eax, g_esp;
    static int n = 0;
    uint32_t self = MEM32(g_esp + 4), a2 = MEM32(g_esp + 8), a3 = MEM32(g_esp + 12);
    /* Un-stubbed 2026-09-12: the stub dated from before the DSOUND
     * per-frame service esp leaks (sub_001F13C5 / sub_001C883B) were
     * enforced; the APU voice processor does advance CBO, so let the real
     * stream Play run (-> sub_001C6D46). */
    /* STUB again (2026-09-12): the game hands this call a NULL stream because the
     * host DirectSound shim creates no stream objects yet; running the XBE
     * body with that crashed 6 s after the movie. */
    g_eax = 0; g_esp += 16;
    if (n < 8) {  n++; }
}

/* sub_0018AB51 — XAPI ReadFileEx(hFile, buf, len, overlapped, completion).
 * DIAG: log args, the NtReadFile thunk value, and the result. */
void sub_0018AB51(void)
{
    extern void sub_0018AB51_gen(void);
    extern uint32_t g_eax, g_esp;
    uint32_t hf = MEM32(g_esp + 4), buf = MEM32(g_esp + 8), len = MEM32(g_esp + 0xC);
    uint32_t ov = MEM32(g_esp + 0x10);
    uint32_t thunk = MEM32(0x00217A0C);
    sub_0018AB51_gen();
    static int n = 0;
    if (n < 10) {   n++; }
}

/* sub_001938E0 — cvFs stream stepper (issues device seek/read for an active stream).
 * DIAG: dump the stream + file-object fields around the call. */
void sub_001938E0(void)
{
    extern void sub_001938E0_gen(void);
    extern uint32_t g_esp;
    uint32_t stm = MEM32(g_esp + 4);
    static int n = 0;
    int log = (n < 10);
    if (log && stm) {
        n++;
        uint32_t fo = MEM32(stm + 4);
    }
    sub_001938E0_gen();
}

/* sub_00198C60 — wxCi real size query (stats the file by NAME via sub_0018B090).
 * DIAG: log the name + result. */
void sub_00198C60(void)
{
    extern void sub_00198C60_gen(void);
    extern uint32_t g_eax, g_esp;
    uint32_t name = MEM32(g_esp + 4);
    char nm[64]; int i; for (i = 0; i < 63; i++) { nm[i] = name ? (char)MEM8(name + i) : 0; if (!nm[i]) break; } nm[63] = 0;
    sub_00198C60_gen();
    static int n = 0;
    if (n < 12) {   n++; }
}

/* sub_0018B090 — XAPI GetFileAttributesExA-like stat. DIAG: log name + result. */
void sub_0018B090(void)
{
    extern void sub_0018B090_gen(void);
    extern uint32_t g_eax, g_esp;
    uint32_t name = MEM32(g_esp + 4);
    char nm[64]; int i; for (i = 0; i < 63; i++) { nm[i] = name ? (char)MEM8(name + i) : 0; if (!nm[i]) break; } nm[63] = 0;
    sub_0018B090_gen();
    static int n = 0;
    if (n < 12) {   n++; }
}

/* sub_0018A4F0 — XAPI CreateFileA(name, access, share, sa, disposition, flags).
 * DIAG: log args + returned handle to see where the CRI's file opens die. */
void sub_0018A4F0(void)
{
    extern void sub_0018A4F0_gen(void);
    extern uint32_t g_eax, g_esp;
    uint32_t fname = MEM32(g_esp + 4);
    uint32_t access = MEM32(g_esp + 8);
    uint32_t disp = MEM32(g_esp + 0x14);
    uint32_t flags = MEM32(g_esp + 0x18);
    char nm[64]; int i; for (i = 0; i < 63; i++) { nm[i] = fname ? (char)MEM8(fname + i) : 0; if (!nm[i]) break; } nm[63] = 0;
    sub_0018A4F0_gen();
    static int n = 0;
    if (n < 20) {   n++; }
}

/* sub_00194750 — cvFs device resolver. The CRI registers named devices (MFS, WX) with WX
 * as the default; WX handles plain drive-letter paths (d:\, z:\, t:\) via the kernel. The
 * resolver only uses the default device when the path has NO prefix, so a drive-letter
 * path like "d:\loadfile.afs" extracts device "d", fails to match MFS/WX, and returns 0 —
 * cvFsOpen then fails. Fall back to the default device for an unresolved single-char drive
 * prefix (the full path is preserved separately and handed to the WX open). */
void sub_00194750(void)
{
    extern void sub_00194750_gen(void);
    extern uint32_t g_eax, g_ebx;
    uint32_t devbuf = g_ebx;
    uint8_t c0 = devbuf ? (uint8_t)MEM8(devbuf) : 0;
    uint8_t c1 = devbuf ? (uint8_t)MEM8(devbuf + 1) : 0;
    char dn[16]; int di; for (di = 0; di < 15; di++) { dn[di] = devbuf ? (char)MEM8(devbuf + di) : 0; if (!dn[di]) break; } dn[15] = 0;
    sub_00194750_gen();
    { static int dn_n = 0; if (dn_n < 12) {   dn_n++; } }
    if (g_eax == 0 && c0 && !c1) {        /* single-char drive-letter device not found */
        MEM8(devbuf) = 0;                  /* clear prefix → resolver uses the default device */
        g_ebx = devbuf;
        sub_00194750_gen();
        static int n = 0;
        if (n < 8) {   n++; }
    }
}

/* sub_001947F0 — cvFsOpen wrapper. DIAG: log the filename it's asked to open, to find
 * where ADXF_LoaddPartitionNw's empty AFS filename comes from. */
void sub_001947F0(void)
{
    extern void sub_001947F0_gen(void);
    extern uint32_t g_esp;
    uint32_t fname = MEM32(g_esp + 4);
    char nm[48]; int i; for (i = 0; i < 47; i++) { nm[i] = fname ? (char)MEM8(fname + i) : 0; if (!nm[i]) break; } nm[47] = 0;
    static int n = 0;
    extern volatile int g_doa3_post_movie;
    if (n < 16 || g_doa3_post_movie) {   n++; }
    sub_001947F0_gen();
}

/* sub_001B8F50 — CRT strncmp(s1, s2, n). The recompiler does not implement the
 * `repne scasb` / `repe cmpsb` REP string instructions it is built from (they were
 * emitted as comments), so the generated body compares garbage and reports unequal
 * strings as equal — which made cvFsAddDev("WX") collide with "MFS". Replace it with
 * a correct strncmp. cdecl, 3 args, caller-cleaned: pop only the dummy return slot. */
void sub_001B8F50(void)
{
    extern uint32_t g_eax, g_esp;
    uint32_t s1 = MEM32(g_esp + 4);
    uint32_t s2 = MEM32(g_esp + 8);
    uint32_t n  = MEM32(g_esp + 0xC);
    int r = 0;
    for (uint32_t i = 0; i < n; i++) {
        unsigned char c1 = (unsigned char)MEM8(s1 + i);
        unsigned char c2 = (unsigned char)MEM8(s2 + i);
        if (c1 != c2) { r = (c1 < c2) ? -1 : 1; break; }
        if (c1 == 0) break;          /* both reached NUL, equal */
    }
    g_eax = (uint32_t)r;
    g_esp += 4;                      /* mimic the original `ret` popping the dummy slot */
}

/* sub_00193F40 — CRI cvFs device-find-by-name. DIAG wrapper: log the name arg, its
 * content, and the result, to see why cvFsAddDev("WX") thinks the device exists. */
void sub_00193F40(void)
{
    extern void sub_00193F40_gen(void);
    extern uint32_t g_eax, g_esp;
    uint32_t name = MEM32(g_esp + 4);
    char nm[20]; int i; for (i = 0; i < 19; i++) { nm[i] = (char)MEM8(name + i); if (!nm[i]) break; } nm[19] = 0;
    sub_00193F40_gen();
    static int n = 0;
    if (n < 10) {   n++; }
}
/* effects-download skip: the real one
 * loads dsstdfx.bin fine now, but its aftermath bails sub_000A5DC0 before the AFS
 * loads (tried 2026-07-01) — keep the stub until that gate is understood. */

/* ── CRT memcpy/memmove native overrides (recomp bug #6 casualties) ──────────
 * The XBE has two identical MSVC CRT memcpy implementations (0x001B73D0 and
 * 0x001B7CB0; overlap-safe = memmove semantics). Their trailing-byte dispatch
 * uses intra-function jump tables interleaved with the case bodies, which the
 * recompiler cannot lift (bug #6) — every non-dword-multiple copy lost its
 * tail AND leaked -4 esp per call through the failed RECOMP_ITAIL. Replace
 * natively. cdecl(dst, src, n) -> eax = dst. Gen bodies renamed _oldjt. */
static void doa3_native_memmove(void)
{
    extern ptrdiff_t g_xbox_mem_offset;
    uint32_t dst = MEM32(esp + 4), src = MEM32(esp + 8), n = MEM32(esp + 0xC);
    if (n)
        memmove((void *)((uintptr_t)dst + g_xbox_mem_offset),
                (void *)((uintptr_t)src + g_xbox_mem_offset), n);
    eax = dst;
    esp += 4; /* pop dummy return; caller cleans args (cdecl) */
}
void sub_001B73D0(void) { doa3_native_memmove(); }
void sub_001B7CB0(void) { doa3_native_memmove(); }

/* DIAG: esp-load chokepoints (longjmp/SEH unwind sites in the gen — the only
 * places that assign esp from memory). site: 1=recomp_0008.c:3548 (longjmp),
 * 2-4=recomp_0009.c (SEH unwind family). */
void doa3_esp_load_log(int site, uint32_t esp_now, uint32_t esp_new)
{
    static int s_n = 0;
    if (s_n < 20) {
        s_n++;
    }
}

/* DIAG: the game-task yield (sub_001C65D8) — backtrace every 600th call to
 * pinpoint WHICH sequencer loop each task spins in. */
void sub_001C65D8_gen(void);
void sub_001C65D8(void)
{
    static int s_n = 0;
    extern int xbox_fiber_current(void);
    extern uint32_t g_task_yields[16];
    {   int fi = xbox_fiber_current();
        if (fi >= 0 && fi < 16) g_task_yields[fi]++; }
    s_n++;
    if (xbox_fiber_current() == 5 && (g_task_yields[5] % 600) == 0) {
        void *bt[6]; int n = CaptureStackBackTrace(1, 6, bt, NULL);
    }
    sub_001C65D8_gen();
}

/* DIAG: per-fiber yield counters, dumped with the fiber dump. */
uint32_t g_task_yields[16];

/* ── XPP (Xbox Peripheral Port) input overrides — host-backed pad 0 ─────────
 * DOA3's boot screens hold forever on the controller-present check (cxbx ran
 * with emulated pads). Report pad 0 connected and serve XInputGetState from
 * the host (src/input xbox_InputGetState; falls back to a neutral pad +
 * keyboard: Enter = START, arrows = d-pad, Z/X = A/B) so the boot flow takes
 * the pad-present path to the intro movie. Gen bodies renamed _gen. */
/* Guest-memory peek for the overlay Debug tab. The overlay is C++ and has no
 * MEM32; these keep the address arithmetic on this side. */
uint32_t doa3_dbg_read32(uint32_t va) { return MEM32(va); }
uint32_t doa3_dbg_read8(uint32_t va)  { return MEM8(va); }

static uint32_t s_xpp_prev_mask;   /* XGetDeviceChanges baseline (real XAPI PreviousConnected) */
void sub_0021157D(void)   /* XGetDevices(type) -> connected mask, stdcall ret 4 */
{
    static int s_n = 0;
    if (s_n < 4) { s_n++;   }
    /* Report the controllers the host actually has.
     *
     * This used to hardcode a single connected pad, because the boot flow
     * needed one. That fake pad is what stopped the attract screen working:
     * with a pad present and screen mode 2, sub_00088910 writes 1 to
     * [0x005C9248], sub_0004FFC0 reads that as input activity and starts the
     * attract watchdog [0x005A695C], which counts 40 frames down and tears
     * the whole screen script down -- 38 opcodes in, two commands before the
     * one at script address 0x0031CFA8 that arms the corner logo.
     *
     * cxbx settles it in both directions: the real game with no pad keeps the
     * watchdog parked at 40 and draws the logo, and forcing [0x0073C6BC] to 1
     * inside cxbx reproduces this port's teardown exactly. */
    {
        extern DWORD xbox_InputHostMask(void);
        uint32_t mask = netplay_filter_pad_mask(xbox_InputHostMask());
        /* Real XAPI semantics (cxbx Xapi.cpp, XGetDevices): reporting the
         * connected set also resets the change baseline, so the next
         * XGetDeviceChanges does NOT re-report these pads as insertions. */
        s_xpp_prev_mask = mask;
        if (s_n <= 4) {   }
        eax = mask;
    }
    esp += 8;
}
void sub_0021159F(void)   /* XGetDeviceChanges(type, &ins, &rem), stdcall ret 12 */
{
    /* Real XAPI semantics (cxbx Xapi.cpp, XGetDeviceChanges): BOTH output
     * words are written on EVERY call -- zero when nothing changed -- and
     * only the pads that appeared/vanished since the previous call (or since
     * XGetDevices) are reported.
     *
     * DOA3 seeds 0x0073C6BC from XGetDevices at boot (sub_000A4D40 opens
     * those pads itself) and then hands that SAME word to this function as
     * the insertions pointer every frame (sub_000A4DD0). So on real hardware
     * 0x0073C6BC is "pads inserted THIS frame": 0 from the first frame on.
     *
     * This used to return FALSE without touching the outputs, which left
     * 0x0073C6BC == 1 for the whole run whenever a controller was attached.
     * The attract driver sub_00088910 tests exactly that word at 0x00088A40
     * (`test [0x0073C6BC], 1<<port`) as "pad just inserted" and treats it like
     * a button press: [0x005C9248] = 1 every frame, the watchdog [0x005A695C]
     * counts 40 -> 0 and the intro scene (scr=5) tears itself down with no
     * input -- the same teardown a START press is supposed to cause. With a
     * controller plugged in there was therefore nothing left for START to
     * skip, and the corner logo never armed. */
    extern DWORD xbox_InputHostMask(void);
    uint32_t p_ins = MEM32(esp + 8), p_rem = MEM32(esp + 12);
    /* A netplay session fixes the topology at ports 0 and 1 on both
     * machines, whatever pads they have (netplay_session.c). */
    uint32_t cur = netplay_filter_pad_mask(xbox_InputHostMask());
    uint32_t ins = cur & ~s_xpp_prev_mask;
    uint32_t rem = s_xpp_prev_mask & ~cur;
    {   /* A forced port the game has not opened yet (no handle at
         * pad+0x78) is reported as an insertion whatever the baseline says:
         * XGetDevices from the menus would otherwise swallow it. */
        uint32_t forced = netplay_forced_pads(), p;
        for (p = 0; p < 4; p++)
            if ((forced & (1u << p)) && MEM32(0x0073C6C8u + 0x80u * p + 0x78u) == 0)
                ins |= 1u << p;
    }
    s_xpp_prev_mask = cur;
    if (p_ins) MEM32(p_ins) = ins;
    if (p_rem) MEM32(p_rem) = rem;
    if (ins | rem) {
    }
    eax = (ins | rem) ? 1u : 0u;
    esp += 16;
}
/* CRT rand() (sub_001B7C48; seed at [[0x1C] + 0x14]). Netplay sessions
 * account for every call (netplay_note_rand). */
void sub_001B7C48_gen(void);
/* Worker fibers' private rand() state, one stream per fiber, reseeded from
 * the session seed at session start and every screen change. */
static uint32_t s_wseed[64];
void doa3_worker_rand_seed(uint32_t seed)
{
    int i;
    for (i = 0; i < 64; i++) s_wseed[i] = (seed ^ (uint32_t)(i * 0x9E3779B1u)) | 1u;
}
void sub_001B7C48(void)
{
    netplay_note_rand();
    /* Online session: worker fibers (audio/file) call rand() a host-timing
     * dependent number of times; they draw from their own streams so the
     * game thread's seed only moves with gameplay. */
    extern int xbox_fiber_active(void), xbox_fiber_is_primary(void), xbox_fiber_is_coroutine(void);
    if (netplay_active() && xbox_fiber_active() && !xbox_fiber_is_primary() && !xbox_fiber_is_coroutine()) {
        extern int xbox_fiber_current(void);
        int f = xbox_fiber_current();
        uint32_t *w = &s_wseed[(f >= 0 && f < 64) ? f : 63];
        if (!*w) *w = 0x12345u | (uint32_t)f;
        *w = *w * 214013u + 2531011u;
        eax = (*w >> 16) & 0x7FFFu;
        return;
    }
    sub_001B7C48_gen();
}
void sub_00211898_xppgen(void);
void sub_00211898(void)   /* XInputClose(handle), stdcall ret 4 */
{
    /* Reached on a removal (sub_000A4DD0 closes the handle it opened). The
     * handles are fake and there is no USB device behind them. */
    fprintf(stderr, "[XPP] XInputClose(0x%08X)\n", MEM32(esp + 4));
    eax = 0;
    esp += 8;
}
void sub_00211823(void)   /* XInputOpen(type, port, slot, attrs) -> handle, ret 16 */
{
    uint32_t port = MEM32(esp + 8);
    eax = 0x0AD00001u + port;   /* fake but consistent nonzero handle */
    esp += 20;
}
void sub_002118A4(void)   /* XInputGetCapabilities(handle, caps->pad), ret 8 */
{
    /* arg2 is the PAD STRUCT base; the real XAPI writes a 0x19-byte caps blob
     * there whose FIRST byte is the device (sub)type — the game's pad polls
     * check MEM8(pad)==1||2 (gamepad). */
    uint32_t caps = MEM32(esp + 8);
    if (caps) {
        for (int i = 0; i < 0x18; i += 4) MEM32(caps + i) = 0;
        MEM8(caps + 0x18) = 0;
        MEM8(caps) = 1;   /* XINPUT_DEVSUBTYPE_GC_GAMEPAD */
    }
    eax = 0;
    esp += 12;
}
void sub_00211A96(void)   /* XInputPoll(handle, out) — complete instantly, ret 8 */
{
    /* The real XAPI kicks an async USB read and stores ERROR_IO_PENDING
     * (0x3E5) in the pad's state dword; the per-frame GetState looper
     * (sub_000A50A0) skips any pad whose marker is 0x3E5 until the USB
     * completion clears it. We have no USB machinery — mark the poll
     * complete so GetState (our host-backed override) actually runs. */
    for (int i = 0; i < 4; i++) {
        uint32_t st = 0x0073C6F7 + 0x80u * i;
        if (MEM32(st) == 0x3E5) MEM32(st) = 0;
    }
    eax = 0;
    esp += 12;
}
void sub_00211B07(void)   /* XInputGetState(handle, state) -> 0, ret 8 */
{
    { extern unsigned g_in_getstate; g_in_getstate++; }
    uint32_t st = MEM32(esp + 8);
    static uint32_t s_packet = 0x1000;   /* never collide with the 0x3E5
                                          * IO_PENDING marker */
    s_packet++;
    if (st) {
        uint16_t buttons = 0;
        uint8_t a = 0, b = 0;
        uint8_t an[8] = {0};          /* X, Y, Black, White, LT, RT at [2..7] */
        int16_t lx = 0, ly = 0, rx = 0, ry = 0;
        /* Which guest port is this? The state pointer is pad+0x2F of the
         * pad struct (base 0x0073C6C8, stride 0x80). This used to read host
         * pad 0 for EVERY port, so a controller enumerated on any other
         * XInput index fed nothing. */
        uint32_t port = 0;
        {
            uint32_t pi;
            for (pi = 0; pi < 4; pi++)
                if (st == 0x0073C6F7u + 0x80u * pi || st == 0x0073C6E1u + 0x80u * pi) port = pi;
        }
        /* host pad for this port (mapping; keyboard only overlays port 0) */
        {
            extern DWORD xbox_InputGetState(DWORD, void *);
            uint8_t raw[32] = {0};
            if (xbox_InputGetState(port, raw) == 0) {
                buttons = *(uint16_t *)(raw + 4);
                memcpy(an, raw + 6, 8);
                a = an[0]; b = an[1];
                lx = *(int16_t *)(raw + 14); ly = *(int16_t *)(raw + 16);
                rx = *(int16_t *)(raw + 18); ry = *(int16_t *)(raw + 20);
            }
        }
        /* Keyboard input comes ONLY through the Esc-menu mapping now; the old
         * fixed Enter/arrows/Z/X extras were removed once the mapper was
         * verified to reach the game. */
        {   /* DIAGNOSTIC ONLY (DOA3_FAKESTART=1), never on by default.
             *
             * The post-movie screen advances only on a real button press:
             * sub_00088910 reaches the screen-change path at 0x00088B96 via
             * sub_0008ACC0, which tests bits 4-15 of the pad aggregate at
             * 0x0073C8D8. Headless runs cannot press a key, so this pulses
             * START after the movie purely to establish whether the rest of
             * the chain (screen change -> title screen -> 3D draws) works.
             * It exists to isolate input plumbing from rendering, not to
             * stand in for input. */
            extern volatile int g_doa3_post_movie;
            static int s_fake = -1;
            static unsigned s_n = 0;
            if (s_fake < 0) {
                const char *e = getenv("DOA3_FAKESTART");
                s_fake = (e && *e && *e != '0') ? 1 : 0;
            }
            if (s_fake && g_doa3_post_movie) {
                s_n++;
                /* ONE press, then released for good.
                 *
                 * Pulsing repeatedly restarts the pad rumble on every press,
                 * and the screen latch is only released while the rumble is
                 * idle: sub_00050250 bails whenever sub_00067220 (the word at
                 * 0x00C59414) is non-zero, and bit 3 of it means "rumble
                 * running" (set at 0x00067342, cleared at 0x0006C430). A
                 * repeating press therefore holds the latch shut forever,
                 * which is not what a real press does. */
                if (s_n >= 300 && s_n < 340) {
                    buttons |= 0x0010;   /* START */
                    /* The post-movie screen gate at 0x000D5208 wants bit 0x20
                     * or 0x200 of the pad word at 0x0073C8D0 + pad*0x2C, which
                     * START does not produce -- assert A (analog) too so the
                     * diagnostic covers the confirm buttons. */
                    /* BACK omitted: holding it pins the screen in state 0 */
                    a = 255;             /* A */
                }
                if (s_n == 300 || s_n == 340)
                    fprintf(stderr, "[FAKESTART] %s at frame %u\n",
                            s_n == 300 ? "press" : "release", s_n), fflush(stderr);
            }
        }
        an[0] = a; an[1] = b;
        {   /* One line per press edge (first 24): what the guest received and
             * what screen it was on, so a run log shows where a press went. */
            static int s_log = 0, s_was = 0;
            int now = (buttons != 0), ai;
            for (ai = 0; ai < 8; ai++) if (an[ai] >= 30) now = 1;
            if (now && !s_was && s_log < 24) {
                s_log++;
            }
            s_was = now;
        }
        /* Each pad struct (base 0x0073C6C8, stride 0x80) holds TWO consecutive
         * XINPUT_STATEs, 0x16 bytes each: one at pad+0x19 and one at pad+0x2F.
         * The game hands XInputGetState the second (pad+0x2F), but the
         * per-frame aggregate builder sub_000A4E70 reads the FIRST -- it walks
         * a cursor at 0x0073C6F3 and loads wButtons from [cursor-0xE] = pad+0x1D,
         * which is pad+0x19 plus the 4-byte packet number. Filling only the
         * slot we were handed left the aggregates at 0x0073C8D0+i*0x2C at zero,
         * so no button ever reached the game and the post-movie screen sat in
         * its "press START" wait loop (0x00083480) forever.
         *
         * Write the state the caller asked for, and mirror it into the slot the
         * aggregate builder actually reads. */
        uint32_t slots[2];
        int nslots = 1;
        slots[0] = st;
        for (int i = 0; i < 4; i++) {
            if (st == 0x0073C6F7u + 0x80u * (uint32_t)i) {
                slots[1] = 0x0073C6E1u + 0x80u * (uint32_t)i;
                nslots = 2;
                break;
            }
        }
        for (int si = 0; si < nslots; si++) {
            uint32_t d = slots[si];
            MEM32(d) = s_packet;          /* dwPacketNumber */
            MEM16(d + 4) = buttons;       /* wButtons */
            for (int i = 0; i < 8; i++) MEM8(d + 6 + i) = an[i];   /* A B X Y Black White LT RT */
            MEM16(d + 14) = (uint16_t)lx; /* sThumbLX */
            MEM16(d + 16) = (uint16_t)ly; /* sThumbLY */
            MEM16(d + 18) = (uint16_t)rx; /* sThumbRX */
            MEM16(d + 20) = (uint16_t)ry; /* sThumbRY */
        }
    }
    {   extern unsigned g_in_getstate, g_in_build;
        extern volatile int g_doa3_post_movie;
        static unsigned n = 0;
        if (g_doa3_post_movie && (g_in_getstate % 256u) == 0 && n < 20) {
            n++;
             }
    }
    eax = 0;    /* ERROR_SUCCESS */
    esp += 12;
}

/* DIAG: cvFs device-range writers — the device table "count" (0x0040CD20/64)
 * goes to an empty range during the boot-phase transition, killing every
 * subsequent file open ('resolve dev="" -> 0', 'ptid range outside'). Trace
 * who resets it and with what values. */
/* DIAG: cvFsSetDefDev (sub_001946A0) - the default-device name at 0x0040C8A0
 * gets CLEARED during the boot-phase transition (its failure path writes a
 * 0 byte), killing all subsequent default-device opens. Log the requested
 * name + result + the default before/after. */
void sub_001946A0_gen(void);
void sub_001946A0(void)
{
    static int s_n = 0;
    uint32_t a1 = MEM32(esp + 4);
    char name[24] = {0};
    for (int i = 0; i < 23 && a1; i++) { name[i] = (char)MEM8(a1 + i); if (!name[i]) break; }
    char pre[24] = {0};
    for (int i = 0; i < 23; i++) { pre[i] = (char)MEM8(0x0040C8A0 + i); if (!pre[i]) break; }
    sub_001946A0_gen();
    s_n++;
    if (s_n <= 12) {
        char post[24] = {0};
        for (int i = 0; i < 23; i++) { post[i] = (char)MEM8(0x0040C8A0 + i); if (!post[i]) break; }
        void *bt[5]; int n = CaptureStackBackTrace(1, 5, bt, NULL);
    }
}

void sub_00194530_gen(void);
void sub_00194530(void)
{
    static int s_n = 0;
    s_n++;
    if (s_n <= 8) {
        void *bt[6]; int n = CaptureStackBackTrace(1, 6, bt, NULL);
    }
    sub_00194530_gen();
}

/* DIAG: screen-element/texture-bind chain counters (draws=0 root hunt). */
/* High-rate pump/service traces. These emit tens of thousands of lines per
 * run; the write cost alone slowed the guest enough that timed runs ended
 * before the movie finished. Off unless DOA3_PUMPTRACE=1. */
static int doa3_pumptrace(void)
{
    static int s_v = -1;
    if (s_v < 0) {
        const char *e = getenv("DOA3_PUMPTRACE");
        s_v = (e && *e && *e != '0') ? 1 : 0;
    }
    return s_v;
}

#define CALL_COUNT_PROBE(fn) \
    void fn##_gen(void); \
    void fn(void) { \
        static int s_n = 0; \
        s_n++; \
        if (doa3_pumptrace() && (s_n <= 3 || (s_n % 5000) == 0)) { \
             \
             } \
        fn##_gen(); \
    }
CALL_COUNT_PROBE(sub_0019BF30)   /* wxCi cache-copy stream starter */
CALL_COUNT_PROBE(sub_0019ED00)   /* Sofdec movie player create */

/* sub_001A6300 — "is the movie data stream finished?" = (streamStat == 4).
 * The gen lifts the `neg/sbb/inc` equality idiom with recomp bug #10 (carry
 * flag never produced), returning TRUE unconditionally — so the mwPly server
 * declared the ninja.sfd stream complete right after the first 1MB read and
 * killed the player (state 4) before a single frame decoded. Native impl. */
void sub_001A6300(void)
{
    extern void sub_001911C0(void);
    uint32_t h = MEM32(esp + 4);
    PUSH32(esp, h);
    PUSH32(esp, 0); sub_001911C0();
    esp += 4;                 /* our arg push */
    eax = (eax == 4) ? 1 : 0;
    esp += 4;                 /* consume fake return */
}
CALL_COUNT_PROBE(sub_0019EFC0)   /* mwPly destroy (DF60 bail path) */
CALL_COUNT_PROBE(sub_00083510)   /* last call before 4A10D0 clear */
CALL_COUNT_PROBE(sub_000869A0)   /* first call in screen-flip task */
CALL_COUNT_PROBE(sub_0019A660)   /* ADXM group-2 slot-1 dispatch (mwPly server) */
CALL_COUNT_PROBE(sub_0019A690)   /* ADXM group-5 dispatch (sfdec decode cb) */
CALL_COUNT_PROBE(sub_001A0260)   /* sfdec main server */

/* DIAG: result probes along the ADXSTM-create chain. */
#define RET_PROBE(fn) \
    void fn##_gen(void); \
    void fn(void) { \
        static int s_n = 0; \
        fn##_gen(); \
        if (s_n < 8) { s_n++; \
             \
             } \
    }

/* DIAG: sfdec error reporter — log every error with a small backtrace of the
 * guest stack so the failing parse site is identifiable.
 * item 102: budget is PER ERROR CODE (a 40B storm used to eat the whole
 * 10-print budget and hid unlock failures like FF000F0E/F0F). */
void sub_001A5DC0_gen(void);
void sub_001A5DC0(void)
{
    static uint32_t s_codes[16]; static int s_counts[16]; static int s_nc = 0;
    uint32_t h = MEM32(esp + 4), err = MEM32(esp + 8);
    int ci = -1;
    for (int i = 0; i < s_nc; i++) if (s_codes[i] == err) { ci = i; break; }
    if (ci < 0 && s_nc < 16) { ci = s_nc++; s_codes[ci] = err; s_counts[ci] = 0; }
    int s_n = (ci >= 0) ? s_counts[ci] : 999;
    if (ci >= 0) s_counts[ci]++;
    if (s_n < 6) {
        /* NATIVE backtrace: the recompiled guest functions are host functions,
         * so the host stack IS the guest call chain. Resolve via doa3.map. */
        {
            void *bt[24];
            USHORT nfr = CaptureStackBackTrace(1, 24, bt, NULL);
        }
    }
    /* BACKPRESSURE: FF00040B = "substream ring full, cannot append". On
     * hardware the ingest simply retries next tick as the decoder drains;
     * storing it kills the handle (status -2). Swallow it as a warning. */
    if (err == 0xFF00040B) {
        static int s_bp = 0;
        if (s_bp < 4) {
            s_bp++;
        }
        eax = 0; esp += 4; return;
    }
    sub_001A5DC0_gen();
}
/* DIAG: SJ sub-region carve helper (register-arg: eax=end, ecx=cur,
 * edx=base, ebx=mode, esi=out struct). size = eax-ecx; the negative-size
 * (0xFFFFF800) SJ creations come through here or its callers. */
void sub_001A7F10_gen(void);
void sub_001A7F10(void)
{
    static int s_n = 0;
    if (s_n < 40) {
        s_n++;
    }
    sub_001A7F10_gen();
}

/* GUARD: is `obj` one of the legit decoder-pool objects (base=[0x00C85148],
 * count=[0x00C85144], stride 0x60D8)? Junk objects reaching the state machine
 * trigger the sfdec error store at junk+0x988 -> corrupts the mwPly slot
 * table -> self-amplifying cascade (FF000222 spam, junk handles, crash). */
static int sfdec_pool_obj_ok(uint32_t obj)
{
    /* Reject only objects OUTSIDE guest RAM. On real hardware junk/residue
     * pointers inside guest RAM are walked harmlessly (low memory reads,
     * bounded error stores); the poison is 32-bit garbage beyond the 128MB
     * guest range, whose error-store at obj+0x988 aliases onto live
     * structures (mwPly slot table) and cascades. Alignment checks are too
     * strict: the state machine also legitimately runs on substream
     * sub-objects at interior offsets of the sfdec handle. */
    return obj >= 0x1000 && obj < 0x8000000u;
}
void sub_001A0B60_gen(void);
void sub_001A0B60(void)
{
    static int s_junk = 0;
    if (!sfdec_pool_obj_ok(eax)) {
        if (s_junk < 4) {
            s_junk++;
        }
        eax = 0; esp += 4; return;
    }
    sub_001A0B60_gen();
}
/* DIAG: frame get + YUV->RGB CSC kernel. */
void sub_001A6220_gen(void);
void sub_001A6220(void)
{
    static int s_n = 0;
    uint32_t h = MEM32(esp + 4), outp = MEM32(esp + 8);
    sub_001A6220_gen();
    if (s_n < 8 || (s_n % 2048) == 0) {
    }
    s_n++;
}
void sub_001A3480_gen(void);
void sub_001A3480(void)
{
    static int s_n = 0;
    sub_001A3480_gen();
    if (s_n < 6 || (s_n % 2048) == 0) {
    }
    s_n++;
}
/* Unresolved RECOMP_ITAIL logger (see recomp_types.h). */
void recomp_itail_fail_log(uint32_t va)
{
    static uint32_t seen[16];
    static int n = 0;
    for (int i = 0; i < n; i++) if (seen[i] == va) return;
    if (n < 16) {
        seen[n++] = va;
    }
}
/* DIAG: esp-delta bisect for the skip-path -4 drift. */
#define DPROBE(fn) void fn##_gen(void); void fn(void) {     static int s_n = 0;     uint32_t e0 = esp;     fn##_gen();     if ((int)(esp - e0) != 4 && s_n < 6) {         s_n++;                       } }
DPROBE(sub_001A9E80)
DPROBE(sub_001A8AC0)
DPROBE(sub_001B0980)
DPROBE(sub_001AFA30)
DPROBE(sub_001AFA80)
DPROBE(sub_001AA4B0)
DPROBE(sub_001AA0F0)
DPROBE(sub_001AA1E0)
#undef DPROBE
/* Per-picture slot FIFO (item 90): pictures complete in bitstream order,
 * but a picture can suspend across many decode invocations while LATER
 * pictures allocate — a single "last slot" cache binds the wrong slot.
 * PALLOC pushes; the completion patch in sub_001A2470 (recomp_cffix.c)
 * pops. */
uint32_t g_doa3_slotq[16];
uint32_t g_doa3_slotq_w = 0, g_doa3_slotq_r = 0;

static int doa3_reftrace_enabled(void)
{
    static int enabled = -1;
    if (enabled < 0)
        enabled = GetEnvironmentVariableA("DOA3_REFTRACE", NULL, 0) != 0;
    return enabled;
}

static int doa3_iframe_dump_enabled(void)
{
    static int enabled = -1;
    if (enabled < 0)
        enabled = GetEnvironmentVariableA("DOA3_IFRAME", NULL, 0) != 0;
    return enabled;
}

static uint32_t g_doa3_plane_hash[7][30];
static uint32_t g_doa3_plane_addr[7];
static uint32_t g_doa3_plane_serial[7];
static uint32_t g_doa3_plane_next_serial;

static uint32_t doa3_hash_bytes(const uint8_t *data, uint32_t size, uint32_t hash)
{
    for (uint32_t i = 0; i < size; i++) {
        hash ^= data[i];
        hash *= 16777619u;
    }
    return hash;
}

static uint32_t doa3_hash_plane_row(uint32_t plane, int macroblock_row)
{
    const uint8_t *y = (const uint8_t *)XBOX_PTR(plane);
    const uint8_t *u = y + 736u * 480u;
    const uint8_t *v = u + 384u * 240u;
    uint32_t hash = 2166136261u;
    for (int row = 0; row < 16; row++)
        hash = doa3_hash_bytes(y + (macroblock_row * 16 + row) * 736u, 720, hash);
    for (int row = 0; row < 8; row++) {
        hash = doa3_hash_bytes(u + (macroblock_row * 8 + row) * 384u, 360, hash);
        hash = doa3_hash_bytes(v + (macroblock_row * 8 + row) * 384u, 360, hash);
    }
    return hash;
}

static void doa3_compare_completed_plane(uint32_t plane)
{
    if (!doa3_reftrace_enabled())
        return;
    for (int slot = 0; slot < 7; slot++) {
        if (g_doa3_plane_addr[slot] != plane || !g_doa3_plane_serial[slot])
            continue;
        uint32_t changed = 0;
        for (int row = 0; row < 30; row++)
            if (g_doa3_plane_hash[slot][row] != doa3_hash_plane_row(plane, row))
                changed |= 1u << row;
        g_doa3_plane_serial[slot] = 0;
        return;
    }
}
uint32_t g_doa3_a6d0_frame = 0;   /* item 90(c): A6D0 frame base (absolute) */
/* item 104 (defect #2 start offset): decode races ~47 pictures ahead before
 * the first blit; the ref rotation frees DECODED-BUT-NEVER-DISPLAYED slots
 * (state 2 is ambiguous: awaiting-display and displayed-now-ref share it)
 * and the early pictures' buffers get rewritten — the movie visibly starts
 * ~1.5s in ([PDECIDE] proved nothing is DROPPED; 120-frame alignment puts
 * our first serves at ref 47-56). During the STARTUP WINDOW (first 90
 * blits) a decoded-but-unserved slot may not be freed: releases against it
 * defer, so decode blocks on slot availability exactly like hardware.
 * Fail-safe: a deferred entry stuck for >2000 drains force-releases (a
 * PSKIP'd never-displayed picture must not jam the ring). */
static uint8_t  g_doa3_slot_pending[7];
static uint32_t g_doa3_defer_age[16];
/* item 104 decode-ahead accounting (cap enforced in sub_001A17B0) */
uint32_t g_doa3_pics_decoded = 0, g_doa3_pics_served = 0;
static uint32_t g_doa3_rel_defer[16];
static int g_doa3_rel_defer_n = 0;
static void doa3_defer_release(uint32_t rec, int to3)
{
    for (int i = 0; i < g_doa3_rel_defer_n; i++)
        if ((g_doa3_rel_defer[i] & ~1u) == rec) return;
    if (g_doa3_rel_defer_n < 16) {
        g_doa3_defer_age[g_doa3_rel_defer_n] = 0;
        g_doa3_rel_defer[g_doa3_rel_defer_n++] = rec | (to3 ? 1u : 0u);
    }
}
void doa3_reset_slot_pending(void)
{
    for (int i = 0; i < 7; i++) g_doa3_slot_pending[i] = 0;
}
static int doa3_release_must_defer(uint32_t rec)
{
    /* item 110 (user revert): the item-104 release DEFERRAL is REMOVED — it was
     * a band-aid for the #2 start-offset that only changed the freeze mode, not
     * the underlying decode stall. Releases now run immediately (raw behavior). */
    (void)rec;
    return 0;
}
void sub_001A89D0_gen(void);
void sub_001A89D0(void)
{
    static unsigned s_n = 0;
    uint32_t a1 = MEM32(esp + 4), a2 = MEM32(esp + 8), a3 = MEM32(esp + 0xC), a4 = MEM32(esp + 0x10);
    sub_001A89D0_gen();
    if (++s_n <= 40) {
    }
}
/* DIAG: video ES delivery + guarded index append. */
void sub_001A4E70_gen(void);
void sub_001A4E70(void)
{
    static int s_n = 0;
    uint32_t a1 = MEM32(esp + 4), a2 = MEM32(esp + 8);
    sub_001A4E70_gen();
    if (s_n < 8 || (s_n % 2048) == 0) {
    }
    s_n++;
}
/* DIAG: picture registration in the bitfeeder (writes rec+0x40?). */
void sub_001AAEE0_gen(void);
void sub_001AAEE0(void)
{
    static int s_n = 0;
    uint32_t ctx = eax;
    sub_001AAEE0_gen();
    if (s_n < 8 || (s_n % 4096) == 0) {
    }
    s_n++;
}
/* DIAG: start-code class scanner + picture bitstream setup. */
void sub_001A9860_gen(void);
void sub_001A9860(void)
{
    static int s_n = 0;
    uint32_t p = MEM32(esp + 4), len = MEM32(esp + 8), mask = MEM32(esp + 0xC);
    sub_001A9860_gen();
    if (mask == 4 && (s_n < 8 || (s_n % 4096) == 0)) {
    }
    if (mask == 4) s_n++;
}
/* DIAG: picture decode initiators inside sub_001A3070's tail. If the
 * sub_001A28E0 out-flag stays 0 these never run and no picture decodes. */
#define CNTPROBE(fn) void fn##_gen(void); void fn(void) {     static int s_n = 0;     fn##_gen();     if (s_n < 6 || (s_n % 4096) == 0) {                       }     s_n++; }
#undef CNTPROBE
/* DIAG: picture-header parse chain (bit readers on ctx h+0x35E0). One of
 * these rejects every picture -> all pictures skipped -> zero decoded
 * frames -> black movie surface. */
#define PICPROBE(fn) void fn##_gen(void); void fn(void) {     static int s_n = 0;     uint32_t inh = eax, inc = ecx, ind = edx;     fn##_gen();     if (s_n < 40) {         s_n++;                       } }
PICPROBE(sub_001A1730)
PICPROBE(sub_001A1770)
#undef PICPROBE
/* DIAG: slice decoder sub_001A2630(a1=win, a2=0xCC; esi=&ctx). Consumes
 * slice start codes from the ES window; frames stay state 1 because this
 * never completes a picture. */
void sub_001A2630_gen(void);
void sub_001A2630(void)
{
    static int s_n = 0;
    uint32_t a1 = MEM32(esp + 4), a2 = MEM32(esp + 8), sctx = esi;
    sub_001A2630_gen();
    if (s_n < 12 || (s_n % 4096) == 0) {
    }
    s_n++;
}
/* item 100: movie AV-clock QPC pacing state (see the synthetic-clock block
 * below). File-scope so the not-playing branch can reset it between movies. */
static LONGLONG s_mvclk_last = 0;
static LONGLONG s_mvclk_qpf = 0;
static double   s_mvclk_accum = 0.0;
void sub_001A7FC0_gen(void);
void sub_001A7FC0(void)
{
    static int s_n = 0;
    uint32_t slot = esi, vt = (esi >= 0x10000 && esi < 0x8000000) ? MEM32(esi) : 0;
    sub_001A7FC0_gen();
    if (s_n < 8) { s_n++;
        (void)vt;
         }
}
RET_PROBE(sub_001A7C00)
RET_PROBE(sub_00195180)
RET_PROBE(sub_00195510)
RET_PROBE(sub_0019BD40)
RET_PROBE(sub_0019C4E0)

/* DIAG: SJ creator + wxCi session creator (both inside the ADXSTM create). */
void sub_00192400_gen(void);
void sub_00192400(void)
{
    static int s_n = 0;
    uint32_t a1 = MEM32(esp + 4), a2 = MEM32(esp + 8);
    if (a2 & 0x80000000u) {
        /* Negative region size (X-0x800 with X=0 upstream). A ring with cap
         * 0xFFFFF800 writes anywhere = guest-wide memory corruption (junk
         * sfdec handles / ASCII stream bytes showing up as pointers).
         * Dump the caller frame to identify the layout bug, then clamp. */
        MEM32(esp + 8) = 0x800;  /* clamp: minimal sane ring */
    }
    sub_00192400_gen();
    {   extern volatile int g_doa3_post_movie;
        if (s_n < 40 || g_doa3_post_movie) { s_n++;
             } }
}
void sub_00195670_gen(void);
void sub_00195670(void)
{
    static int s_n = 0;
    uint32_t a1 = MEM32(esp + 4);
    sub_00195670_gen();
    if (s_n < 12) { s_n++;
         }
}

/* DIAG: sfdec size calculator (create path) — print the size table it fills.
 * After the 30 vtable-fn emissions the sfdec create started failing with
 * params+4==0; these outputs feed the buffer carve in sub_0019F150. */
void sub_0019EAB0_gen(void);
void sub_0019EAB0(void)
{
    static int s_n = 0;
    sub_0019EAB0_gen();
    if (s_n < 3) {
        s_n++;
    }
}

/* DIAG: sfdec state-2 evaluator (fastcall, handle in eax): print cmd (+0x44),
 * gate sub_001A0310 result path, and the state it returns. */
void sub_001A0A70_gen(void);
void sub_001A0A70(void)
{
    static unsigned s_n = 0;
    uint32_t h = eax;
    uint32_t cmd = MEM32(h + 0x44), st = MEM32(h + 0x40);
    sub_001A0A70_gen();
    if (++s_n <= 6 || (s_n % 2000) == 0) {
    }
}

/* DIAG: gate sub_001A0310 (fastcall-ish, handle in esi). */
void sub_001A0310_gen(void);
void sub_001A0310(void)
{
    static unsigned s_n = 0;
    uint32_t h = esi;
    sub_001A0310_gen();
    if (++s_n <= 6 || (s_n % 2000) == 0) {
        for (int si = 0; si < 9; si++) {
            uint32_t vt = MEM32(h + 0x2F4C + 0x610u * si);
        }
    }
}
/* Boot-task body enter/exit markers (BOOT_MARK was #undef'd above). */
#define BOOT_MARK2(name) \
    void name(void) { \
        extern void name##_gen(void); \
        static int n = 0; \
        int log = (n < 60); n++; \
        if (log) {   } \
        name##_gen(); \
        if (log) {   } \
    }
/* DirectSoundCreate chain (cxbx symbol cache names): sub_001C800C = create
 * path, sub_001C7ECD = CDirectSound::Initialize, sub_001C6AA0 = DSOUND pool
 * alloc, sub_001C765A / sub_001C8A76 / sub_001C90C0 = APU driver setup steps.
 * Enter/exit markers to find which step leaves the game with pDS == NULL. */
#define BOOT_MARK2_ABI(name) \
    void name(void) { \
        extern void name##_gen(void); \
        static int n = 0; \
        uint32_t s_edi = edi, s_esi = esi, s_ebx = ebx; \
        int log = (n < 60); n++; \
        if (log) {   } \
        name##_gen(); \
        if (log) {   } \
        edi = s_edi; esi = s_esi; ebx = s_ebx; \
    }
BOOT_MARK2_ABI(sub_001F1E95)
BOOT_MARK2_ABI(sub_001F1DF9)
BOOT_MARK2_ABI(sub_001F2227)
/* APU interrupt delivery (see apu_core.c g_apu_irq_pending). Runs the
 * DirectSound driver's KINTERRUPT service routine (the one registered from
 * the DSOUND library, routine VA 0x001EE000..0x0020D000) and then every DPC
 * it queued, all as ordinary guest calls on this thread. */
void doa3_apu_deliver_irq(void)
{
    typedef struct MCPXAPUState MCPXAPUState;
    extern MCPXAPUState *g_apu_state;
    extern uint64_t mcpx_apu_mmio_read(MCPXAPUState *, uint64_t, unsigned int);
    extern int mcpx_apu_take_irq(void);
    extern int xbox_kernel_get_isr(int, uint32_t *, uint32_t *, uint32_t *);
    extern int xbox_kernel_pop_dpc(uint32_t *, uint32_t *, uint32_t *);
    extern recomp_func_t recomp_lookup(uint32_t xbox_va);
    extern recomp_func_t recomp_lookup_manual(uint32_t xbox_va);
    static unsigned s_isr_calls = 0, s_dpc_calls = 0;
    static int s_delivering = 0;
    uint32_t obj, routine, ctx, dpc, a1, a2;
    int i;
    if (s_delivering) return;   /* an interrupt does not preempt its own service routine or DPC */
    if (!mcpx_apu_take_irq()) return;
    s_delivering = 1;
    for (i = 0; xbox_kernel_get_isr(i, &obj, &routine, &ctx); i++) {
        recomp_func_t fn;
        if (routine < 0x001EE000u || routine >= 0x0020D000u) continue;
        fn = recomp_lookup_manual(routine);
        if (!fn) fn = recomp_lookup(routine);
        if (!fn) continue;
        {
            uint32_t saved_esp = esp;
            PUSH32(esp, ctx);
            PUSH32(esp, obj);
            PUSH32(esp, 0);           /* dummy return address */
            fn();
            esp = saved_esp;
        }
        s_isr_calls++;
        if (s_isr_calls <= 5 || (s_isr_calls % 500) == 0) {
            
        }
    }
    while (xbox_kernel_pop_dpc(&dpc, &a1, &a2)) {
        uint32_t droutine = MEM32(dpc + 12), dctx = MEM32(dpc + 16);
        recomp_func_t fn = recomp_lookup_manual(droutine);
        if (!fn) fn = recomp_lookup(droutine);
        if (!fn) continue;
        {
            uint32_t saved_esp = esp;
            PUSH32(esp, a2);
            PUSH32(esp, a1);
            PUSH32(esp, dctx);
            PUSH32(esp, dpc);
            PUSH32(esp, 0);
            fn();
            esp = saved_esp;
        }
        s_dpc_calls++;
        if (s_dpc_calls <= 5 || (s_dpc_calls % 500) == 0) {
            
        }
    }
    s_delivering = 0;
}

/* DirectSound's retire wait (sub_001F5157): spin until the buffer's
 * retire-pending bit (0x10000000) is cleared by the ISR's idle-voice
 * retirement. Both callers spin at PASSIVE level with the driver's busy
 * count released, where the hardware interrupt arrives; here it is delivered
 * from inside the wait. All guest registers are preserved across it. */
void doa3_apu_wait_retire(uint32_t obj)
{
    uint32_t r_eax = eax, r_ecx = ecx, r_edx = edx, r_ebx = ebx, r_esi = esi,
             r_edi = edi, r_esp = esp, r_seh = g_seh_ebp;
    DWORD t0 = GetTickCount();
    int warned = 0;
    while (MEM32(obj + 8) & 0x10000000u) {
        doa3_apu_deliver_irq();
        eax = r_eax; ecx = r_ecx; edx = r_edx; ebx = r_ebx; esi = r_esi;
        edi = r_edi; esp = r_esp; g_seh_ebp = r_seh;
        if (!(MEM32(obj + 8) & 0x10000000u)) break;
        {   /* netplay session: the chip only moves when stepped (apu_core.c) */
            extern volatile int g_apu_det;
            extern void mcpx_apu_det_step(void);
            if (g_apu_det) { mcpx_apu_det_step(); continue; }
        }
        Sleep(1);
        if (!warned && GetTickCount() - t0 > 500) {
            warned = 1;
        }
    }
}
#define BOOT_MARK2_ABI_ESI(name)     void name(void) {         extern void name##_gen(void);         static int n = 0;         uint32_t s_edi = edi, s_esi = esi, s_ebx = ebx, s_esp = esp;         int log = (n < 12); n++;         name##_gen();         if (log) {   }         edi = s_edi; esi = s_esi; ebx = s_ebx;     }
BOOT_MARK2_ABI_ESI(sub_001A6020)
BOOT_MARK2_ABI_ESI(sub_001A0390)
BOOT_MARK2_ABI_ESI(sub_001A8B30)
uint32_t g_doa3_last_adx_dev = 0;   /* device handed to the ADX Start method most recently (the movie voice) */
BOOT_MARK2_ABI_ESI(sub_001F91CD)
static void apu_dump_block(const char *tag, uint32_t apu)
{
    int i;
}
void sub_001F1D89_gen(void);
void sub_001F1D89(void)   /* IDirectSoundBuffer method (this, value); this-0x1C = CDirectSoundBuffer */
{
    static int n = 0;
    uint32_t self = MEM32(esp + 4), arg = MEM32(esp + 8);
    uint32_t s_edi = edi, s_esi = esi, s_ebx = ebx;
    if (self < 0x10000 || self >= 0x08000000u) {
        if (n < 20) { n++;
             }
        eax = 0x80004005u; esp += 12; return;   /* ret 8: refuse instead of walking the zero page */
    }
    if (n < 8) { n++;  }
    sub_001F1D89_gen();
    edi = s_edi; esi = s_esi; ebx = s_ebx;
}
void sub_001F2CAB_gen(void);
void sub_001F2CAB(void)   /* IDirectSound_CreateSoundBuffer(this, desc, out) */
{
    static int n = 0;
    uint32_t ds = MEM32(esp + 4), desc = MEM32(esp + 8), out = MEM32(esp + 12);
    uint32_t s_edi = edi, s_esi = esi, s_ebx = ebx, e_esp = esp;
    sub_001F2CAB_gen();
    if (n < 12) { n++;
         }
    edi = s_edi; esi = s_esi; ebx = s_ebx;
}
void sub_001F1ED1_gen(void);
void sub_001F1ED1(void)   /* IDirectSoundBuffer_Lock(this, off, bytes, ppv1, pcb1, ppv2, pcb2, flags) */
{
    static int n = 0;
    uint32_t a[8], i; for (i = 0; i < 8; i++) a[i] = MEM32(esp + 4 + 4 * i);
    uint32_t s_edi = edi, s_esi = esi, s_ebx = ebx;
    {   static uint32_t s_ppv = 0, s_pcb = 0;   /* what did the caller write into the region it locked last time? */
        if (s_ppv > 0x1000 && s_ppv < 0x8000000 && n < 80) { uint32_t k, nz = 0; for (k = 0; k < s_pcb; k += 4) nz += (MEM32(s_ppv + k) != 0);
             }
        sub_001F1ED1_gen();
        s_ppv = (a[3] > 0x1000 && a[3] < 0x8000000) ? MEM32(a[3]) : 0; s_pcb = (a[4] > 0x1000 && a[4] < 0x8000000) ? MEM32(a[4]) : 0; if (s_pcb > 0x10000) s_pcb = 0;
    }
    if (n < 80) { n++;
         }
    edi = s_edi; esi = s_esi; ebx = s_ebx;
}
void sub_0019B0F0_gen(void);
void sub_0019B0F0(void)   /* CRI ADX output writer: (obj) -> pushes decoded PCM to each attached device */
{
    static int n = 0;
    uint32_t obj = MEM32(esp + 4);
    uint32_t s_edi = edi, s_esi = esi, s_ebx = ebx;
    if (n < 40) { n++;
         }
    sub_0019B0F0_gen();
    if (n <= 40) {  }
    edi = s_edi; esi = s_esi; ebx = s_ebx;
}
void sub_0019B380_gen(void);
void sub_0019B380(void)   /* CRI ADX output server step: gates the PCM writer on the manager state at 0x00C6F200 */
{
    static int n = 0; static uint32_t last[4] = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
    uint32_t s_edi = edi, s_esi = esi, s_ebx = ebx, k;
    for (k = 0; k < 4; k++) { uint32_t m = 0x00C6F200 + k * 0x4D8, st = MEM32(m);
        if (st != last[k] && n < 60) { n++; last[k] = st;
             } }
    sub_0019B380_gen();
    edi = s_edi; esi = s_esi; ebx = s_ebx;
}
void sub_0019B040_gen(void);
void sub_0019B040(void)   /* CRI ADX output server, mode 1: pull decoded data from the source and probe it */
{
    static int n = 0;
    uint32_t obj = MEM32(esp + 4), src = MEM32(obj + 0x1C);
    uint32_t s_edi = edi, s_esi = esi, s_ebx = ebx;
    sub_0019B040_gen();
    if (n < 24) { n++;
         }
    edi = s_edi; esi = s_esi; ebx = s_ebx;
}

/* The resource-load service (sub_000804EB) keeps the slot pointer in ESI
 * across its callees and, on completion at 0x00080646, writes the request key
 * back through it: [esi+3] = [esi+1], [esi+4] = [esi+2]. ESI is callee-saved,
 * but the recompiled callees drop it (the split-epilogue class), so the
 * completed resource is filed under key (0xFF,0xFF) instead of its real one.
 * sub_0007ED10 then never finds it and sub_00074470 retries forever, which is
 * what keeps the screen dispatcher out of its loop. Enforce the ABI. */
#define ABI_MARK2(name) \
    void name##_gen(void); \
    void name(void) { \
        uint32_t _di = edi, _si = esi, _bx = ebx; \
        static int n = 0; int log = (n < 60); n++; \
        if (log) {   } \
        name##_gen(); \
        edi = _di; esi = _si; ebx = _bx; \
        if (log) {   } \
    }
#define ABI_MARK(name) \
    void name##_gen(void); \
    void name(void) { \
        uint32_t _di = edi, _si = esi, _bx = ebx; \
        name##_gen(); \
        edi = _di; esi = _si; ebx = _bx; \
    }
BOOT_MARK2(sub_000A5B40)
BOOT_MARK2(sub_00086980)
BOOT_MARK2(sub_00085820)
BOOT_MARK2(sub_00084FD0)
BOOT_MARK2(sub_001C663F)
/* Load-wait exit: what did the resource loader actually leave in the
 * destination? id/dest are the request globals (sub_0007E4A0). */
void sub_00085D70_gen(void);
void sub_00085D70(void) {
    uint32_t _di = edi, _si = esi, _bx = ebx;
    static int n = 0; int log = (n < 60); n++;
    if (log) {   }
    sub_00085D70_gen();
    edi = _di; esi = _si; ebx = _bx;
    if (log) {
        uint32_t dst = MEM32(0x005B3194); int k;
    }
}
BOOT_MARK2(sub_0007D5C0)
ABI_MARK2(sub_001E0900)
ABI_MARK2(sub_00086F50)
BOOT_MARK2(sub_0008A240)
BOOT_MARK2(sub_0019F7D0)   /* movie teardown chain (enter/exit) */
BOOT_MARK2(sub_001A0CB0)   /* movie teardown chain (enter/exit) */
BOOT_MARK2(sub_00192C10)   /* movie teardown chain (enter/exit) */
BOOT_MARK2(sub_001A0010)   /* movie teardown chain (enter/exit) */
/* Set once the movie teardown has returned -- i.e. the game has genuinely
 * left the intro movie. The frame-capture diagnostic keys off this. */
volatile int g_doa3_post_movie = 0;
volatile int g_doa3_in_pump = 0;   /* doa3_pump_cri_servers is on the stack */
/* May the primary fiber hand a time slice to the worker threads right now?
 * Only after the movie (its verified timing is left alone), never from
 * inside the CRI server pump, and not while the CRI lock is held or a CRI
 * server is on the stack -- the workers would re-enter them. */
int doa3_workers_may_run(void)
{
    return g_doa3_post_movie && !g_doa3_in_pump && MEM32(0x0040C6F8) == 0 && MEM32(0x00C85160) == 0;
}

/* [FLOWCNT] which links of the title-screen chain actually execute.
 * mode 0 (sub_00087EB0) -> mode 1 (sub_00083BC0 sets 0x005A26CC) ->
 * sub_000CF500/sub_000C6E30 populate the player slots ->
 * sub_000C5D70 -> sub_000C4D00 advances the screen state byte ->
 * state >= 10 -> sub_000CEB20 sets 0x00596A5C = 1 -> title screen. */
unsigned g_fc[16];
void doa3_flowcount_dump(void)
{
}


/* D3DDevice_SetTransform (0x001DC3F0) and D3DDevice_SetViewport (0x001DD240)
 * and D3D_UpdateProjectionViewportTransform (0x001DDF40), from the cxbx symbol
 * cache. DIAGNOSTIC WRAPPERS (logging only).
 *
 * The composite matrix the GPU receives is all zeros because the driver builds
 * it as projection-viewport (device+0x5A0) x view (device+0x880), and both of
 * those are garbage: +0x5A0 is never written at all (only
 * D3D_UpdateProjectionViewportTransform writes it) and +0x880 comes back as
 * mostly zeros from SetTransform. Log what the game actually hands the driver
 * so it is clear whether the game computes a bad matrix or the driver loses
 * a good one. */
void doa3_dump_mat4(const char *tag, uint32_t p)
{
    int i;
    for (i = 0; i < 16; i++) {
        float f; uint32_t u = MEM32(p + i * 4);
        memcpy(&f, &u, 4);
    }
}
/* Render-target identity for the pgraph translator: the implicit back buffer
 * surface lives inside the device object (dev+0x2150 / dev+0x2168); anything
 * else the game hands SetRenderTarget is a texture surface (the reflection
 * target 0x04002E50 in stage 0x3F). Both have the same 720x480 pitch, so
 * the translator cannot tell them apart from surface registers alone; it
 * keys on the colour offsets recorded here (D3DResource.Data & 0x03FFFFFF,
 * which is what SET_SURFACE_COLOR_OFFSET carries). */
uint32_t g_doa3_fb_offs[4]; int g_doa3_fb_n;
uint32_t g_doa3_offrt_offs[8]; int g_doa3_offrt_n;   /* every texture surface seen */

/* The guest's own D3DPRESENT_PARAMETERS (0x00A48C30): the DISPLAY resolution,
 * 720x480, which is the space every 2D overlay coordinate the game submits is
 * expressed in.  It is NOT the size of the colour surface -- on character
 * select the game turns on 2x2 supersampling (D3DRS_MultiSampleType 0x2022)
 * and the frame buffer becomes 1440x960, while the overlay quads keep coming
 * in at 0..720 / 0..480.  Anything mapping overlay coordinates onto the host
 * back buffer has to divide by this, not by SET_SURFACE_CLIP.
 * Returns 0 and leaves the outputs alone if the fields are not plausible
 * (before CreateDevice they are zero). */
int doa3_guest_display_size(unsigned *w, unsigned *h)
{
    uint32_t dw = MEM32(0x00A48C30u), dh = MEM32(0x00A48C34u);
    if (dw < 64u || dw > 4096u || dh < 64u || dh > 4096u) return 0;
    *w = (unsigned)dw; *h = (unsigned)dh;
    return 1;
}


/* CRI callback dispatch: enforce the callee-saved ABI.
 *
 * sub_0019A5E0 walks a table of registered callbacks and invokes each
 * through an indirect call, having pushed ebx/ebp/esi/edi on entry and
 * popping them on exit -- so on hardware a caller's edi survives it.
 * Here it does not: a callback corrupts the guest stack slots holding
 * those saved registers, and the pops read live data back instead
 * (observed: edi 0x00000001 -> 0x00000000, then 0x00C0F7C0, 0x001EB3A0).
 *
 * That single lost register is what deadlocked the movie teardown. The
 * CRI server loop at 0x0016A650 holds its sentinel in edi (edi = 1) and
 * clears the shutdown-ack flag only when [0xB24D3C] == edi. With edi
 * corrupted the compare never matched, so the ack was never given and
 * the teardown wait (sub_0016A4C0) spun its full 200,000,000 iterations
 * -- the game hung between the intro movie and the post-movie screen.
 * The server was running the whole time (its heartbeat 0xB24D48 climbed
 * past 700k during the stall); it simply never took the clear branch.
 *
 * Snapshot and restore in C, which is what the guest stack was meant to
 * do and cannot be trusted to here. Same remedy as ESP_PROBE above. */
void sub_0019A5E0_gen(void);
void sub_0019A5E0(void) {
    uint32_t s_edi = edi, s_esi = esi, s_ebx = ebx;
    sub_0019A5E0_gen();
    edi = s_edi; esi = s_esi; ebx = s_ebx;
}

/* DOA3 DIAG: sub_00157700 (vertex-block walker, this in ecx) ring of the
 * last entries -- dumped by the VEH when a wild read fires inside it, so the
 * object whose block chain is garbage is identified at the fault. */
struct doa3_vbw_ent { uint32_t self, f4, f8, l50, l54, l58, l5c, l60, blk, blk68, seq; };
struct doa3_vbw_ent g_vbw_ring[8]; unsigned g_vbw_seq = 0;
void doa3_vbw_dump(void)
{
    unsigned i;
    for (i = 0; i < 8; i++) {
        struct doa3_vbw_ent *e = &g_vbw_ring[i];
        if (!e->seq) continue;
    }
}

/* [INCHAIN] end-to-end input plumbing.
 *
 * XInputGetState fills the pad state; sub_000A4E70 folds the four pads
 * into the per-frame aggregates at 0x0073C8D0 (+0x2C per pad), whose
 * button word at +8 is what the post-movie screen tests for START
 * (sub_00088910, 0x000822BB: test byte [0x0073C8D8], 0x10).
 *
 * Counters, so the chain can be checked headless: if the builder never
 * runs post-movie, no keypress could ever reach the game. */
unsigned g_in_getstate, g_in_build;
CALL_COUNT_PROBE(sub_001931E0)   /* ADX stream handle create (movie work buf) */

/* DIAG: ADXF_LoadPartition (sub_00190EF0): print ptid + filename to map which
 * partition mount hits "not AFS". */
void sub_00190EF0_gen(void);
void sub_00190EF0(void)
{
    uint32_t id = MEM32(esp + 4), fn = MEM32(esp + 8);
    char nm[40] = {0};
    if (fn >= 0x10000 && fn < 0x8000000)
        for (int i = 0; i < 39; i++) { nm[i] = (char)MEM8(fn + i); if (!nm[i]) break; }
    sub_00190EF0_gen();
}

/* DIAG: CRI CompareFileTime (used by the cache validator sub_000A4378 to
 * decide 0x0073C0A4 cache-dirty). Print both FILETIMEs + result for the first
 * calls to see which compare rejects our pre-seeded cache files. */
void sub_0018BEB9_gen(void);
void sub_0018BEB9(void)
{
    static int s_n = 0;
    uint32_t a = MEM32(esp + 4), b = MEM32(esp + 8);
    uint32_t alo = MEM32(a), ahi = MEM32(a + 4), blo = MEM32(b), bhi = MEM32(b + 4);
    sub_0018BEB9_gen();
    if (++s_n <= 12) {
    }
}

/* DIAG: wxCi copy pump — gated on the wxCi object state (+1)==2. */
void sub_0019C120_gen(void);
void sub_0019C120(void)
{
    static unsigned s_n = 0;
    uint32_t obj = MEM32(esp + 4);
    s_n++;
    if (s_n <= 4 || (s_n % 3000) == 0) {
    }
    sub_0019C120_gen();
}

/* DIAG: esp-balance probes for the state-block batch callees (drift hunt).
 * Each prints espin/espout for its first few calls. */
#define ESP_PROBE(fn) \
    void fn##_gen(void); \
    void fn(void) { \
        uint32_t ei = esp; \
        uint32_t s_edi = edi, s_esi = esi, s_ebx = ebx; /* enforce callee-saved ABI */ \
        fn##_gen(); \
        edi = s_edi; esi = s_esi; ebx = s_ebx; \
        static int s_n = 0; \
        if (s_n < 4) { s_n++; \
             \
             } \
    }
/* CreateDevice tail: two callees leak the guest stack, and that is what left
 * the device without a render target.
 *
 * D3DDevice_CreateDevice ends in the fragment at 0x001B9537, which reads the
 * device out of its own frame at [esp+4] and hands the implicit back buffer
 * (device + 0x2150) to SetRenderTarget. Measured across that tail, esp came
 * back 0xC0 bytes low -- sub_001E2E01 returned -8 where it should return +4,
 * and sub_001B9130 returned -172 where it should return +8, which is exactly
 * the 192 lost. Both are split functions whose pushes are popped in a
 * successor fragment, so the pops never run on the path taken here.
 *
 * With the frame shifted, [esp+4] read 0xEFFF00DE instead of the device, so
 * SetRenderTarget stored 0xEFFF222E as the current colour surface. SetViewport
 * clamps every viewport against that surface: the game asks for 720x480 and
 * the device records width 0, D3D_UpdateProjectionViewportTransform then
 * builds an all-zero projection-viewport matrix, the composite matrix streamed
 * to the GPU is 16 zero dwords, and every transformed vertex lands on the
 * viewport centre. That is the black post-movie screen.
 *
 * Enforce the documented contract at both boundaries: pop the dummy return
 * slot plus the callee-popped argument bytes, and restore the callee-saved
 * registers the split epilogues never restored. */
ESP_PROBE(sub_001E24B0)   /* GPU wait spin (ret 0)            expect d=+4  */
/* (the ESP_FIX uses live next to the macro definition further down) */

ESP_PROBE(sub_0019E9B0)   /* movie ring finalize */
/* Push-buffer append (0x001DDEB0) -- __fastcall(ecx, edx), plain ret.
 *
 * Reserves 8 bytes at the device write cursor and stores ecx/edx there:
 *
 *     mov eax, [0x001EB3A0] / add eax, 8 / cmp eax, [0x001EB3A4]
 *     jae  full
 *     mov [0x001EB3A0], eax / mov [eax-8], ecx / mov [eax-4], edx / ret
 *   full:
 *     call sub_001B8B00        ; make space
 *     jmp  0x001DDEB0            ; retry
 *
 * 0x001EB3A0 is not a private global: [0x1C3390] (the device pointer) is set
 * to 0x001EB3A0, so these are dev+0 and dev+4 -- the very cursor/limit pair
 * the sub_001B8DA0 and sub_001B8DC0 overrides already clamp. This path does
 * not go through either of them; it tests the limit itself and relies on
 * sub_001B8B00 to wrap, which never happens here. So once the buffer filled,
 * the retry never succeeded -- and because the guest "jmp" back to the top is
 * emitted as a call, that hardware retry loop became real recursion and ran
 * the host stack out (0xC00000FD, frames all sub_001DDEB0+0x31).
 *
 * Apply the same wrap the other two use and do the append directly, so there
 * is no retry to recurse on. */
static void doa3_pb_wrap(uint32_t dev, const char *who);
ESP_PROBE(sub_001DC340)
ESP_PROBE(sub_001EEA0C)   /* D3DX draw (8 args, ret 0x20): expect d=+36 */

/* DIAG: drift probes for the 8 dirty-state sub-appliers under sub_001B7690. */
#define DRIFT_PROBE(fn) \
    void fn##_gen(void); \
    void fn(void) { \
        static int s_n = 0; \
        uint32_t ei = esp; \
        fn##_gen(); \
        if (s_n < 8 && (int)(esp - ei) != 8) { \
            s_n++; \
             \
             } \
    }

/* sub_001B3760 — D3D inline vertex push (BEGIN prim + scatter-gather copy of
 * vertex attributes into the push buffer). The copy loop walks descriptors at
 * device+0x7F4 (pairs {dwords, skip}) with count device+0x874, both populated
 * by SetVertexShader. Print them at call time: garbage descriptors = the
 * movie-quad crash (host memcpy read past base+4GB). */
static int doa3_pb_recording(uint32_t dev);
extern uint32_t g_doa3_pb_base, g_doa3_pb_end;
/* [TASKNEW] temporary: which task entry points actually get registered.
 * sub_001C66A2(priority, entry) is the task-create the post-movie screen
 * (0x000CEF80) is launched through from sub_00087D00. */
void sub_001C66A2_gen(void);
void sub_001C66A2(void) {
    uint32_t pri = MEM32(esp + 4), ent = MEM32(esp + 8);
    static int n = 0;
    if (n < 40) { n++;
         }
    sub_001C66A2_gen();
}
void sub_00089AC0_gen(void);
void sub_00089AC0(void) {
    static int n = 0;
    sub_00089AC0_gen();
    if (n < 6) { n++;
          }
}
unsigned g_mw_calls, g_mw_st6, g_mw_set3, g_mw_laststate;
unsigned g_e1f0_calls, g_e1f0_nz;
/* [MVST] temporary: what the movie status vtable slot actually reports. */
unsigned g_st_calls; int g_st_lastret, g_st_lastst8; uint32_t g_st_lastobj;
void sub_0019F460_gen(void);
void sub_0019F460(void) {
    uint32_t obj = MEM32(esp + 4);
    uint32_t h = obj ? MEM32(obj + 0x30) : 0;
    g_mw_calls++;
    if (h) { g_mw_laststate = MEM32(h + 0x40);
             if (g_mw_laststate == 6) g_mw_st6++; }
    sub_0019F460_gen();
    if (obj && MEM32(obj + 8) == 3) g_mw_set3++;
}

/* ESP_FIX: like ESP_PROBE but also ENFORCES the known stdcall stack cleanup
 * (esp_out = esp_in + 4 + argbytes) — for XDK functions whose inner callees
 * leak stack through mis-split fragments. Registers + esp fully restored to
 * the ABI contract; the inner rot stays contained. */
#define ESP_FIX(fn, argbytes) \
    void fn##_gen(void); \
    void fn(void) { \
        uint32_t ei = esp; \
        uint32_t s_edi = edi, s_esi = esi, s_ebx = ebx; \
        fn##_gen(); \
        edi = s_edi; esi = s_esi; ebx = s_ebx; \
        esp = ei + 4 + (argbytes); \
    }
/* D3DTexture_LockRect (0x001E0570, per cxbx symbols) — full semantic override.
 * The inner XDK path (sub_001E4420/sub_001E41F0) is mis-split by the lifter
 * and returned a garbage D3DLOCKED_RECT (pBits=0/0x2D0), so the movie CSC
 * had no destination and the screen stayed black. Decode the Xbox
 * D3DPixelContainer header ourselves:
 *   +0 Common  +4 Data (GPU addr of pixels)  +8 Lock  +C Format  +10 Size
 *   Size(linear): width-1 [0:11] | height-1 [12:23] | pitch/64-1 [24:31]
 * pBits = Data (raw guest RAM address; 0x8xxxxxxx alias also maps there).
 * args: (pTex, level, pLockedRect, pRect, flags), ret 20, eax=HRESULT. */
void sub_001E0570(void)
{
    uint32_t tex   = MEM32(esp + 4);
    uint32_t plr   = MEM32(esp + 0xC);
    static int s_n = 0;
    uint32_t data = 0, fmt = 0, size = 0, pitch = 0;
    if (tex >= 0x1000 && tex < 0x8000000u) {
        data = MEM32(tex + 4);
        fmt  = MEM32(tex + 0xC);
        size = MEM32(tex + 0x10);
        if (size) {
            pitch = (((size >> 24) & 0xFF) + 1) * 64;
        } else {
            /* swizzled/power-of-2 header: pitch from format U/P exponent */
            uint32_t u = (fmt >> 20) & 0xF;              /* log2 width */
            uint32_t bpp = ((fmt >> 8) & 0xFF);
            pitch = (1u << u) * ((bpp == 0x11 || bpp == 0x1E) ? 1 : 2);
        }
    }
    if (plr >= 0x1000 && plr < 0x8000000u) {
        MEM32(plr)     = pitch;                          /* D3DLOCKED_RECT.Pitch */
        MEM32(plr + 4) = data & 0x07FFFFFFu;             /* .pBits (raw RAM addr) */
    }
    if (s_n < 8) {
    }
    s_n++;
    eax = 0;
    esp += 24;   /* fake-ret slot + ret 20 */
}
ESP_FIX(sub_001E96A5, 4)   /* D3DDevice_ApplyStateBlock(handle), ret 4 */
ESP_FIX(sub_001EE0A0, 8)   /* D3DX context factory (dev, out), ret 8 */

/* Main-loop callee balance probes: the frame loop (sub_000A06D0) leaks
 * ~320 B/frame; find which per-frame callee drifts (prints every 600th
 * call with esp so the drift shows). */
#define LOOP_PROBE(fn) \
    void fn##_gen(void); \
    void fn(void) { \
        static unsigned s_n = 0; \
        uint32_t ei = esp; \
        fn##_gen(); \
        s_n++; \
        if ((s_n % 600) == 1) { \
             \
             } \
    }
LOOP_PROBE(sub_000A65B0)
void sub_001A77B0_gen(void);
void sub_001A77B0(void)
{
    static unsigned s_n = 0;
    uint32_t ei = esp;
    sub_001A77B0_gen();
    s_n++;
    if ((s_n % 5000) == 1 && ei > 0xF00000) {   /* task-stack callers only (heap base) */
        void *bt[7]; int n = CaptureStackBackTrace(1, 7, bt, NULL);
    }
}
ESP_FIX(sub_00180490, 0)  /* DSOUND buffer maintenance: leaked 24 B/frame */
LOOP_PROBE(sub_0018BDD1)
LOOP_PROBE(sub_001C650C)
LOOP_PROBE(sub_000A6680)

/* ── DIAG: sprite/glyph blitter (sub_000403F0) — wild-write storm source ─────
 * (struct, count) cdecl. Writes walk from a garbage dest; log the struct and
 * its dest-surface field (+0x278) to find where the bad pointer comes from. */
int g_blit_gen_hits = 0;   /* incremented by a probe at sub_000403F0_gen entry */

/* ── D3D8 push-buffer overrides (following burnout3's PB-trio pattern) ────────
 * burnout3 overrides its push-buffer management functions (sub_003518E0 kickoff,
 * sub_00351770 make-space, sub_00351A20 flush) in recomp_manual.c to: keep the
 * device write cursor inside a real RAM buffer, and simulate the GPU having
 * consumed the buffer + acked the fence (so the D3D8LTCG spin loops exit).
 * docs/d3d8ltcg_device_context.md: "device+0x30 -> device+0x2C ... GPU_read ==
 * write -> no spin loop".
 *
 * DOA3 is retail D3D8 (not D3D8LTCG); the cxbx symbol cache names the exact
 * analogues:  CDevice_KickOff=0x1B88C0, CDevice_MakeSpace=0x1B8B00,
 * XMETAL_StartPush=0x1B8DA0.  Device PB fields (mapped by reading the gen code):
 *   device[0]        = PB write cursor      device+0x04   = PB segment limit
 *   device+0x2304    = fence notifier ptr   notifier+0x44 = GPU-acked fence value
 *   device+0x2518    = FIFO GET (GPU read)  device+0x2B60 = FIFO PUT (CPU write)
 * The fence waits compare (MEM32(device) ^ MEM32(notifier+0x44)) & 0xFFFFFFF, so
 * setting notifier+0x44 = device[0] makes them self-equal -> always satisfied
 * (the "GPU read == write" trick, adapted to DOA3's notifier layout).
 * RAM push buffer is allocated in main.c. */
/* Flags carried across a generated-fragment boundary; see recomp_types.h.
 * Exact x86 flag semantics for CMP (a - b) and TEST (a & b) at the operand
 * width the compare used. */
uint32_t g_flg_a, g_flg_b;
int g_flg_w = 4, g_flg_test;

int rc_flg_cc(int cc)
{
    uint32_t mask = (g_flg_w == 1) ? 0xFFu : (g_flg_w == 2) ? 0xFFFFu : 0xFFFFFFFFu;
    uint32_t sign = (g_flg_w == 1) ? 0x80u : (g_flg_w == 2) ? 0x8000u : 0x80000000u;
    uint32_t a = g_flg_a & mask, b = g_flg_b & mask, r;
    int zf, sf, cf = 0, of = 0, pf, i, ones = 0;
    unsigned lo;

    if (g_flg_test) {
        r = (a & b) & mask;
    } else {
        r = (a - b) & mask;
        cf = (a < b);
        of = ((((a ^ b) & (a ^ r)) & sign) != 0);
    }
    zf = (r == 0);
    sf = ((r & sign) != 0);
    lo = (unsigned)(r & 0xFFu);
    for (i = 0; i < 8; i++) if (lo & (1u << i)) ones++;
    pf = ((ones & 1) == 0);

    switch (cc) {
    case 0:  return zf;                 /* je  */
    case 1:  return !zf;                /* jne */
    case 2:  return cf;                 /* jb  */
    case 3:  return !cf;                /* jae */
    case 4:  return cf || zf;           /* jbe */
    case 5:  return !cf && !zf;         /* ja  */
    case 6:  return sf != of;           /* jl  */
    case 7:  return sf == of;           /* jge */
    case 8:  return zf || (sf != of);   /* jle */
    case 9:  return !zf && (sf == of);  /* jg  */
    case 10: return sf;                 /* js  */
    case 11: return !sf;                /* jns */
    case 12: return of;                 /* jo  */
    case 13: return !of;                /* jno */
    case 14: return pf;                 /* jp  */
    case 15: return !pf;                /* jnp */
    default: return 0;
    }
}

uint32_t g_doa3_pb_base = 0, g_doa3_pb_end = 0;
uint32_t g_doa3_movie_ticks = 0;    /* synthetic movie clock (PTS units) */
uint32_t g_doa3_movie_frames = 0;   /* frames actually blitted (clock pace anchor) */
static uint32_t g_pb_parsed = 0;   /* last push-buffer offset translated to D3D11 */

/* Push-buffer -> D3D11 translation (following burnout3's parse_live_pushbuffer).
 * Walk new push-buffer dwords [from, to), decode NV2A Kelvin method headers, and
 * dispatch each method to the shared pgraph_d3d11 translator (renders through the
 * host D3D8->D3D11 device). NV097_CLEAR_SURFACE (0x1D0) begins a frame, so present
 * the previous frame's accumulated draws when we hit one. */
#define NV097_CLEAR_SURFACE 0x01D0u
static void doa3_translate_pb(uint32_t from, uint32_t to)
{
    extern int  pgraph_d3d11_method(int subchannel, uint32_t method, uint32_t param);
    extern void pgraph_d3d11_flush(void);
    extern void doa3_present_frame(void);
    static int drew_since_present = 0;

    (void)drew_since_present;
    uint32_t pos = from;
    /* DOA3 DIAG: words the parser cannot read as a method header, and
     * headers whose parameters run past the write cursor. Either one means
     * the parse is out of step with the guest's stream. */
    extern volatile int g_doa3_post_movie;
    static uint32_t s_skip = 0, s_over = 0, s_hdrs = 0; static int s_log = 0;
    static DWORD s_next = 0;
    uint32_t last_hdr = 0, last_pos = 0;
    while (pos + 4 <= to) {
        uint32_t word = MEM32(pos); pos += 4;
        if (word == 0) continue;                       /* NOP / padding */
        uint32_t kind = word & 0xE0030003u;
        if (kind == 0 || kind == 0x40000000u) {        /* increasing / non-increasing */
            uint32_t count   = (word >> 18) & 0x7FF;
            uint32_t method  = word & 0x1FFC;
            uint32_t subchan = (word >> 13) & 7;
            s_hdrs++;
            if (count == 0 || pos + count * 4 > to) {
                s_over++;
                if (g_doa3_post_movie && s_log < 40) { s_log++;
                     }
                continue;
            }
            last_hdr = word; last_pos = pos - 4 - from;
            for (uint32_t i = 0; i < count; i++) {
                uint32_t param = MEM32(pos); pos += 4;
                uint32_t m = (kind == 0) ? method + i * 4 : method;
                pgraph_d3d11_method((int)subchan, m, param);   /* translate to D3D11 */
            }
        }
        else {
            s_skip++;
            {   static uint32_t s_ctx = 0; static uint32_t s_ctx_from = 0;
                if (g_doa3_post_movie && s_ctx < 8 && s_ctx_from != from) { s_ctx++; s_ctx_from = from;
                    uint32_t k, b = (pos - 4 - from >= 48) ? pos - 4 - 48 : from;
                      }
            }
            if (g_doa3_post_movie && s_log < 40) { s_log++;
                 }
        }
        /* jump/call/return (low bits 1/2) carry no params we translate — skip */
    }
    if (g_doa3_post_movie && GetTickCount() >= s_next) {
        s_next = GetTickCount() + 2000;
    }
}

/* Wrap the write cursor back to the base of our RAM push buffer.
 *
 * Burnout's sub_00351770 parses [base, write_ptr) BEFORE it resets the
 * cursor. The DOA3 wrap sites below used to reset the cursor and leave
 * g_pb_parsed where it was, relying on the next KickOff to notice
 * g_pb_parsed > cursor and restart from the base. That only works if the
 * next kick is shorter than the old parsed offset: a frame that needs more
 * than the 1 MB buffer wraps mid-frame ([PBFULL] shows single kicks at
 * 786 KB), and the following kick then translated from an arbitrary point
 * inside the new stream -- index and vertex data read as method headers,
 * which put packed shorts into SET_SURFACE_PITCH/OFFSET, SET_VIEWPORT_SCALE
 * and SET_CLIP_MIN/MAX and routed the whole scene offscreen (the freeze
 * after the title stage). Everything written since the last kick was also
 * dropped. Translate the pending range, then reset both together. */
/* Recording mode. The XDK sets bit 2 of [dev+0xC] while the device records
 * into a scratch buffer (state-block / push-buffer-object recording): [dev]
 * then points at that scratch area (seen at 0x00E00244, in the guest stack
 * region), the live ring cursor is parked at [dev+0x400], and the original
 * MakeSpace (0x001B8B00, flag-4 branch) rewinds the scratch cursor to the
 * chunk base [[dev+0x3F4]+4] and adds the bytes written to [dev+0x3F8].
 * The overrides below used to treat that scratch cursor as "outside our
 * push buffer" and drag it to the ring base, so recorded commands were
 * written over the live stream and the parser was restarted on them:
 * 33 of the 40 logged wraps in rt163 were this case. */
static int doa3_pb_recording(uint32_t dev)
{
    return (MEM8(dev + 0xC) & 4) != 0;
}
static uint32_t doa3_pb_makespace_recording(uint32_t dev)
{
    uint32_t cursor = MEM32(dev);
    uint32_t desc   = MEM32(dev + 0x3F4);
    uint32_t chunk  = MEM32(desc + 4);
    extern volatile int g_doa3_post_movie;
    static int s_n = 0;
    MEM32(dev + 0x3F8) = MEM32(dev + 0x3F8) + (cursor - chunk);
    MEM32(dev) = chunk;
    if (g_doa3_post_movie && s_n < 12) { s_n++;
         }
    return chunk;
}

static void doa3_pb_wrap(uint32_t dev, const char *who)
{
    uint32_t cursor = MEM32(dev);
    extern volatile int g_doa3_post_movie;
    static int s_n = 0;
    if (cursor > g_pb_parsed && g_pb_parsed >= g_doa3_pb_base && cursor <= g_doa3_pb_end)
        doa3_translate_pb(g_pb_parsed, cursor);
    if (g_doa3_post_movie && s_n < 40) { s_n++;
         }
    {   /* DOA3 DIAG: a cursor outside our buffer altogether was not put
         * there by any of our overrides; name the guest routine that did. */
        static int s_odd = 0;
        if (g_doa3_post_movie && s_odd < 8 &&
            (cursor < g_doa3_pb_base || cursor > g_doa3_pb_end)) {
            void *bt[14]; USHORT nf = CaptureStackBackTrace(1, 14, bt, NULL); USHORT k;
            s_odd++;
        }
    }
    MEM32(dev + 0x00) = g_doa3_pb_base;              /* write cursor = base */
    MEM32(dev + 0x04) = g_doa3_pb_end;               /* segment limit = end */
    g_pb_parsed = g_doa3_pb_base;
}

/* CDevice_KickOff (0x1B88C0) — burnout sub_003518E0 analogue. fastcall (ecx=this),
 * ret 0. Simulate GPU drain + fence ack so the FIFO/fence spin loops exit. */
static unsigned g_kick_count = 0;

/* Render command-list walker (0x00180730) — cdecl(end, start), ret 0.
 *
 * The list is built by sub_00158BE0 as a flat run of records: type 0 is a
 * 0x290-byte state block, type 1 is 0xC bytes, type 2 is 0x14 bytes, and
 * every builder call appends at least the type-2 record.  The walker reads
 * the type word, dispatches, and adds the matching size.  A type word that
 * is not 0/1/2 sends it to loc_00158FC5, which only re-tests the bound —
 * ebx never advances, so the guest spins at 100% CPU with the process
 * alive.  That is the post-title hang: every [WDOG] report has the same
 * rip inside sub_00180730 and an unchanging ebx.
 *
 * The list does not overflow (watermark: 60 KB peak of 1 MB), so the chain
 * itself is breaking.  Replay it here before the walk, read-only, and say
 * where and on what.  The walk itself is unchanged. */
uint32_t g_walk_start, g_walk_end, g_walk_canary;

/* Per-record trace of the walk itself (called at loc_00158E20, once per
 * record).  The list validates clean at every entry and ebx survives every
 * callee, yet the walk still lands on a word that is not a record type, so
 * record what the walk actually visits and dump the tail when it breaks. */
void doa3_walk_step(uint32_t rec)
{
    extern volatile int g_doa3_post_movie;
    extern volatile LONG g_doa3_heartbeat;
    static uint32_t ring[12]; static unsigned n = 0; static int reported = 0;
    uint32_t t = MEM32(rec);
    ring[n % 12] = rec; n++;
    {   /* Who else touches this buffer while the walk is reading it?
         * sub_00181400 repoints the RECORDING write pointer [0x00AD38FC] at
         * 0x00B58A88 -- the same 1 MB buffer the walk is reading -- and sets
         * the recording flag [0x00B58A84]; the append path sub_00158D60 then
         * writes state-block records over it from the base.  Nothing moves
         * [0x00C58A90], so the earlier write-pointer and canary checks could
         * not see it.  Latch the frame state at the first record of a walk
         * and report the first thing that changes under it. */
        extern int xbox_fiber_current(void);
        static uint32_t w0, f0, rp0, wp0; static int fib0, armed = 0, told = 0;
        if (w0 != g_walk_start || wp0 != g_walk_end) {
            w0 = g_walk_start; wp0 = g_walk_end;
            f0 = MEM32(0x00B58A84u); rp0 = MEM32(0x00AD38FCu);
            fib0 = xbox_fiber_current(); armed = 1;
        } else if (armed && g_doa3_post_movie && told < 6) {
            uint32_t f = MEM32(0x00B58A84u), rp = MEM32(0x00AD38FCu);
            int fib = xbox_fiber_current();
            if (f != f0 || rp != rp0 || fib != fib0) { told++; armed = 0;
                 }
        }
    }
    if (t <= 2 || !g_doa3_post_movie || reported >= 4) return;
    reported++;
    {
        unsigned i, first = (n > 12) ? n - 12 : 0;
        uint32_t p, good = 0; unsigned gi = 0;
        for (i = first; i < n; i++) {
            uint32_t r = ring[i % 12];
        }
        for (p = g_walk_start; p < g_walk_end; ) {
            uint32_t ct = MEM32(p);
            if (ct > 2) break;
            if (p <= rec) { good = p; gi++; } else break;
            p += (ct == 0) ? 0x290u : (ct == 1) ? 0xCu : 0x14u;
        }
    }
}
int      g_walk_active;

/* DIAG/OVERRIDE: CSC coefficient builder (matrix invert). Dump in/out. */
static double doa3_memd(uint32_t a) { 
    uint64_t q = (uint64_t)MEM32(a) | ((uint64_t)MEM32(a + 4) << 32);
    double d; memcpy(&d, &q, 8); return d;
}
static void doa3_stored(uint32_t a, double d)
{
    uint64_t q; memcpy(&q, &d, 8);
    MEM32(a) = (uint32_t)q; MEM32(a + 4) = (uint32_t)(q >> 32);
}
/* Full C override (item 81): the x87 emission of this 3x3 matrix inversion
 * came out subtly wrong (row 2 badly off -> Y-table lanes unequal -> the
 * whole movie rendered green). src = forward RGB->YUV matrix (row-major),
 * dst = inverse (YUV->RGB, rows = R,G,B lanes) x MEMD(0x0021A220) (=64, the
 * table fixed-point scale). Offsets/rounding are separate ROM constants
 * used by the table builder, not computed here. */
void sub_0019E640(void)
{
    static int s_n = 0;
    uint32_t src = MEM32(esp + 4), dst = MEM32(esp + 8);
    double a[9], inv[9];
    for (int k = 0; k < 9; k++) a[k] = doa3_memd(src + 8u * k);
    double det = a[0]*(a[4]*a[8]-a[5]*a[7])
               - a[1]*(a[3]*a[8]-a[5]*a[6])
               + a[2]*(a[3]*a[7]-a[4]*a[6]);
    double s = doa3_memd(0x0021A220) / det;
    inv[0]= (a[4]*a[8]-a[5]*a[7])*s; inv[1]=-(a[1]*a[8]-a[2]*a[7])*s; inv[2]= (a[1]*a[5]-a[2]*a[4])*s;
    inv[3]=-(a[3]*a[8]-a[5]*a[6])*s; inv[4]= (a[0]*a[8]-a[2]*a[6])*s; inv[5]=-(a[0]*a[5]-a[2]*a[3])*s;
    inv[6]= (a[3]*a[7]-a[4]*a[6])*s; inv[7]=-(a[0]*a[7]-a[1]*a[6])*s; inv[8]= (a[0]*a[4]-a[1]*a[3])*s;
    for (int k = 0; k < 9; k++) doa3_stored(dst + 8u * k, inv[k]);
    if (s_n < 2) {
    }
    s_n++;
    esp += 4;   /* cdecl */
}
#undef RESUME_GUARD

/* DIAG: MB-worker esp anomaly probes (the -36 hunt). Print only imbalances. */
#define ESPANOM_PROBE(fn)     void fn##_gen(void);     void fn(void) {         static int s_bad = 0;         uint32_t e0 = esp;         fn##_gen();         int _d = (int)(esp - e0);         if (_d != 4 && _d != 28 && s_bad < 12) {             s_bad++;                           } }
ESPANOM_PROBE(sub_0020FCA0)
#undef ESPANOM_PROBE

/* DIAG: skip-variant picture "decoders" (type-table entries 4/5) — esp
 * balance probes for the -36 leak in the skip chain. */
#define SKIPSTUB_PROBE(fn)     void fn##_gen(void);     void fn(void) {         static int s_n = 0;         uint32_t e0 = esp;         fn##_gen();         if (s_n < 10) {                           }         s_n++; }
#undef SKIPSTUB_PROBE

/* DIAG: post-decode frame handoff (h, cls, fridx) — display-queue push? */
void sub_001A06F0_gen(void);
void sub_001A06F0(void)
{
    static int s_n = 0;
    uint32_t h = MEM32(esp + 4), cls = MEM32(esp + 8), fr = MEM32(esp + 0xC);
    sub_001A06F0_gen();
    if (s_n < 14 || (s_n % 2048) == 0) {
    }
    s_n++;
}
static uint32_t g_doa3_display_frame;
static int doa3_display_trace_enabled(void)
{
    static int enabled = -1;
    if (enabled < 0)
        enabled = GetEnvironmentVariableA("DOA3_DISPLAYTRACE", NULL, 0) != 0;
    return enabled;
}
void sub_001A7680_gen(void);
void sub_001A7680(void)
{
    static int s_n = 0;
    uint32_t h = MEM32(esp + 4), fr = MEM32(esp + 8);
    sub_001A7680_gen();
    if (s_n < 12 || (s_n % 2048) == 0) {
    }
    s_n++;
}

/* DIAG: picture-index entry matcher (fastcall ecx=idxstruct; stack args
 * {pic, ringsize, ringbase}). Returns steps-to-entry or -1. */
void sub_001AB510_gen(void);
void sub_001AB510(void)
{
    static int s_n = 0;
    uint32_t st = ecx;
    uint32_t a1 = MEM32(esp + 4), a2 = MEM32(esp + 8), a3 = MEM32(esp + 0xC);
    sub_001AB510_gen();
    if (s_n < 10 || (s_n % 1024) == 0) {
    }
    s_n++;
}

/* CRI server pump — shared by the per-frame SetFence hook AND the vblank-wait
 * bridge. On hardware these servers run from the vsync interrupt / their own
 * threads; in the fiber model both starve unless pumped. Pumping ONLY from
 * Present livelocks the game-side movie wait loops ("wait vblank; poll
 * status") which never present — so the vblank wait also pumps (item 79). */

/* DOA3 DIAG: integrity check of the ADXF partition table for loadfile.afs
 * (block 0x005CE8F8: u16 sector sizes at +0x116, 1102 entries). Verified
 * intact through the boot loads and corrupted by the first post-movie load,
 * with no write caught by the page watch -- so it is checked from several
 * hook points to bracket the writer (an alias/host-side write). */
void (*g_kernel_ptinfo_hook)(const char *where);   /* kernel_bridge.c calls it from NtReadFile */
static uint16_t s_pt_ref[1102];
static int s_pt_have = 0, s_pt_reported = 0;
static const char *s_pt_last_ok = "none"; static unsigned s_pt_checks = 0;
void doa3_ptinfo_check(const char *where)
{
    const uint32_t blk = 0x005CE8F8u;
    int i;
    /* OFF unless DOA3_PTCHK=1. This walks 1102 entries and is called from
     * the present/flush/kick/pump/read hooks, i.e. several times a frame.
     * Left on by default it starves the cooperative decode fibers and the
     * intro movie ends after a handful of frames -- measured, not assumed. */
    {   static int s_want = -1;
        if (s_want < 0) { const char *e = getenv("DOA3_PTCHK"); s_want = (e && *e == '1'); }
        if (!s_want) return; }
    if (s_pt_reported) return;
    if (!s_pt_have) {
        if (MEM32(0x00C7E1C0 + 4) != blk || MEM16(blk + 0xC) != 1102 ||
            MEM16(blk + 0x116 + 2 * 0x15) != 0x328) return;
        for (i = 0; i < 1102; i++) s_pt_ref[i] = MEM16(blk + 0x116 + 2u * i);
        s_pt_have = 1;
        return;
    }
    {   int first = -1, last = -1, n = 0;
        for (i = 0; i < 1102; i++)
            if (MEM16(blk + 0x116 + 2u * i) != s_pt_ref[i]) { if (first < 0) first = i; last = i; n++; }
        if (first >= 0) {
            void *bt[16]; USHORT nb = CaptureStackBackTrace(0, 16, bt, NULL); int k;
            s_pt_reported = 1;
        } else { s_pt_last_ok = where; s_pt_checks++; }
    }
}

/* ── Override: CRT small-block-heap allocator __sbh_alloc_block @ 0x0018E2DE ──
 * DOA3's recompiled SBH init leaves the heap descriptor global (0x00C6BAC0) NULL,
 * so the generated allocator walks free-lists from a NULL descriptor and faults.
 * Serve allocations from a private bump arena instead. (Gen body #if 0'd in
 * recomp/gen/recomp_0008.c — re-apply after regen.) The matching SBH free path
 * finds our blocks in no (empty) SBH region and falls back to a no-op system
 * free, so blocks are effectively leaked-freed.
 * __stdcall(heapDesc, flags, size) -> block VA in eax; callee pops 3 args. */
static uint32_t g_sbh_next = 0, g_sbh_end = 0;

/* Size-classed allocator with REAL free (the pure bump version leaked every
 * CRT free -> 45 MB Xbox heap exhausted during the boot screen loads, and the
 * game doesn't check malloc failure -> wild-write storms). Each block gets a
 * 16-byte header {magic, chunk_size, class, freelist_next}; freed blocks go
 * on per-class LIFO lists and are reused. <1MB: power-of-2 classes; >=1MB: a
 * first-fit large list (64 KB granularity). Backing memory still comes from
 * the bump arena (xbox_HeapAlloc 8 MB refills). */
#define SBH_MAGIC 0x48334142u
#define SBH_NCLASS 16               /* 32 << 0 .. 32 << 15 (= 1 MB) */
static uint32_t g_sbh_class_head[SBH_NCLASS]; /* header VAs */
static uint32_t g_sbh_large_head = 0;

static uint32_t g_sbh_nalloc = 0, g_sbh_nfree = 0, g_sbh_nforeign = 0;
static uint64_t g_sbh_live = 0;

static void sbh_free(uint32_t block)
{
    if (block < 32) return;
    uint32_t hdr = block - 16;
    if (MEM32(hdr) != SBH_MAGIC) { g_sbh_nforeign++; return; } /* foreign/corrupt: leak */
    MEM32(hdr) = SBH_MAGIC + 1;             /* poison against double free */
    uint32_t cls = MEM32(hdr + 8);
    g_sbh_nfree++; g_sbh_live -= MEM32(hdr + 4);
    if (cls < SBH_NCLASS) {
        MEM32(hdr + 8) = g_sbh_class_head[cls];
        g_sbh_class_head[cls] = hdr;
    } else {
        MEM32(hdr + 8) = g_sbh_large_head;
        g_sbh_large_head = hdr;
    }
}

/* __sbh_free_block(desc, flags, block) — called by the CRT free front
 * sub_0018B857. Was a no-op (blocks leaked). stdcall ret 12 -> esp += 16. */
void sub_0018EA60(void)
{
    sbh_free(MEM32(esp + 12));
    eax = 1;
    esp += 16;
}

/* ── Override: CRT heap creator (__sbh_heap_init core) @ 0x0018DEBA ──
 * The recompiled creator builds the SBH groups but returns a NULL descriptor
 * (its descriptor local stays 0 — the SEH-frame path that captures it is never
 * taken). Return a valid zeroed descriptor so _heap_init (sub_0018F83F) stores
 * a non-NULL 0x00C6BAC0 and downstream code reads sane (zero) descriptor fields.
 * Actual allocations are served by the sub_0018E2DE bump override above.
 * __stdcall, 6 args -> descriptor VA in eax. Gen body #if 0'd in recomp_0008.c. */
void sub_0018DEBA(void)
{
    eax = xbox_HeapAlloc(0x2000, 16);  /* 8 KB zeroed; ~0x600 used by descriptor */
    esp += 28;                          /* pop dummy return (4) + 6 args (24) */
}

/* sub_001F13AF -- IDirectSoundBuffer::Release() adjustor thunk
 * (`push eax; call [vtbl+8]; ret 4`, so __stdcall with one argument and
 * ebx/esi/edi callee-saved).
 *
 * The release chain under it (sub_001C792E -> sub_001C6BEF -> the class
 * destructor through vtable[0]) returns with the guest stack 4 to 8 bytes
 * low, and sub_001C6BEF's `pop edi; pop esi` epilogue then loads the wrong
 * slots -- measured directly at the call site: esi 006A69E8 -> 00000002,
 * esp delta 0 where +4 is correct.
 *
 * That lands in the attract flow: the screen-14 setup sweeps the voice table
 * in sub_000A5A00 (`for esi = 0x007FD3C8; esi < 0x007FE2C8; esi += 0x60`) and
 * calls this Release for every voice of the group. With esi destroyed the
 * sweep restarts from a wild pointer instead of advancing, calls Release on
 * garbage forever, and the guest stack marches down megabytes a second until
 * the host APU refuses another voice.
 *
 * Enforce the ABI the hardware guarantees, the same way sub_001BCC00 and
 * sub_001BC260 are enforced above. */
void sub_001F13AF_gen(void);
void sub_001F13AF(void)
{
    uint32_t ei = esp;
    uint32_t s_edi = edi, s_esi = esi, s_ebx = ebx;
    sub_001F13AF_gen();
    edi = s_edi; esi = s_esi; ebx = s_ebx;
    esp = ei + 4 + 4;   /* dummy return slot + one argument (ret 4) */
}

/* ICALL failure diagnostic (rate-limited).
 * Called by the RECOMP_ICALL macros when an indirect-call target resolves to
 * neither a generated function, a manual override, nor a kernel thunk. */
static uint64_t g_icall_fail_logged = 0;

/* Census of DISTINCT unresolved indirect-call targets.
 *
 * The line-by-line report below is capped at 200 lines, which the boot
 * phase exhausts long before the game reaches its screens -- so a target
 * that only ever fails later (the way sub_000318D0 did, right before a
 * null-pointer crash) never showed up. Track every distinct target with
 * a hit count instead, and dump the table on demand. */
#define ICALL_CENSUS_MAX 256
static struct { uint32_t va; uint32_t hits; } g_icall_census[ICALL_CENSUS_MAX];
static int g_icall_census_n;
static int g_icall_census_overflow;

void recomp_icall_census_dump(void)
{
    int i;
}

void recomp_icall_fail_log(uint32_t va)
{
    int new_target = 0;
    {   int i;
        for (i = 0; i < g_icall_census_n; i++)
            if (g_icall_census[i].va == va) { g_icall_census[i].hits++; break; }
        if (i == g_icall_census_n) {
            if (g_icall_census_n < ICALL_CENSUS_MAX) {
                new_target = 1;
                g_icall_census[g_icall_census_n].va = va;
                g_icall_census[g_icall_census_n].hits = 1;
                g_icall_census_n++;
            } else {
                g_icall_census_overflow = 1;
            }
        }
    }
    if (g_icall_fail_logged < 200 || new_target) {
        if (va == 0) {
            void *bt[10]; int n = CaptureStackBackTrace(1, 10, bt, NULL);
        }
        g_icall_fail_logged++;
    }
}

/* ── Manual override table ──────────────────────────────────────────
 * Map original Xbox VA -> hand-written replacement; the trailing {0,0}
 * sentinel keeps the array valid and is skipped at lookup. */
static const struct {
    uint32_t      xbox_va;
    recomp_func_t func;
} g_manual_funcs[] = {
    { 0u, 0 },  /* sentinel */
};
#define NUM_MANUAL_FUNCS (sizeof(g_manual_funcs) / sizeof(g_manual_funcs[0]))

recomp_func_t recomp_lookup_manual(uint32_t xbox_va)
{
    for (size_t i = 0; i < NUM_MANUAL_FUNCS; i++) {
        if (g_manual_funcs[i].func && g_manual_funcs[i].xbox_va == xbox_va)
            return g_manual_funcs[i].func;
    }
    return NULL;
}

/* DOA3 DIAG: esp balance of the PTS->frame chain under the timecode
 * splitter. Expected net +4 (each returns by popping only the dummy). */
#define ESP_BAL_PROBE(fn) \
    void fn##_gen(void); \
    void fn(void) { \
        uint32_t ei = esp; static int s_bad = 0, s_n = 0; \
        fn##_gen(); \
        if ((int)(esp - ei) != 4 && s_bad < 12) { s_bad++; \
             \
             } \
        else if (s_n < 3) { s_n++; \
              } \
    }
ESP_BAL_PROBE(sub_001A99B0)
ESP_BAL_PROBE(sub_001B72AE)
ESP_BAL_PROBE(sub_001BA214)
ESP_BAL_PROBE(sub_001BA0AF)
ESP_BAL_PROBE(sub_001BA0EC)
ESP_BAL_PROBE(sub_001BA00F)

/* DOA3 DIAG: sub_0017C3A0 = translate the matrix-stack top (0x00A49220) by
 * (x,y,z) = args. It is the first routine that stores NaN into the stack
 * post-movie, and its own arithmetic is right, so the NaN comes in through
 * the arguments. Log them with the native caller chain. */
void sub_0017C3A0_gen(void);
void sub_0017C3A0(void)
{
    static int s_bad = 0, s_n = 0;
    uint32_t a = MEM32(esp + 4), b = MEM32(esp + 8), c = MEM32(esp + 0xC);
    int nan = ((a & 0x7F800000u) == 0x7F800000u) || ((b & 0x7F800000u) == 0x7F800000u) || ((c & 0x7F800000u) == 0x7F800000u);
    if ((nan && s_bad < 8) || s_n < 3) { if (nan) s_bad++; else s_n++;
        void *bt[10]; USHORT nb = CaptureStackBackTrace(1, 10, bt, NULL); int k;
        float fa, fb, fc; memcpy(&fa, &a, 4); memcpy(&fb, &b, 4); memcpy(&fc, &c, 4);
          }
    sub_0017C3A0_gen();
}

/* D3DDevice_GetBackBuffer (0x001DCE10) and D3DDevice_GetDepthStencilSurface
 * (0x001DD210) must preserve esi/edi/ebx like any cdecl callee.
 *
 * sub_0017FD00 computes its slot index into esi (esi = 5*index), calls these
 * two, and only then reads the saved colour/depth surfaces at
 * [esi*8 + 0x00C58EFC] / [+0x00C58F00] to hand to SetRenderTarget. With esi
 * clobbered across the calls it read a wrong slot and passed 1 -- a refcount,
 * not a surface -- so SetViewport clamped every viewport against a 1x1
 * "surface" (the logged w=1 h=1 / w=1 h=4006) and the whole title screen
 * collapsed to nothing while the game still issued tens of thousands of
 * draws. Same failure mode as the Present/esi bug. Report any correction so
 * this is evidence, not a guess. */
#define D3D_ABI_KEEP(name)                                                   \
    void name##_gen(void);                                                   \
    void name(void) {                                                        \
        uint32_t _si = esi, _di = edi, _bx = ebx;                            \
        name##_gen();                                                        \
        if (esi != _si || edi != _di || ebx != _bx) {                        \
            static int s_n = 0;                                              \
            if (s_n < 6) { s_n++;                                            \
                                       \
                 }                                            \
            esi = _si; edi = _di; ebx = _bx;                                 \
        }                                                                    \
    }

/* Sofdec player flag setter: (player, index, value). Index 6 = audio enabled. */
void sub_001A6030_gen(void);
void sub_001A6030(void)
{
    static int n = 0;
    uint32_t pl = MEM32(esp + 4), idx = MEM32(esp + 8), val = MEM32(esp + 12);
    uint32_t s_edi = edi, s_esi = esi, s_ebx = ebx;
    if (idx == 6 && n < 20) { n++;
         }
    sub_001A6030_gen();
    edi = s_edi; esi = s_esi; ebx = s_ebx;
}
BOOT_MARK2_ABI_ESI(sub_0018B83A)

/* ── Not ported yet: inert stubs so the runtime links ──────────── */
/* doa3_netplay_force_pads: online only; the XInput pad block layout changed in XDK 4134 (0x5E5CC8 -> 0x73C6BC sits 0xC below the pads, not 8) */
void doa3_netplay_force_pads(uint32_t mask) { }
/* doa3_rebuild_button_maps: sub_000BB270: code address with no JPN counterpart */
void doa3_rebuild_button_maps(void) { }
/* doa3_pump_cri_servers: sub_00170710: code address with no JPN counterpart */
void doa3_pump_cri_servers(void) { }
