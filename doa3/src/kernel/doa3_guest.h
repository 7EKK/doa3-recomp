/* doa3_guest.h - guest addresses the runtime itself relies on, per release.
 * The recompiled code carries its own addresses; */

#ifndef DOA3_GUEST_H
#define DOA3_GUEST_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Doa3Guest {
    const char *release;
    uint32_t entry_point;           /* XBE entry */
    uint32_t crt_xi_a, crt_xi_z;    /* C initializers (_initterm) */
    uint32_t crt_xc_a, crt_xc_z;    /* C++ constructors */
    uint32_t crt_lock_table;        /* _mtinitlocks: {CRITICAL_SECTION*, flag} x 36 */
    uint32_t crt_lock_cs;           /* ... and the CS buffer it hands out (stride 0x1C) */
    /* Video state the game caches from XC_VIDEO (video_settings.c). */
    uint32_t video_pp_width;        /* D3DPRESENT_PARAMETERS.BackBufferWidth */
    uint32_t video_pp_flags;        /* D3DPRESENT_PARAMETERS.Flags */
    uint32_t video_flags;           /* raw XGetVideoFlags result */
    uint32_t video_widescreen;      /* the game's widescreen flag (bit 0) */
    uint32_t install_thread;        /* asset install worker routine */
    uint32_t cri_watchdog_thread;   /* CRI watchdog: a pure yield loop */
    uint32_t cri_vsync_thread;      /* ADX vsync server */
    /* D3D device: a fixed address, or (0) read from the device pointer
     * global once CreateDevice has run. */
    uint32_t d3d_device;
    uint32_t d3d_pdevice;
    uint32_t d3d_vblank_event_off;  /* KEVENT the vblank interrupt signals */
    uint32_t d3d_vblank_count_off;  /* vblank counter the frame pacing reads */
    int online_play;                /* netplay ported to this release */
    int cache_on_disc;              /* z:\ is the installed disc folder */
    int ord_args_fixed;             /* kernel ordinals 24/144 pop their real stdcall args */
} Doa3Guest;

extern const Doa3Guest g_guest_usa;
extern const Doa3Guest g_guest_jpn;
extern const Doa3Guest *g_guest;    /* the running release (default USA) */

/* The D3D device's guest VA, or 0 before it exists. */
uint32_t doa3_guest_d3d_device(void);

#ifdef __cplusplus
}
#endif

#endif /* DOA3_GUEST_H */
