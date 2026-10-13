/* doa3_guest.c - per-release guest addresses (see doa3_guest.h). */

#include "doa3_guest.h"
#include <stddef.h>

extern ptrdiff_t g_xbox_mem_offset;   /* xbox_memory_layout.c */

const Doa3Guest g_guest_usa = {
    "USA",
    0x001651A5u,
    0x00219640u, 0x0021964Cu,
    0x00219650u, 0x002196F4u,
    0x003C0FB8u, 0x00BF4CF0u,
    0x0090F4A8u, 0x0090F4D0u, 0x0090F4E0u, 0x0090F544u,
    0x0009D440u,
    0x0016A530u,
    0x0016A570u,
    0x001C2B08u, 0x001C3390u,
    0x1E8u, 0x820u,
    1,
    0,
    0,
};

const Doa3Guest g_guest_jpn = {
    "Japan",
    0x0018CB89u,
    0x00252060u, 0x0025206Cu,
    0x00252070u, 0x00252168u,
    0x002587E0u, 0x004D9EF0u,   /* read off _mtinitlocks 0x001BA3F8 */
    0x00A48C30u, 0x00A48C58u, 0x00A48C78u, 0x00A48CDCu,
    0x001C67C0u,
    0x001926B0u,
    0x001926F0u,
    0, 0x001EDE80u,
    0x2430u, 0x245Cu,
    0,     /* online play: not ported yet (netplay_session.c reads USA addresses) */
    /* Japan copies voice/bgm/loadfile.afs to z:\ (thread 0x001C67C0) while it
     * boots and holds the intro until the copy pauses; */
    1,
    /* XAPI's getters and SetThreadPriorityBoost return through esp-relative
     * frames in this release, so the leaked arguments shifted its stack. */
    1,
};

const Doa3Guest *g_guest = &g_guest_usa;

uint32_t doa3_guest_d3d_device(void)
{
    if (g_guest->d3d_device)
        return g_guest->d3d_device;
    return *(volatile uint32_t *)((uintptr_t)g_guest->d3d_pdevice + g_xbox_mem_offset);
}
