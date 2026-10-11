#define RECOMP_GENERATED_CODE
#include "recomp_funcs.h"
#include <stdio.h>
#include <math.h>

/* Direct lookup for the initializer tables.
 *
 * Deliberately local rather than added to recomp_dispatch.c: that table is
 * binary-searched with a curated size, and editing it would change which
 * indirect-call targets resolve across the whole game. These entries are only
 * ever needed by the _initterm walk in main.c. */
typedef void (*doa3_ctor_fn)(void);   /* matches recomp_func_t */
static const struct { uint32_t va; doa3_ctor_fn fn; } g_doa3_ctors[] = {
    { 0x00192687u, sub_00192687 },
    { 0x0019515Fu, sub_0019515F },
    { 0x00198000u, sub_00198000 },
    { 0x001985A0u, sub_001985A0 },
    { 0x001985D0u, sub_001985D0 },
    { 0x001986E0u, sub_001986E0 },
    { 0x001986F0u, sub_001986F0 },
    { 0x00198700u, sub_00198700 },
    { 0x00198710u, sub_00198710 },
    { 0x00198730u, sub_00198730 },
    { 0x00199710u, sub_00199710 },
    { 0x0019ABE0u, sub_0019ABE0 },
    { 0x0019AC50u, sub_0019AC50 },
    { 0x0019C1C0u, sub_0019C1C0 },
    { 0x0019D1F0u, sub_0019D1F0 },
    { 0x0019EB70u, sub_0019EB70 },
    { 0x0019EC10u, sub_0019EC10 },
    { 0x001A0180u, sub_001A0180 },
    { 0x001A3BC0u, sub_001A3BC0 },
    { 0x001A7390u, sub_001A7390 },
    { 0x001A73B0u, sub_001A73B0 },
    { 0x001A7950u, sub_001A7950 },
    { 0x001A7B70u, sub_001A7B70 },
    { 0x001A7EF0u, sub_001A7EF0 },
    { 0x001A7F90u, sub_001A7F90 },
    { 0x001A9D30u, sub_001A9D30 },
    { 0x001AB820u, sub_001AB820 },
    { 0x001AB840u, sub_001AB840 },
    { 0x001AF280u, sub_001AF280 },
    { 0x001AFA60u, sub_001AFA60 },
    { 0x001AFA80u, sub_001AFA80 },
    { 0x001AFA90u, sub_001AFA90 },
    { 0x001AFAD0u, sub_001AFAD0 },
    { 0x001AFB20u, sub_001AFB20 },
    { 0x001AFB40u, sub_001AFB40 },
    { 0x001AFB70u, sub_001AFB70 },
    { 0x001AFB90u, sub_001AFB90 },
    { 0x001AFD00u, sub_001AFD00 },
    { 0x001B0D60u, sub_001B0D60 },
    { 0x001B0D80u, sub_001B0D80 },
    { 0x001B22B0u, sub_001B22B0 },
};

doa3_ctor_fn doa3_crt_lookup(uint32_t va)
{
    size_t i;
    for (i = 0; i < sizeof(g_doa3_ctors) / sizeof(g_doa3_ctors[0]); i++)
        if (g_doa3_ctors[i].va == va)
            return g_doa3_ctors[i].fn;
    return 0;
}
