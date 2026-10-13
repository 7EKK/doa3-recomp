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
    { 0x001BB70Au, sub_001BB70A },
    { 0x001BD480u, sub_001BD480 },
    { 0x001DDD90u, sub_001DDD90 },
    { 0x001F708Au, sub_001F708A },
    { 0x001F7095u, sub_001F7095 },
    { 0x001DC2D0u, sub_001DC2D0 },
    { 0x001DC2B0u, sub_001DC2B0 },
    { 0x001DBDC0u, sub_001DBDC0 },
    { 0x001DBDE0u, sub_001DBDE0 },
    { 0x001DBC90u, sub_001DBC90 },
    { 0x001DBCA0u, sub_001DBCA0 },
    { 0x001DBCE0u, sub_001DBCE0 },
    { 0x001DBD30u, sub_001DBD30 },
    { 0x001DBD50u, sub_001DBD50 },
    { 0x001D9200u, sub_001D9200 },
    { 0x001DB490u, sub_001DB490 },
    { 0x001DBC70u, sub_001DBC70 },
    { 0x001D79D0u, sub_001D79D0 },
    { 0x001D7A30u, sub_001D7A30 },
    { 0x001D8B70u, sub_001D8B70 },
    { 0x001D91E0u, sub_001D91E0 },
    { 0x001D6E80u, sub_001D6E80 },
    { 0x001D7420u, sub_001D7420 },
    { 0x001D7530u, sub_001D7530 },
    { 0x001D7650u, sub_001D7650 },
    { 0x001D1180u, sub_001D1180 },
    { 0x001D3410u, sub_001D3410 },
    { 0x001D6E60u, sub_001D6E60 },
    { 0x001CE000u, sub_001CE000 },
    { 0x001CE9A0u, sub_001CE9A0 },
    { 0x001D03D0u, sub_001D03D0 },
    { 0x001D0470u, sub_001D0470 },
    { 0x001CB390u, sub_001CB390 },
    { 0x001CBD10u, sub_001CBD10 },
    { 0x001CD280u, sub_001CD280 },
    { 0x001CD2F0u, sub_001CD2F0 },
    { 0x001CB360u, sub_001CB360 },
    { 0x001CB340u, sub_001CB340 },
    { 0x001CB350u, sub_001CB350 },
    { 0x001CB270u, sub_001CB270 },
    { 0x001CABD0u, sub_001CABD0 },
    { 0x001CAC30u, sub_001CAC30 },
    { 0x001CACA0u, sub_001CACA0 },
    { 0x001CAD00u, sub_001CAD00 },
    { 0x001CAD40u, sub_001CAD40 },
    { 0x001CADA0u, sub_001CADA0 },
    { 0x001CADE0u, sub_001CADE0 },
    { 0x001CAE50u, sub_001CAE50 },
    { 0x001CAEB0u, sub_001CAEB0 },
    { 0x001CAF10u, sub_001CAF10 },
    { 0x001CAF50u, sub_001CAF50 },
    { 0x001CAFC0u, sub_001CAFC0 },
    { 0x001CB000u, sub_001CB000 },
    { 0x001CB090u, sub_001CB090 },
    { 0x001CB110u, sub_001CB110 },
    { 0x001CB1B0u, sub_001CB1B0 },
    { 0x001CB210u, sub_001CB210 },
    { 0x001CABC0u, sub_001CABC0 },
    { 0x001CABA0u, sub_001CABA0 },
    { 0x001CAA20u, sub_001CAA20 },
    { 0x001CAA10u, sub_001CAA10 },
    { 0x001CA9E0u, sub_001CA9E0 },
    { 0x001CA690u, sub_001CA690 },
};

doa3_ctor_fn doa3_crt_lookup(uint32_t va)
{
    size_t i;
    for (i = 0; i < sizeof(g_doa3_ctors) / sizeof(g_doa3_ctors[0]); i++)
        if (g_doa3_ctors[i].va == va)
            return g_doa3_ctors[i].fn;
    return 0;
}
