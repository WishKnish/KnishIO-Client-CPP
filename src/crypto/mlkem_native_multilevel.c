/*
 * KnishIO multilevel compilation unit for mlkem-native (FIPS 203).
 * Compiles both ML-KEM-768 and ML-KEM-1024 into a single object file.
 */

#ifndef MLK_CONFIG_MULTILEVEL_BUILD
#define MLK_CONFIG_MULTILEVEL_BUILD
#endif

#ifndef MLK_CONFIG_NAMESPACE_PREFIX
#define MLK_CONFIG_NAMESPACE_PREFIX mlkem
#endif

#ifndef MLK_CONFIG_NO_RANDOMIZED_API
#define MLK_CONFIG_NO_RANDOMIZED_API
#endif

#ifndef MLK_CONFIG_NO_SUPERCOP
#define MLK_CONFIG_NO_SUPERCOP
#endif

/* First level (768): include shared level-independent code and preserve shared headers */
#define MLK_CONFIG_MULTILEVEL_WITH_SHARED
#define MLK_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#define MLK_CONFIG_PARAMETER_SET 768
#include "../../external/mlkem-native/mlkem/mlkem_native.c"
#undef MLK_CONFIG_PARAMETER_SET
#undef MLK_CONFIG_MULTILEVEL_WITH_SHARED

/* Second level (1024): exclude shared code and undef shared headers at end */
#define MLK_CONFIG_MULTILEVEL_NO_SHARED
#define MLK_CONFIG_PARAMETER_SET 1024
#include "../../external/mlkem-native/mlkem/mlkem_native.c"
#undef MLK_CONFIG_PARAMETER_SET
#undef MLK_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
