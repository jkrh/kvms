#define MAX_GUESTS		8
#define GUEST_MEM_MAX		0x100000000
#define STATIC_TTBL_NUM		256
#define MAX_PAGING_BLOCKS	4096
#define KVM_GUEST_SUPPORT	1
#undef				HOSTBLINDING
#undef				TEE_IF
#define PLATFORM_MBEDTLS_CONFIG "nxp_mbedtls_config.h"
