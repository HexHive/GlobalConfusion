# auto-generated TEE configuration file
# TEE version 3.16.0-181-ga9edcef3
ARCH=arm
PLATFORM=vexpress
PLATFORM_FLAVOR=qemu_armv8a
CFG_AES_GCM_TABLE_BASED=y
CFG_ARM32_ta_arm32=y
CFG_ARM64_core=y
CFG_ARM64_ldelf=y
CFG_ARM64_ta_arm64=y
CFG_ARM_GICV3=y
CFG_ATTESTATION_PTA=n
CFG_ATTESTATION_PTA_KEY_SIZE=3072
CFG_BOOT_SECONDARY_REQUEST=n
CFG_CC_OPT_LEVEL=s
CFG_COMPAT_GP10_DES=y
CFG_CORE_ARM64_PA_BITS=32
CFG_CORE_ASLR=y
CFG_CORE_ASYNC_NOTIF=n
CFG_CORE_ASYNC_NOTIF_GIC_INTID=0
CFG_CORE_BGET_BESTFIT=n
CFG_CORE_BIGNUM_MAX_BITS=4096
CFG_CORE_BTI=n
CFG_CORE_CLUSTER_SHIFT=2
CFG_CORE_DEBUG_CHECK_STACKS=n
CFG_CORE_DUMP_OOM=n
CFG_CORE_DYN_SHM=y
CFG_CORE_HAS_GENERIC_TIMER=y
CFG_CORE_HEAP_SIZE=65536
CFG_CORE_HUK_SUBKEY_COMPAT=y
CFG_CORE_HUK_SUBKEY_COMPAT_USE_OTP_DIE_ID=n
CFG_CORE_LARGE_PHYS_ADDR=n
CFG_CORE_MAX_SYSCALL_RECURSION=4
CFG_CORE_MBEDTLS_MPI=y
CFG_CORE_NEX_HEAP_SIZE=16384
CFG_CORE_PAGE_TAG_AND_IV=n
CFG_CORE_RESERVED_SHM=y
CFG_CORE_RODATA_NOEXEC=n
CFG_CORE_RWDATA_NOEXEC=y
CFG_CORE_SANITIZE_KADDRESS=n
CFG_CORE_SANITIZE_UNDEFINED=n
CFG_CORE_THREAD_SHIFT=0
CFG_CORE_TPM_EVENT_LOG=n
CFG_CORE_TZSRAM_EMUL_SIZE=458752
CFG_CORE_UNMAP_CORE_AT_EL0=y
CFG_CORE_WORKAROUND_NSITR_CACHE_PRIME=y
CFG_CORE_WORKAROUND_SPECTRE_BP=y
CFG_CORE_WORKAROUND_SPECTRE_BP_SEC=y
CFG_CRYPTO=y
CFG_CRYPTOLIB_DIR=core/lib/libtomcrypt
CFG_CRYPTOLIB_NAME=tomcrypt
CFG_CRYPTOLIB_NAME_tomcrypt=y
CFG_CRYPTO_AES=y
CFG_CRYPTO_AES_GCM_FROM_CRYPTOLIB=n
CFG_CRYPTO_CBC=y
CFG_CRYPTO_CBC_MAC=y
CFG_CRYPTO_CBC_MAC_BUNDLE_BLOCKS=64
CFG_CRYPTO_CCM=y
CFG_CRYPTO_CMAC=y
CFG_CRYPTO_CONCAT_KDF=y
CFG_CRYPTO_CTR=y
CFG_CRYPTO_CTS=y
CFG_CRYPTO_DES=y
CFG_CRYPTO_DH=y
CFG_CRYPTO_DSA=y
CFG_CRYPTO_ECB=y
CFG_CRYPTO_ECC=y
CFG_CRYPTO_GCM=y
CFG_CRYPTO_HKDF=y
CFG_CRYPTO_HMAC=y
CFG_CRYPTO_MD5=y
CFG_CRYPTO_PBKDF2=y
CFG_CRYPTO_RSA=y
CFG_CRYPTO_RSASSA_NA1=y
CFG_CRYPTO_SHA1=y
CFG_CRYPTO_SHA224=y
CFG_CRYPTO_SHA256=y
CFG_CRYPTO_SHA384=y
CFG_CRYPTO_SHA512=y
CFG_CRYPTO_SHA512_256=y
CFG_CRYPTO_SIZE_OPTIMIZATION=y
CFG_CRYPTO_SM2_DSA=y
CFG_CRYPTO_SM2_KEP=y
CFG_CRYPTO_SM2_PKE=y
CFG_CRYPTO_SM3=y
CFG_CRYPTO_SM4=y
CFG_CRYPTO_XTS=y
CFG_DEBUG_INFO=y
CFG_DEVICE_ENUM_PTA=y
CFG_DRIVERS_CLK=y
CFG_DRIVERS_CLK_DT=y
CFG_DRIVERS_CLK_EARLY_PROBE=n
CFG_DRIVERS_CLK_FIXED=y
CFG_DRIVERS_DT_RECURSIVE_PROBE=n
CFG_DRIVERS_RSTCTRL=y
CFG_DRIVERS_RTC=n
CFG_DRIVERS_TPM2=n
CFG_DRIVERS_TPM2_MMIO=n
CFG_DT=y
CFG_DTB_MAX_SIZE=0x100000
CFG_DT_DRIVER_EMBEDDED_TEST=y
CFG_EARLY_TA=y
CFG_EARLY_TA_COMPRESS=y
CFG_EMBEDDED_TS=y
CFG_EMBED_DTB=y
CFG_EMBED_DTB_SOURCE_FILE=embedded_dtb_test.dts
CFG_ENABLE_EMBEDDED_TESTS=y
CFG_ENABLE_SCTLR_RR=n
CFG_ENABLE_SCTLR_Z=n
CFG_EXTERNAL_DTB_OVERLAY=n
CFG_FTRACE_BUF_WHEN_FULL=shift
CFG_FTRACE_SUPPORT=n
CFG_FTRACE_US_MS=10000
CFG_GENERATE_DTB_OVERLAY=n
CFG_GIC=y
CFG_GP_SOCKETS=y
CFG_HWRNG_PTA=n
CFG_HWSUPP_MEM_PERM_PXN=y
CFG_HWSUPP_MEM_PERM_WXN=y
CFG_IN_TREE_EARLY_TAS=trusted_keys/f04a0fe7-1f5d-4b9b-abf7-619b85b4ce8c
CFG_KERN_LINKER_ARCH=aarch64
CFG_KERN_LINKER_FORMAT=elf64-littleaarch64
CFG_LIBUTILS_WITH_ISOC=y
CFG_LOCKDEP=n
CFG_LOCKDEP_RECORD_STACK=y
CFG_LPAE_ADDR_SPACE_BITS=32
CFG_MAP_EXT_DT_SECURE=n
CFG_MMAP_REGIONS=13
CFG_MSG_LONG_PREFIX_MASK=0x1a
CFG_NUM_THREADS=2
CFG_OPTEE_REVISION_MAJOR=3
CFG_OPTEE_REVISION_MINOR=16
CFG_OS_REV_REPORTS_GIT_SHA1=y
CFG_PAGED_USER_TA=n
CFG_PKCS11_TA_ALLOW_DIGEST_KEY=y
CFG_PKCS11_TA_AUTH_TEE_IDENTITY=y
CFG_PKCS11_TA_HEAP_SIZE=(32 * 1024)
CFG_PKCS11_TA_TOKEN_COUNT=3
CFG_PL011=y
CFG_PREALLOC_RPC_CACHE=y
CFG_REE_FS=y
CFG_REE_FS_ALLOW_RESET=n
CFG_REE_FS_TA=y
CFG_REE_FS_TA_BUFFERED=n
CFG_RESERVED_VASPACE_SIZE=(1024 * 1024 * 10)
CFG_RPMB_FS=n
CFG_RPMB_FS_CACHE_ENTRIES=0
CFG_RPMB_FS_DEBUG_DATA=n
CFG_RPMB_FS_DEV_ID=0
CFG_RPMB_FS_RD_ENTRIES=8
CFG_RPMB_RESET_FAT=n
CFG_RPMB_TESTKEY=n
CFG_RPMB_WRITE_KEY=n
CFG_RTC_PTA=n
CFG_SCMI_MSG_CLOCK=n
CFG_SCMI_MSG_DRIVERS=n
CFG_SCMI_MSG_RESET_DOMAIN=n
CFG_SCMI_MSG_SMT=n
CFG_SCMI_MSG_VOLTAGE_DOMAIN=n
CFG_SCMI_PTA=n
CFG_SCTLR_ALIGNMENT_CHECK=n
CFG_SECSTOR_TA=y
CFG_SECSTOR_TA_MGMT_PTA=y
CFG_SECURE_DATA_PATH=n
CFG_SECURE_PARTITION=n
CFG_SECURE_TIME_SOURCE_CNTPCT=y
CFG_SHMEM_SIZE=0x00200000
CFG_SHMEM_START=0x42000000
CFG_SHOW_CONF_ON_BOOT=n
CFG_SM_NO_CYCLE_COUNTING=y
CFG_STACK_THREAD_EXTRA=0
CFG_STACK_TMP_EXTRA=0
CFG_SYSCALL_FTRACE=n
CFG_SYSCALL_WRAPPERS_MCOUNT=n
CFG_SYSTEM_PTA=y
CFG_TA_ASLR=y
CFG_TA_ASLR_MAX_OFFSET_PAGES=128
CFG_TA_ASLR_MIN_OFFSET_PAGES=0
CFG_TA_BGET_TEST=y
CFG_TA_BIGNUM_MAX_BITS=2048
CFG_TA_BTI=n
CFG_TA_FLOAT_SUPPORT=y
CFG_TA_GPROF_SUPPORT=n
CFG_TA_MBEDTLS=y
CFG_TA_MBEDTLS_MPI=y
CFG_TA_MBEDTLS_SELF_TEST=y
CFG_TA_PAUTH=n
CFG_TA_STRICT_ANNOTATION_CHECKS=y
CFG_TEE_API_VERSION=GPD-1.1-dev
CFG_TEE_BENCHMARK=n
CFG_TEE_CORE_DEBUG=y
CFG_TEE_CORE_EMBED_INTERNAL_TESTS=y
CFG_TEE_CORE_LOG_LEVEL=3
CFG_TEE_CORE_MALLOC_DEBUG=n
CFG_TEE_CORE_NB_CORE=4
CFG_TEE_CORE_TA_TRACE=y
CFG_TEE_FW_IMPL_VERSION=FW_IMPL_UNDEF
CFG_TEE_FW_MANUFACTURER=FW_MAN_UNDEF
CFG_TEE_IMPL_DESCR=OPTEE
CFG_TEE_MANUFACTURER=LINARO
CFG_TEE_RAM_VA_SIZE=0x00300000
CFG_TEE_SDP_MEM_SIZE=0x00400000
CFG_TEE_TA_LOG_LEVEL=1
CFG_TEE_TA_MALLOC_DEBUG=n
CFG_TZDRAM_SIZE=0x00f00000
CFG_TZDRAM_START=0x0e100000
CFG_ULIBS_MCOUNT=n
CFG_ULIBS_SHARED=n
CFG_UNWIND=y
CFG_VIRTUALIZATION=n
CFG_WARN_DECL_AFTER_STATEMENT=y
CFG_WARN_INSECURE=y
CFG_WDT=n
CFG_WDT_SM_HANDLER=n
CFG_WITH_ARM_TRUSTED_FW=y
CFG_WITH_LPAE=y
CFG_WITH_PAGER=n
CFG_WITH_SOFTWARE_PRNG=y
CFG_WITH_STACK_CANARIES=y
CFG_WITH_STATS=y
CFG_WITH_STMM_SP=n
CFG_WITH_USER_TA=y
CFG_WITH_VFP=y
CFG_ZLIB=y
