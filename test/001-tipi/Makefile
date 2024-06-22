CFG_TEE_TA_LOG_LEVEL ?= 4
ARCH ?= arm32
CROSS_COMPILE ?= arm-linux-gnueabihf-

# The UUID for the Trusted Application
BINARY=001cafee-2450-11e4-abe2-0002a5d5c51b

TA_DEV_KIT_DIR=$(shell pwd)/../ta-compiler/arm/export-ta_$(ARCH)

-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk), )
clean:
	@echo 'Note: $$(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk not found, cannot clean TA'
	@echo 'Note: TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)'
endif
