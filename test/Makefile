HOST_CROSS_COMPILE ?= arm-linux-gnueabihf-
ARCH ?= arm32
OUTPUT_DIR := $(CURDIR)/out

TIPI_TEST_LIST := $(subst /,,$(dir $(wildcard *-tipi/Makefile)))

compile-tipi-tests:
	@for test in $(TIPI_TEST_LIST); do \
		$(MAKE) -C $$test CROSS_COMPILE="$(HOST_CROSS_COMPILE)" ARCH="$(ARCH)" || exit -1; \
	done

clean-tipi-tests:
	@for test in $(TIPI_TEST_LIST); do \
		$(MAKE) -C $$test clean || exit -1; \
	done
