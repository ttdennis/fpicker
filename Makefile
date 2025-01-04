.PHONY: setup-devkit clean fpicker-macos fpicker-linux fpicker-ios

OS ?= unknown
ARCH ?= $(shell uname -m)
CC ?= clang
FRAMEWORKS =
CFLAGS = -fPIC -ffunction-sections -fdata-sections -Wall -Os -pipe -g3
LDFLAGS = -L. -lfrida-core -ldl -lm -lresolv -pthread

ifeq ($(MAKECMDGOALS), fpicker-macos)
  OS = macos
  CC = xcrun -r clang
  FRAMEWORKS = -framework Foundation -framework CoreGraphics -framework AppKit -framework IOKit -framework Security
  LDFLAGS += -lbsm
endif

ifeq ($(MAKECMDGOALS), fpicker-linux)
  OS = linux
  LDFLAGS += -lrt -Wl,--export-dynamic -Wl,--gc-sections,-z,noexecstack
endif

ifeq ($(MAKECMDGOALS), fpicker-ios)
  OS = ios
  ARCH = arm64
  CC = xcrun -sdk iphoneos -r clang
  FRAMEWORKS = -framework Foundation -framework CoreGraphics -framework UIKit -framework IOKit -framework Security
  LDFLAGS += -arch $(ARCH)
endif

FRIDA_VERSION = 16.5.9
BASE_URL = https://github.com/frida/frida/releases/download/$(FRIDA_VERSION)
DEVKIT_FILENAME = frida-core-devkit-$(FRIDA_VERSION)-$(OS)-$(ARCH).tar.xz
DEVKIT_URL = $(BASE_URL)/$(DEVKIT_FILENAME)
DEVKIT_DIR = frida-devkit-$(OS)-$(ARCH)

$(DEVKIT_FILENAME):
	@echo "Checking for devkit tarball..."
	@if [ ! -f $@ ]; then \
		echo "Downloading $(DEVKIT_FILENAME)..."; \
		wget -q $(DEVKIT_URL) -O $@ || curl -L -o $@ $(DEVKIT_URL); \
		if [ $$? -ne 0 ]; then \
			echo "Error downloading $(DEVKIT_FILENAME)"; exit 1; \
		fi; \
		if [ $$(stat -c%s $@) -lt 1000 ]; then \
			echo "Error: Downloaded file $(DEVKIT_FILENAME) is too small. Ensure your system is supported by Frida."; \
			rm -f $@; exit 1; \
		fi; \
	else \
		echo "$(DEVKIT_FILENAME) already exists, skipping download."; \
	fi

$(DEVKIT_DIR): $(DEVKIT_FILENAME)
	@echo "Checking for extracted devkit..."
	@if [ ! -d $@ ]; then \
		echo "Extracting $(DEVKIT_FILENAME) into $(DEVKIT_DIR)..."; \
		mkdir -p $@; \
		tar Jxvf $< -C $@; \
		if [ $$? -ne 0 ]; then \
			echo "Error extracting $(DEVKIT_FILENAME)"; exit 1; \
		fi; \
	else \
		echo "$(DEVKIT_DIR) already exists, skipping extraction."; \
	fi

setup-devkit: $(DEVKIT_DIR)
	@echo "Setting up devkit..."
	cp $(DEVKIT_DIR)/libfrida-core.a libfrida-core.a
	cp $(DEVKIT_DIR)/frida-core.h frida-core.h

fpicker-macos fpicker-linux fpicker-ios: setup-devkit
	@echo "Building for $(OS)..."
	$(CC) $(CFLAGS) $(FRAMEWORKS) fpicker.c fp_communication.c fp_standalone_mode.c fp_afl_mode.c -o fpicker $(LDFLAGS)

clean:
	@echo "Cleaning up..."
	rm -rf fpicker fpicker.dSYM frida-devkit-* frida-core-devkit-*.tar.xz libfrida-core.a frida-core.h
