ifeq ($(MAKECMDGOALS), fpicker-macos)
  OS = macos
  ARCH ?= $(shell uname -m)
  CC = xcrun -r clang
  FRAMEWORKS = -framework Foundation -framework CoreGraphics -framework AppKit -framework IOKit -framework Security
endif

ifeq ($(MAKECMDGOALS), fpicker-linux)
  OS = linux
  ARCH ?= $(shell uname -m)
endif

ifeq ($(MAKECMDGOALS), fpicker-ios)
  OS = ios
  ARCH ?= arm64
  CC = xcrun -sdk iphoneos -r clang
  FRAMEWORKS = -framework Foundation -framework CoreGraphics -framework UIKit -framework IOKit -framework Security
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
	else \
		echo "$(DEVKIT_FILENAME) already exists, skipping download."; \
	fi

$(DEVKIT_DIR): $(DEVKIT_FILENAME)
	@echo "Checking for extracted devkit..."
	@if [ ! -d $@ ]; then \
		echo "Extracting $(DEVKIT_FILENAME) into $(DEVKIT_DIR)..."; \
		mkdir -p $@; \
		tar Jxvf $< -C $@; \
	else \
		echo "$(DEVKIT_DIR) already exists, skipping extraction."; \
	fi

setup-devkit: $(DEVKIT_DIR)
	cp $(DEVKIT_DIR)/libfrida-core.a libfrida-core.a
	cp $(DEVKIT_DIR)/frida-core.h frida-core.h

fpicker-macos: setup-devkit
	$(CC) -fPIC $(FRAMEWORKS) -ffunction-sections -fdata-sections -Wall -Os -pipe -g3 fpicker.c fp_communication.c fp_standalone_mode.c fp_afl_mode.c -o fpicker -L. -lfrida-core -ldl -lbsm -lm -lresolv -pthread

fpicker-linux: setup-devkit
	$(CC) -fPIC -m64 -ffunction-sections -fdata-sections -Wall -Wno-format -Os -pipe -g3 fpicker.c fp_communication.c fp_standalone_mode.c fp_afl_mode.c -o fpicker -L. -lfrida-core -ldl -lm -lresolv -lrt -Wl,--export-dynamic -Wl,--gc-sections,-z,noexecstack -pthread

fpicker-ios: setup-devkit
	$(CC) -fPIC $(FRAMEWORKS) -ffunction-sections -fdata-sections -Wall -Os -pipe -g3 fpicker.c fp_communication.c fp_standalone_mode.c fp_afl_mode.c -o fpicker -L. -arch $(ARCH) -lfrida-core -ldl -lm -lresolv -pthread

clean:
	rm -rf fpicker fpicker.dSYM frida-devkit-* frida-core-devkit-*.tar.xz libfrida-core.a frida-core.h fpicker-macos fpicker-linux fpicker-ios
