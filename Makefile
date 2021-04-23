FRAMEWORKS_MACOS = -framework Foundation -framework CoreGraphics -framework AppKit
FRAMEWORKS_iOS = -framework Foundation -framework CoreGraphics -framework UIKit

CC_MACOS = xcrun -r clang
CC_iOS = xcrun -sdk iphoneos -r clang

fpicker-macos:
	$(CC_MACOS) -fPIC $(FRAMEWORKS_MACOS) -ffunction-sections -fdata-sections -Wall -Os -pipe -g3 fpicker.c fp_communication.c fp_standalone_mode.c fp_afl_mode.c -o fpicker -L. -lfrida-core-macos -ldl -lbsm -lm -lresolv -pthread

fpicker-linux:
	$(CC) -fPIC -m64 -ffunction-sections -fdata-sections -Wall -Wno-format -Os -pipe -g3 fpicker.c fp_communication.c fp_standalone_mode.c fp_afl_mode.c -o fpicker -L. -lfrida-core-linux -ldl -lm -lresolv -lrt -Wl,--export-dynamic -Wl,--gc-sections,-z,noexecstack -pthread

fpicker-ios:
	$(CC_iOS) -fPIC $(FRAMEWORKS_iOS) -ffunction-sections -fdata-sections -Wall -Os -pipe -g3 fpicker.c fp_communication.c fp_standalone_mode.c fp_afl_mode.c -o fpicker -L. -arch arm64 -lfrida-core-ios -ldl -lm -lresolv -pthread

