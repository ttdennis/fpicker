test-network-macos:
	xcrun -r clang test-network.c -o test-network -O0 -fno-stack-protector -framework Foundation

test-network-ios:
	xcrun -sdk iphoneos -r clang test-network.c -o test-network -fno-stack-protector -arch arm64 -framework Foundation

test-network-linux:
	$(CC) test-network.c -o test-network -fno-stack-protector
