test-macos:
	xcrun -r clang test.c -o test -O0 -fno-stack-protector -framework Foundation

test-ios:
	xcrun -sdk iphoneos -r clang test.c -o test -fno-stack-protector -arch arm64 -framework Foundation

test-linux:
	$(CC) test.c -o test -fno-stack-protector
