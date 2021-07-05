# Protocol Example

This is a short example to showcase some of fpickers features. The program `protocol_example` is a
small server that accepts connections and stores them in a data structure. In the reception handler
of the process, a connection is referenced by its handle. There are different cases that cause the
connection to be disconnected. The purpose is to show a minimal example of what needs to be done to
fuzz bluetoothd on iOS

A corresponding tutorial was given at WiSec 2021. You can find the recording on [YouTube at
3:25:00](https://youtu.be/uyAPi663NP4?t=12300). I also uploaded the slides
[here](./wisec21_tutorial_frida_fuzzing.pdf). However, without audio the slides are probably not
that useful.

## Running The Example

- Install fpicker and AFL++ according to the [installation instructions](../../README.md)
- Compile the binary `gcc -o protocol_example protocol_example.c`
- Compile the fuzzer script `frida-compile test-fuzzer.js -o harness.js`
- Run the proces: `./protocol_example $PORT`
- Run the AFL++ and fpicker: `afl-fuzz -i in -o out -- fpicker --fuzzer-mode afl --communication-mode shm -e attach -p protocol_example -f ./harness.js`

If something doesn't work, add `-v` for more verbose output, but remove the flag for actual fuzzing
as it impacts the fuzzer's speed.

You will likely not encounter any crashes as the `protocol_handler` function does not do anything
with the input except for printing.


