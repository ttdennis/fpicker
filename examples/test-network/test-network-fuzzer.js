// Import the fuzzer base class
const Fuzzer = require("../../harness/fuzzer.js");

// The custom fuzzer needs to subclass the Fuzzer class to work properly
class TestFuzzer extends Fuzzer.Fuzzer {
    constructor() {
        // The constructor needs to specify the address of the targeted function and a NativeFunction
        // object that can later be called by the fuzzer.

        // Usually you would use:
        //      const proc_fn_addr = Module.getExportByName(null, "proc_fn");
        // However, there are cases where the symbol is not an export. We can still find it by enumerating
        // all symbols and filtering for the one we're looking for.
        const proc_fn_addr = Module.enumerateSymbolsSync("test-network").filter(function(o) {return o.name == "proc_fn";})[0].address;
        const proc_fn = new NativeFunction(
            proc_fn_addr,
            "void", ["pointer", "int64"], {
        });

        // The constructor needs:
        //      - the module name
        //      - the address of the targeted function
        //      - the NativeFunction object of the targeted function
        super("test-network", proc_fn_addr, proc_fn);
    }

    // The pepare function is called once the script is loaded into the target process in case any
    // preparation or state setup is required. In this case, no preparation is needed (see the bluetoothd
    // example for a preparation function that does something)
    prepare() {
    }

    // this callback is called when the target function is called, it can be used to extract the
    // payload and send it back to the fuzzer in passive mode
    passiveCallback(args) {
        const len = args[1];
        const data = new Uint8Array(Memory.readByteArray(args[0], parseInt(len)));

        // this encodes the data and sends it back to the fuzzer
        this.sendPassiveCorpus(data, len);
    }

    // This function is called by the fuzzer with the first argument being a pointer into memory
    // where the payload is stored and the second the length of the input.
    fuzz(payload, len) {
        this.target_function(payload, parseInt(len));
    }

}

const f = new TestFuzzer();
exports.fuzzer = f;
