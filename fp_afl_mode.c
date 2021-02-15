#include "fpicker.h"

// Forkserver logic
// based on AFL++'s afl-proxy.c example
static bool _start_forkserver() {
    uint8_t tmp[4] = {0, 0, 0, 0};
    return write(FORKSRV_FD+1, tmp, 4) == 4;
}

static uint32_t _next_testcase(uint8_t *buf, uint32_t max_len) {
    int32_t status = 0;
    int32_t res = 1;

    // Wait for parent by reading from the pipe. Abort if read fails.
    if (read(FORKSRV_FD, &status, 4) != 4) return 0;

    // afl only writes the test case to stdout when the cmdline does not contain "@@"
    status = read(0, buf, max_len);

    // Report that we are starting the target
    if (write(FORKSRV_FD + 1, &res, 4) != 4) return 0;

    return status;
}

static bool _end_testcase(int32_t status) {
  if (write(FORKSRV_FD + 1, &status, 4) != 4) {
      plog("[!] Error writing status in _end_testcase.\n");
      return false;
  }
  return true;
}

void _forkserver_send_error() {
    // we don't really care about the actual status that much, just want to report an error
    uint32_t status = 0xffff;
    int s = write(FORKSRV_FD + 1, &status, 4);
    if (s < 0) {
        plog("[!] Error while sending error to forkserver :(\n");
    }
}

void run_forkserver(fuzzer_state_t *fstate) {
    uint32_t len;
    uint8_t buf[FUZZING_PAYLOAD_SIZE];

    if(!_start_forkserver()) {
        plog("[!] Unable to start forkserver, couldn't write to parent.\n");
        return;
    }

    struct timeval *mut_timer = _start_measure();

    plog("[*] Everything ready, starting to fuzz!\n");
    while ((len = _next_testcase(buf, sizeof(buf))) >= 0) {
        fstate->mutation_time += _stop_measure(mut_timer);

        struct timeval *iteration_timer = _start_measure();

        do_fuzz_iteration(fstate, buf, len);

        // Check if the fuzzed process is still running
        if (kill(fstate->target_pid, 0) == -1) {
            plog("[!] Target process is not there anymore. Crash?\n");
            fstate->exec_ret_status = SIGSEGV;

            if (fstate->config->exec_mode == EXEC_MODE_SPAWN) {
                spawn_or_attach(fstate);
            } else {
                _forkserver_send_error();
                do_exit(fstate);
            }
        }

        if (!_end_testcase(fstate->exec_ret_status)) {
            break;
        }

        fstate->exec_ret_status = 0;
        bzero(buf, len);

        fstate->total_payload_count++;

        if (fstate->config->metrics) {
            uint64_t itime = _stop_measure(iteration_timer);

            int mut_avg = fstate->mutation_time / fstate->total_payload_count;
            int cov_avg = fstate->coverage_time / fstate->total_payload_count;

            plog("[METRICS]: [t=%lu] [fc=%llu] [cur_loop=%d] [mut_avg=%d] [cov_avg=%d]\n", 
                time(NULL), fstate->total_payload_count, itime, mut_avg, cov_avg);
        }
        mut_timer = _start_measure();
    }

    plog("[!] Forkserver execution ended\n");
}
