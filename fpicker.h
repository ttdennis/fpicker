#ifdef __linux__
    #include "frida-core-linux.h"
#else
    #include "frida-core.h"
#endif

#include <syslog.h>
#include <stdint.h>
#include <stdbool.h>
#include <semaphore.h>
#include <errno.h>
#include <dirent.h>
#include <stdio.h>
#include <sys/time.h>

// We cannot log to stdout when fuzzing with AFL, therefore we're logging to
// syslog or os_log on Apple systems.
#ifdef __APPLE__
    #include <spawn.h>
    #include <sys/shm.h>
    extern char **environ;
    // On Darwin we need LOG_NOTICE for logs to show up in Console.app
    #define SYSLOG_LEVEL LOG_NOTICE
#else
    #define SYSLOG_LEVEL LOG_INFO
#endif

#define FUZZING_PAYLOAD_SIZE 0x1000
#define COMMUNICATION_MAP_SIZE (0x1000 + 8 + 8 + 16)

#define STATE_FLAG_SENT 1
#define STATE_FLAG_EXEC_FINISHED 2

#define COVERAGE_BITMAP_SIZE 65535

#define COMMAP_SIZE 0x2000
#define SEM_NAME_PREFIX "/fpicker-sem"

#define SHM_ENV_VAR "__AFL_SHM_ID"

#define DRCOV_HEADER "DRCOV VERSION: 2\nDRCOV FLAVOR: drcov\n"
#define DRCOV_MODULE_TABLE_HEAD "Module Table: version 2, count %d\nColumns: id, base, end, entry, checksum, timestamp, path\n"

#define CUSTOM_MUTATOR_TMP_BUFSIZE 0x2000

typedef enum FUZZER_MODE {
    FUZZER_MODE_AFL,
    FUZZER_MODE_STANDALONE_ACTIVE,
    FUZZER_MODE_STANDALONE_PASSIVE
} fuzzer_mode_t;

typedef enum COVERAGE_MODE {
    COVERAGE_MODE_STALKER_SUMMARY = 0,
    COVERAGE_MODE_AFL_BITMAP
} coverage_mode_t;

typedef enum STANDALONE_MUTATOR {
    STANDALONE_MUTATOR_NULL,
    STANDALONE_MUTATOR_RAND,
    STANDALONE_MUTATOR_CUSTOM
} standalone_mutator_t;

typedef enum COMMUNICATION_MODE {
    COMMUNICATION_MODE_SEND,
    COMMUNICATION_MODE_SHM
} communication_mode_t;

typedef enum INPUT_MODE {
    INPUT_MODE_IN_PROCESS,
    INPUT_MODE_CMD
} input_mode_t;

typedef enum EXEC_MODE {
    EXEC_MODE_SPAWN,
    EXEC_MODE_ATTACH
} exec_mode_t;

typedef enum DEVICE {
    DEVICE_LOCAL,
    DEVICE_REMOTE,
    DEVICE_USB
} device_t;

typedef struct _fuzzer_config_t {

    fuzzer_mode_t fuzzer_mode;
    coverage_mode_t coverage_mode;
    standalone_mutator_t standalone_mutator;
    communication_mode_t communication_mode;
    input_mode_t input_mode;
    exec_mode_t exec_mode;
    device_t device;

    bool verbose;

    char *process_name;
    char **spawn_argv;
    int spawn_argc;

    char *command;
    char *custom_mutator_cmd;

    char *agent_path;

    uint32_t fuzzer_timeout;
    uint32_t fuzzer_sleep;

    uint64_t seed;

    char* corpus_dir;
    char* out_dir;

    bool metrics;

} fuzzer_config_t;

typedef struct _communication_map_t {

  uint64_t state_flag;
  uint64_t payload_len;
  char sem_name[16];
  char payload[];

} communication_map_t;

// Standalone mode structures (standalone mode requires more state as
// it handles all the coverage and payloads itself as opposed to AFL mode)
#define BASIC_BLOCK_MAX_COUNT 100000

typedef struct _corpus_entry_t {
    uint8_t *data;
    size_t length;
    char *name;
    uint8_t exclusion_factor;
    bool excluded;
    struct _corpus_entry_t *next;
} corpus_entry_t;

typedef struct _basic_block_t {
    uint64_t start;
    uint64_t end;
} basic_block_t;

typedef struct _coverage_t {
    basic_block_t *basic_blocks;
    size_t basic_block_count;
} coverage_t;

// this is a drcov bb entry
typedef struct _bb_entry_t {
   uint32_t start;
   uint16_t size;
   uint16_t mod_id;
} bb_entry_t;

typedef struct _module_t {
    char *name;
    uint64_t start;
    uint64_t end;
    struct _module_t *next;
} module_t;

typedef struct _fuzzer_state_t {

    fuzzer_config_t *config;

    FridaSession *session;
    FridaDevice *frida_device;
    FridaScript *script;

    pid_t target_pid;

    char *agent_code;
    char *send_buf;
    size_t req_id;

    volatile bool exec_finished;
    volatile int32_t exec_ret_status;

    char *shm_id;

    int commap_fd;
    char *commap_id;
    communication_map_t *commap;
    sem_t *iteration_sem;
    sem_t *exec_sem;

    // Standalone only fields
    corpus_entry_t *corpus;
    corpus_entry_t *last_corpus;
    size_t corpus_count;

    char *custom_mutator_buf;
    size_t custom_mutator_bufsize;

    coverage_t coverage;
    coverage_t *last_coverage;
    char *last_err;

    void *coverage_bitmap;
    char *cur_input_file;

    bool is_ready;

    module_t *modules;
    char *drcov_modules_str;
    bool skip_cov;

    uint64_t total_payload_count;
    struct timeval t_total_time;
    uint64_t mutation_time;
    uint64_t mutation_count;
    uint64_t coverage_time;
    uint64_t loop_time;

    corpus_entry_t *passive_corp;
} fuzzer_state_t;

// Common function declarations
void plog(const char *format, ...);
FridaSession *spawn_or_attach(fuzzer_state_t *fstate);
void do_exit(fuzzer_state_t *fstate);
struct timeval *_start_measure();
uint64_t _stop_measure(struct timeval *t);

// AFL Fuzzer Mode Functions
#define FORKSRV_FD 198
void run_forkserver(fuzzer_state_t *fstate);

// Standalone Mode Stuff
void run_standalone_active(fuzzer_state_t *fstate);
void run_standalone_passive(fuzzer_state_t *fstate);
module_t *stdln_parse_modules_from_json(JsonArray *arr);
coverage_t *stdln_parse_coverage_from_json(JsonArray *arr);
corpus_entry_t *stdln_parse_corpus_from_json(JsonObject *obj);

// Fuzzer communication stuff
void on_message(FridaScript *script, const gchar *message, const gchar *data, gpointer user_data);
void on_detached(FridaSession *session, FridaSessionDetachReason reason, FridaCrash *crash, gpointer user_data);
bool do_fuzz_iteration(fuzzer_state_t *fstate, uint8_t *buf, uint32_t len);
void create_communication_map(fuzzer_state_t *fstate);
void harness_prepare(fuzzer_state_t *fstate);
void _system_cmd(char *command, bool should_log);

extern bool verbose;
#define plog_debug(fmt, args...) if(verbose) plog(fmt, ##args);
