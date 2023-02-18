#include "fpicker.h"
#include "frida-core.h"

#include <stdbool.h>
#include <stdarg.h>
#include <getopt.h>

// Global variable indicating whether we want to log to stdout or to syslog.
// Logging to syslog is usually required when using fpicker in AFL mode as stdout
// is consumed by AFL.
bool log_to_syslog = false;

struct timeval *_start_measure() {
    struct timeval *t = malloc(sizeof(struct timeval));
    gettimeofday(t, NULL);
    return t;
}

uint64_t _stop_measure(struct timeval *t) {
    struct timeval now, res;
    gettimeofday(&now, NULL);
    timersub(&now, t, &res);
    free(t);
    return res.tv_usec;
}

void do_exit(fuzzer_state_t *fstate) {
    if (fstate != NULL) {
        if (fstate->script != NULL) {
            frida_script_unload_sync(fstate->script, NULL, NULL);
            frida_unref(fstate->script);
        }
        if (fstate->session) {
            frida_session_detach_sync(fstate->session, NULL, NULL);
            frida_unref(fstate->session);
        }
        if (fstate->frida_device) {
            frida_unref(fstate->frida_device);
        }
        free(fstate->config);
        free(fstate);
    }
    exit(0);
}

// Either log to stdout or to syslog depending on whether we are run in AFL or standalone mode
void plog(const char *format, ...) {
    va_list args;
    va_start(args, format);

    if (log_to_syslog) {
        vsyslog(SYSLOG_LEVEL, format, args);
    } else {
        vprintf(format, args);
    }

    va_end(args);
}

void load_agent_script(fuzzer_state_t *fstate, char *filename) {
    size_t agent_code_len;
    size_t name_len;
    int r;
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        plog("[!] Unable to open agent script file %s. Error: %s\n", filename, strerror(errno));
        do_exit(fstate);
    }

    name_len = strlen(filename) + 1;
    fstate->config->agent_path = malloc(name_len);
    strncpy(fstate->config->agent_path, filename, name_len);

    fseek(fp, 0, SEEK_END);
    agent_code_len = ftell(fp);

    fstate->agent_code = malloc(agent_code_len);
    rewind(fp);
    r = fread(fstate->agent_code, 1, agent_code_len, fp);
    if (r < 0) {
        plog("[!] Error reading agent code: %s\n", strerror(errno));
        do_exit(fstate);
    }

    fclose(fp);
}

bool dir_exists(char *path) {
    DIR* dir = opendir(path);
    if (dir) {
        closedir(dir);
        return true;
    } else {
        return false;
    }
}

// Check if the parsed config is valid. Some modes and configs cannot be combined.
bool check_config(fuzzer_config_t *config) {
    if (config->fuzzer_mode == FUZZER_MODE_STANDALONE_PASSIVE) {
        if (config->communication_mode == COMMUNICATION_MODE_SHM) {
            plog("[!] SHM communication mode not supported in passive mode\n");
            return false;
        }
        if (config->corpus_dir != NULL) {
            plog("[!] Input/corpus directory not required in passive mode, collected "
                 "corpora will be stored in the output directory\n");
            return false;
        }
    }
    if (config->fuzzer_mode == FUZZER_MODE_STANDALONE_ACTIVE) {
        // in active standalone, corpus and out dir are strictly necessary
        if (config->out_dir == NULL) {
            plog("[!] No out-dir specified!\n");
            return false;
        }
        if (config->corpus_dir == NULL) {
            plog("[!] No corpus-dir specified!\n");
            return false;
        }
        if (!dir_exists(config->out_dir)) {
            plog("[!] Cannot open out-dir (%s), does it exist?\n", config->out_dir);
            return false;
        }
        if (!dir_exists(config->corpus_dir)) {
            plog("[!] Cannot open corpus-dir (%s), does it exist?\n", config->corpus_dir);
            return false;
        }
    }
    if (config->coverage_mode == COVERAGE_MODE_AFL_BITMAP) {
        plog("[!] The coverage mode AFL_bitmap is currently not implemented in standalone mode.\n");
        return false;
    }
    if (config->device == DEVICE_USB) {
        if (config->communication_mode == COMMUNICATION_MODE_SHM) {
            plog("[!] Shared memory communication mode not possible with USB device.\n");
            return false;
        }
        if (config->fuzzer_mode == FUZZER_MODE_AFL) {
            plog("[!] Fuzzer mode AFL not possible with USB device.\n");
            return false;
        }
    } else if (config->device == DEVICE_REMOTE) {
        if (config->communication_mode == COMMUNICATION_MODE_SHM) {
            plog("[!] Shared memory communication mode not possible with remote device.\n");
            return false;
        }
        if (config->fuzzer_mode == FUZZER_MODE_AFL) {
            plog("[!] Fuzzer mode AFL not possible with remote device.\n");
            return false;
        }
    }
    if (config->standalone_mutator == STANDALONE_MUTATOR_CUSTOM && config->custom_mutator_cmd == NULL) {
        plog("[!] Mutator mode set to CMD but no command supplied (--mutator-command)\n");
        return false;
    }
    return true;
}

void print_config(fuzzer_config_t *config) {
    char *fuzzer_mode_string;
    char *fuzzer_device_string;

    plog("Running fpicker using the following configuration:\n");

    if (config->fuzzer_mode == FUZZER_MODE_AFL) {
        fuzzer_mode_string = "FUZZER_MODE_AFL";
    } else if (config->fuzzer_mode == FUZZER_MODE_STANDALONE_ACTIVE) {
        fuzzer_mode_string = "FUZZER_MODE_STANDALONE_ACTIVE";
    } else {
        fuzzer_mode_string = "FUZZER_MODE_STANDALONE_PASSIVE";
    }

    if (config->device == DEVICE_LOCAL) {
        fuzzer_device_string = "DEVICE_LOCAL";
    } else if (config->device == DEVICE_USB) {
        fuzzer_device_string = "DEVICE_USB";
    } else {
        fuzzer_device_string = "DEVICE_REMOTE";
    }
    plog("- fuzzer-mode: \t\t\t%s\n", fuzzer_mode_string);
    plog("- coverage_mode: \t\t%s\n", config->coverage_mode == COVERAGE_MODE_AFL_BITMAP ? "COVERAGE_MODE_AFL_BITMAP" : "COVERAGE_MODE_STALKER_SUMMARY");
    plog("- standalone_mutator: \t\t%s\n", config->standalone_mutator == STANDALONE_MUTATOR_NULL ? "STANDALONE_MUTATOR_NULL" :
        config->standalone_mutator == STANDALONE_MUTATOR_RAND ? "STANDALONE_MUTATOR_RAND" : "STANDALONE_MUTATOR_CMD");
    plog("- communication_mode: \t\t%s\n", config->communication_mode == COMMUNICATION_MODE_SEND ? "COMMUNICATION_MODE_SEND" : "COMMUNICATION_MODE_SHM");
    plog("- input_mode: \t\t\t%s\n", config->input_mode == INPUT_MODE_CMD ? "INPUT_MODE_CMD" : "INPUT_MODE_IN_PROCESS");
    plog("- exec_mode: \t\t\t%s\n", config->exec_mode == EXEC_MODE_SPAWN ? "EXEC_MODE_SPAWN" : "EXEC_MODE_ATTACH");
    plog("- device_type: \t\t\t%s\n", fuzzer_device_string);
    plog("- process_name: \t\t%s\n", config->process_name);
    plog("- command: \t\t\t%s\n", config->command);
    plog("- fuzzer_timeout: \t\t%d\n", config->fuzzer_timeout);
    plog("- fuzzer_sleep: \t\t%d\n", config->fuzzer_sleep);
    plog("- verbose: \t\t\t%s\n", config->verbose ? "true": "false");
    plog("- agent_script: \t\t%s\n", config->agent_path);
    plog("- corpus_dir: \t\t\t%s\n", config->corpus_dir);
    plog("- out_dir: \t\t\t%s\n", config->out_dir);
    plog("- metrics: %s\n", config->metrics ? "enabled" : "disabled");
    plog("\n");
}

fuzzer_state_t *parse_args(int argc, char **argv) {
    fuzzer_state_t *fstate = (fuzzer_state_t *) malloc(sizeof(fuzzer_state_t));
    fuzzer_config_t *config = (fuzzer_config_t *) malloc(sizeof(fuzzer_config_t));

    pid_t _pid;
    size_t arg_len = 0;

    int opt = 0;
    int arg_idx = 0;

    bzero(config, sizeof(fuzzer_config_t));
    bzero(fstate, sizeof(fuzzer_state_t));

    fstate->config = config;
    static struct option long_opts[] = {
        {"fuzzer-mode", required_argument, 0, 'm'},
        {"coverage-mode", required_argument, 0, 'r'},
        {"standalone-mutator", required_argument, 0, 'U'},
        {"communication-mode", required_argument, 0, 'u'},
        {"input-mode", required_argument, 0, 'I'},
        {"exec-mode", required_argument, 0, 'e'},
        {"device", required_argument, 0, 'D'},
        {"process", required_argument, 0, 'p'},
        {"agent-script", required_argument, 0, 'f'},
        {"command", required_argument, 0, 'c'},
        {"mutator-command", required_argument, 0, 'C'},
        {"timeout", required_argument, 0, 't'},
        {"sleep-time", required_argument, 0, 's'},
        {"seed", required_argument, 0, 'x'},
        {"corpus-dir", required_argument, 0, 'i'},
        {"out-dir", required_argument, 0, 'o'},
        {"metrics", required_argument, 0, 'M'},
        {"verbose", required_argument, 0, 'v'},
        {0, 0, 0, 0}
    };

    // default timeout and sleep values
    config->fuzzer_timeout = 500;
    config->fuzzer_sleep = 100;
    config->metrics = false;

    while ((opt = getopt_long(argc, argv, "m:r:U:u:a.e:D:p:f:c:C:t:s:x:i:o:Mv", long_opts, &arg_idx)) != -1) {
        switch(opt) {
            case 'm':
                if (strncmp("afl", optarg, 3) == 0) {
                    config->fuzzer_mode = FUZZER_MODE_AFL;
                } else if (strncmp("active", optarg, 6) == 0) {
                    config->metrics = true;
                    config->fuzzer_mode = FUZZER_MODE_STANDALONE_ACTIVE;
                } else if (strncmp("passive", optarg, 7) == 0) {
                    config->metrics = true;
                    config->fuzzer_mode = FUZZER_MODE_STANDALONE_PASSIVE;
                } else {
                    plog("[!] Unknown fuzzer mode: %s\n", optarg);
                    do_exit(fstate);
                }
                break;
            case 'r':
                if (strncmp("bitmap", optarg, 6) == 0) {
                    config->coverage_mode = COVERAGE_MODE_AFL_BITMAP;
                } else if (strncmp("stalker_summary", optarg, 15) == 0) {
                    config->coverage_mode = COVERAGE_MODE_STALKER_SUMMARY;
                } else {
                    plog("Unknown coverage mode: %s\n", optarg);
                    do_exit(fstate);
                }
                break;
            case 'U':
                if (strncmp("null", optarg, 3) == 0) {
                    config->standalone_mutator = STANDALONE_MUTATOR_NULL;
                } else if (strncmp("rand", optarg, 4) == 0) {
                    config->standalone_mutator = STANDALONE_MUTATOR_RAND;
                } else if (strncmp("cmd", optarg, 3) == 0) {
                    config->standalone_mutator = STANDALONE_MUTATOR_CUSTOM;
                } else {
                    plog("Unknown standalone mutator: %s\n", optarg);
                    do_exit(fstate);
                }
                break;
            case 'u':
                if (strncmp("send", optarg, 4) == 0) {
                    config->communication_mode = COMMUNICATION_MODE_SEND;
                } else if (strncmp("shm", optarg, 3) == 0) {
                    config->communication_mode = COMMUNICATION_MODE_SHM;
                } else {
                    plog("Unknown communication mode: %s\n", optarg);
                    do_exit(fstate);
                }
                break;
            case 'I':
                if (strncmp("in-process", optarg, 10) == 0) {
                    config->input_mode = INPUT_MODE_IN_PROCESS;
                } else if (strncmp("cmd", optarg, 3) == 0) {
                    config->input_mode = INPUT_MODE_CMD;
                } else {
                    plog("Unknown command mode: %s\n", optarg);
                    do_exit(fstate);
                }
                break;
            case 'e':
                if (strncmp("spawn", optarg, 5) == 0) {
                    config->exec_mode = EXEC_MODE_SPAWN;
                } else if (strncmp("attach", optarg, 6) == 0) {
                    config->exec_mode = EXEC_MODE_ATTACH;
                } else {
                    plog("Unknown exec mode: %s\n", optarg);
                    do_exit(fstate);
                }
                break;
            case 'D':
                if (strncmp("local", optarg, 5) == 0) {
                    config->device = DEVICE_LOCAL;
                } else if (strncmp("usb", optarg, 3) == 0) {
                    config->device = DEVICE_USB;
                } else if (strncmp("remote", optarg, 6) == 0) {
                    config->device = DEVICE_REMOTE;
                } else {
                    plog("Unknown device type: %s\n", optarg);
                    do_exit(fstate);
                }
                break;
            case 'p':
                // try to parse the process as PID first, otherwise it's the process name as string
                _pid = atoi(optarg);
                if (_pid > 0) {
                    fstate->target_pid = _pid;
                } else {
                    size_t name_len = strlen(optarg) + 1;
                    config->process_name = malloc(name_len);
                    strncpy(config->process_name, optarg, name_len);
                }
                break;
            case 'f':
                load_agent_script(fstate, optarg);
                break;
            case 'c':
                arg_len = strlen(optarg) + 1;
                config->command = malloc(arg_len);
                strncpy(config->command, optarg, arg_len);
                break;
            case 'C':
                arg_len = strlen(optarg) + 1;
                config->custom_mutator_cmd = malloc(arg_len);
                strncpy(config->custom_mutator_cmd, optarg, arg_len);
                break;
            case 't':
                config->fuzzer_timeout  = atoi(optarg);
                if (config->fuzzer_timeout <= 0) {
                    plog("[!] Invalid fuzzer timeout value %s\n", optarg);
                    do_exit(fstate);
                }
                break;
            case 's':
                config->fuzzer_sleep = atoi(optarg);
                if (config->fuzzer_sleep <= 0) {
                    plog("[!] Invalid fuzzer sleep value %s\n", optarg);
                    do_exit(fstate);
                }
                break;
            case 'x':
                config->seed = atoi(optarg);
                if (config->seed <= 0) {
                    plog("[!] Invalid seed value %s\n", optarg);
                    do_exit(fstate);
                }
                break;
            case 'i':
                arg_len = strlen(optarg) + 1;
                config->corpus_dir = malloc(arg_len);
                strncpy(config->corpus_dir, optarg, arg_len);
                break;
            case 'o':
                arg_len = strlen(optarg) + 1;
                config->out_dir = malloc(arg_len);
                strncpy(config->out_dir, optarg, arg_len);
                break;
            case 'M': config->metrics = true; break;
            case 'v': config->verbose = true; verbose = true; break;
            default: break;
        }
    }

    if (!check_config(config)) {
        free(config);
        free(fstate);
        do_exit(NULL);
    }

    print_config(config);

    return fstate;
}

FridaSession *spawn_or_attach(fuzzer_state_t *fstate) {
    fuzzer_config_t *config = fstate->config;

    FridaSession *session;
    GError *error = NULL;
    pid_t target_pid = 0;
    FridaDevice *device = fstate->frida_device;

    if (config->exec_mode == EXEC_MODE_SPAWN) {
        plog("[*] Trying to spawn %s on device %s\n", config->process_name, frida_device_get_name(device));

        FridaSpawnOptions *spawn_options = frida_spawn_options_new();
        if (config->spawn_argc > 1) {
            frida_spawn_options_set_argv(spawn_options, config->spawn_argv, config->spawn_argc);
        }

        target_pid = frida_device_spawn_sync(device, config->process_name, spawn_options, NULL, &error);
        g_object_unref(spawn_options);
        if (error) {
            plog("[!] Failed to spawn %s\n", config->process_name);
            return NULL;
        }

        plog("[*] Spawned %s with PID %d\n", config->process_name, target_pid);
    } else {
        if (config->process_name != NULL) {
            plog("[*] Trying to attach to process with name %s.\n", config->process_name);
            // This loop is mainly for afl-cmin as the attached binary often seems to
            // crash when afl-showmap is run. When it's a daemon like bluetoothd, it
            // will take a while to restart so we just wait here.
            for (int retry = 0; retry <= 5 && target_pid == 0; retry++) {
                // FIXME if the frida port for remote device is not forwarded, this just segfaults
                FridaProcessList *proc_list = frida_device_enumerate_processes_sync(device, NULL, NULL, &error);
                for (int i = 0; i < frida_process_list_size(proc_list) && target_pid == 0; i++) {
                    FridaProcess *proc = frida_process_list_get(proc_list, i);
                    if (strncmp(frida_process_get_name(proc), config->process_name, strlen(config->process_name)) == 0) {
                        target_pid = frida_process_get_pid(proc);
                        plog("[*] Found process %s with PID %d\n", config->process_name, target_pid);
                    }
                }
                if (target_pid == 0) {
                    plog("[!] Unable to find %s PID, retrying.\n", config->process_name);
                    sleep(1);
                }
            }
        } else {
            target_pid = fstate->target_pid;
        }

        if (target_pid == 0) {
            plog("[!] Unable to find process %s to attach to (after 5 retries)\n", config->process_name);
            return NULL;
        }

        fstate->target_pid = target_pid;
    }

    // once we can use the newer Frida versions, the device_attach_sync call needs to look like this:
    session = frida_device_attach_sync(device, target_pid, FRIDA_REALM_NATIVE, NULL, &error);
    if (error != NULL) {
        plog("[!] Failed to attach to process %s on frida device %s (%s)\n", config->process_name, frida_device_get_name(device), error->message);
        g_error_free(error);
        return NULL;
    }

    if (config->process_name == NULL && config->device == DEVICE_REMOTE) {
        plog("[!] Process name is null! Try using process name instead of PID on remote devices.\n");
        plog("[!] Use 'frida-ps -R' to get a list of process names from the remote device.\n");
    }

    plog("[*] Attached to process %s on frida device %s\n", config->process_name, frida_device_get_name(device));

    return session;
}

bool inject_frida_script(fuzzer_state_t *fstate) {
    GError *error = NULL;
    FridaScriptOptions *options = frida_script_options_new();
    frida_script_options_set_name(options, "harness");
    frida_script_options_set_runtime(options, FRIDA_SCRIPT_RUNTIME_QJS);

    if (fstate->agent_code == NULL) {
        plog("[!] Cannot create frida session, no agent code given\n");
        do_exit(fstate);
    }

    fstate->script = frida_session_create_script_sync(fstate->session, fstate->agent_code, options, NULL, &error);
    if (error != NULL) {
        plog("[!] Unable to create agent script: %s\n", error->message);
        return false;
    }

    plog("[*] Agent script created\n");

    // set up message handler callback to receive messages from frida agent
    g_signal_connect(fstate->script, "message", G_CALLBACK(on_message), (gpointer)fstate);
    // set up the detach handler callback to react to frida detach
    g_signal_connect(fstate->session, "detached", G_CALLBACK (on_detached), (gpointer)fstate);

    frida_script_load_sync(fstate->script, NULL, &error);
    if (error != NULL) {
        plog("[!] Error loading agent script: %s\n", error->message);
        do_exit(fstate);
    }

    plog("[*] Agent script loaded\n");

    sleep(1);
    plog("[*] Slept a bit to give the agent script some time.\n");

    return true;
}

void print_banner() {
    plog("       __       _      _                     \n"
         "      / _|     (_)    | |                    \n"
         "     | |_ _ __  _  ___| | _____ _ __         \n"
         "     |  _| '_ \\| |/ __| |/ / _ \\ '__|      \n"
         "     | | | |_) | | (__|   <  __/ |           \n"
         "     |_| | .__/|_|\\___|_|\\_\\___|_|        \n"
         "         | |                                 \n"
         "         |_|        Frida-Based Fuzzing Suite\n"
         "- - - - - - - - - - - - - - - - - - - - - - -\n\n");
}

int main(int argc, char **argv) {
    FridaDeviceManager *manager = NULL;
    FridaDeviceList *devices = NULL;
    FridaDevice *device = NULL;
    FridaSession *session;

    GError *error = NULL;
    gint num_devices = 0;

    // If the AFL env var is defined, we're probably running in AFL so all output goes
    // to syslog, regardless of whether the user specified AFL mode or not
    if (getenv(SHM_ENV_VAR)) {
        log_to_syslog = true;
    }

    print_banner();

    fuzzer_state_t *fstate = parse_args(argc, argv);
    if (fstate->config->fuzzer_mode == FUZZER_MODE_AFL) {
        fstate->shm_id = getenv(SHM_ENV_VAR);
        // if SHM_ENV_VAR does not exist we're not running in AFL (or there's some other problem)
        if (!fstate->shm_id) {
            plog("[!] " SHM_ENV_VAR " not defined!\n");
            return 1;
        }
        plog("[*] SHM_ENV_VAR = %s\n", fstate->shm_id);
    }

    if (fstate->config->communication_mode == COMMUNICATION_MODE_SHM) {
        create_communication_map(fstate);
    }

    // The args after ours' are the target proces's
    fstate->config->spawn_argc = argc - (optind - 1);
    fstate->config->spawn_argv = argv + (optind - 1);

    frida_init();

    manager = frida_device_manager_new();
    devices = frida_device_manager_enumerate_devices_sync(manager, NULL, &error);
    if (error != NULL) {
        plog("[!] Unable to enumerate Frida devices.\n");
        do_exit(fstate);
    }

    num_devices = frida_device_list_size(devices);
    if (num_devices == 0) {
        plog("[!] Couldn't find any Frida devices.\n");
        do_exit(fstate);
    } else {
        plog("[*] Found %d Frida devices.\n", num_devices);
    }

    FridaDeviceType desired_type = FRIDA_DEVICE_TYPE_LOCAL;
    if (fstate->config->device == DEVICE_USB) {
        desired_type = FRIDA_DEVICE_TYPE_USB;
    } else if (fstate->config->device == DEVICE_REMOTE) {
        desired_type = FRIDA_DEVICE_TYPE_REMOTE;
        plog("[*] Set remote device. Ensure the port 27042 is forwarded!\n"); // FIXME warning as long as this doesn't work
    }
    for (int i = 0; i < num_devices && device == NULL; i++) {
        FridaDevice *dev = frida_device_list_get(devices, i);
        FridaDeviceType t = frida_device_get_dtype(dev);

        if (t == desired_type) {
            plog("[*] Found desired Frida device: %s(%d)\n", frida_device_get_name(dev), (int) t);
            device = g_object_ref(dev);
        }

        g_object_unref(dev);
    }

    if (device == NULL) {
        plog("[!] Unable to find desired Frida device\n");
        do_exit(fstate);
    }

    fstate->frida_device = device;

    frida_unref(devices);

    session = spawn_or_attach(fstate);
    if (session == NULL) {
        plog("[!] Error in spawning or attaching to process\n");
        do_exit(fstate);
    }
    fstate->session = session;

    if(!inject_frida_script(fstate)) {
        plog("[!] Error injecting Frida agent script\n");
        do_exit(fstate);
    }

    harness_prepare(fstate);

    if (fstate->config->fuzzer_mode == FUZZER_MODE_AFL) {
        // Get into an infinite loop simulating AFL's forkserver
        run_forkserver(fstate);
    } else if (fstate->config->fuzzer_mode == FUZZER_MODE_STANDALONE_ACTIVE) {
        run_standalone_active(fstate);
    } else {
        run_standalone_passive(fstate);
    }

    frida_unref(device);
    frida_device_manager_close_sync(manager, NULL, &error);
    frida_unref(manager);

    do_exit(fstate);
}
