#include "fpicker.h"

#include <sys/stat.h>
#include <fcntl.h>
#ifdef __APPLE__
    #include <sys/mman.h>
    #include <sys/types.h>
#else
    #include <sys/shm.h>
    #include <sys/ipc.h>
#endif

int64_t millis() {
    struct timespec now;
    timespec_get(&now, TIME_UTC);
    return ((int64_t) now.tv_sec) * 1000 + ((int64_t) now.tv_nsec) / 1000000;
}

void on_detached(FridaSession *session, FridaSessionDetachReason reason, FridaCrash *crash, gpointer user_data) {
    fuzzer_state_t *fstate = (fuzzer_state_t *)user_data;
    gchar * reason_str;

    reason_str = g_enum_to_string(FRIDA_TYPE_SESSION_DETACH_REASON, reason);
    plog("[!] Frida detachted from target, reason: %s\n", reason_str);
    g_free(reason_str);

    // TODO: not everything is a segfault!
    fstate->exec_ret_status = SIGSEGV;
    fstate->exec_finished = true;

    plog("[*] SEM_POST in on_detached %llu\n", millis());
    sem_post(fstate->iteration_sem);
}

void _signal_exec_finished_with_ret_status(fuzzer_state_t *fstate, int ret_status) {
    fstate->exec_ret_status = ret_status;
    fstate->exec_finished = true;
    if (fstate->config->communication_mode == COMMUNICATION_MODE_SHM) {
        plog("[*] SEM_POST in _signal_exec_finished_with_ret_status %llu\n", millis());
        sem_post(fstate->iteration_sem);
    }
}

void on_message(FridaScript *script, const gchar *message, const gchar *data, gpointer user_data) {
    JsonParser *parser;
    JsonObject *root;
    const gchar *type;

    fuzzer_state_t *fstate = (fuzzer_state_t*)user_data;

    parser = json_parser_new();
    json_parser_load_from_data(parser, message, -1, NULL);
    root = json_node_get_object(json_parser_get_root(parser));

    type = json_object_get_string_member(root, "type");

    if (strcmp(type, "log") == 0) {
        const gchar *log_message = json_object_get_string_member(root, "payload");
        if (fstate->config->verbose) plog("[JS]: %s\n", log_message);
    } else if(strcmp(type, "send") == 0) {
        const gchar *send_msg = json_object_get_string_member(root, "payload");

        if (fstate->config->verbose) plog("[JS]: %s\n", message);

        // This message is received whenever the target function is left and
        // Interceptor's onLeave callback is called. This signals afl-frida to
        // continue with the next iteration.
        if (send_msg != NULL && strcmp(send_msg, "INTERCEPTOR_DONE") == 0) {
            fstate->exec_finished = true;
        } else {
            // The other cases are the more complex cases where the payload is either
            // an object or an array
            JsonNode *payload_node = json_object_get_member(root, "payload");
            if (json_node_get_node_type(payload_node) == JSON_NODE_OBJECT) {
                JsonObject *payload_obj = json_object_get_object_member(root, "payload");
                if (payload_obj != NULL && json_object_has_member(payload_obj, "type")) {
                    const gchar *type = json_object_get_string_member(payload_obj, "type");
                    if (type == NULL) return;
                    // This is the message we would receive if our installed exceptionHandler would 
                    // be taken. Currently not possible until our GitHub issue is resolved/implemented (see:
                    // https://github.com/frida/frida-gum/issues/484)
                    if (strcmp(type, "crash") == 0) {
                        plog("[->] CRASH type received\n");
                        plog("[->] message: %s\n", message);
                        _signal_exec_finished_with_ret_status(fstate, SIGSEGV);
                    } else if (strcmp(type, "_fpicker_ready") == 0) {
                        fstate->modules = stdln_parse_modules_from_json(json_object_get_array_member(payload_obj, "data"));
                        fstate->is_ready = true;
                    } else if (strcmp(type, "_fpicker_coverage") == 0) {
                        if (fstate->skip_cov) {
                            fstate->skip_cov = false;
                        } else {
                            if (json_object_has_member(payload_obj, "data")) {
                                coverage_t *cov = stdln_parse_coverage_from_json(json_object_get_array_member(payload_obj, "data"));
                                fstate->last_coverage = cov;
                            } else {
                                fstate->last_coverage = NULL;
                            }
                        }

                        fstate->exec_finished = true;
                    } else if (strcmp(type, "_fpicker_passive_corp") == 0) {
                        fstate->passive_corp = stdln_parse_corpus_from_json(json_object_get_object_member(payload_obj, "data"));
                    }
                }
            } else if (json_node_get_node_type(payload_node) == JSON_NODE_ARRAY) {
                JsonArray *payload_arr = json_object_get_array_member(root, "payload");
                // We get this error message whenever an exception occurs somewhere.
                if (json_array_get_length(payload_arr) >= 3 &&
                    strcmp(json_array_get_string_element(payload_arr, 2), "error") == 0) {
                    plog("[->] error_send_message: %s\n", message);
                    _signal_exec_finished_with_ret_status(fstate, SIGSEGV);
                }
            }
        }
    }
    // These messages arrive when the agent script throws an exception.
    else if (strcmp(type, "error") == 0) {
        const gchar *error_description = json_object_get_string_member(root, "description");

        // If the description starts with the string HEAPSAN it is a heap sanitizer
        // exception in this case we indicate an error (by setting
        // exec_ret_status). However, we do not set exec_finished. Regardless
        // of the heap exception the target function will return properly. If we
        // indicate a finished execution at this point, we significantly decrease
        // stability as the coverage collected at this point might be different.
        fstate->exec_ret_status = SIGSEGV;

        if (error_description != NULL && strncmp("HEAPSAN", error_description, 7) == 0) {
            plog("[!] HEAP Exception: %s\n", error_description);
        } else {
            // Issue https://github.com/frida/frida-gum/issues/620
            // message-dispatcher.js parses unexpected string end, ignore this error
            // by setting ret_status to 0
            // TODO apply a real fix, not sure if length issue on our end or in Frida
            if (strstr(message, "unexpected end of string") != NULL) {
                plog("[!] Frida's message dispatcher got an unexpected end of string while parsing.\n");
                _signal_exec_finished_with_ret_status(fstate, 0);
            } else {
                plog("[->] error: %s\n", message);
                _signal_exec_finished_with_ret_status(fstate, SIGSEGV);
            }
        }
    } else {
        if (fstate->config->verbose) plog("[->] on_message (unknown type): %s\n", message);
    }

    g_object_unref(parser);
}

void harness_prepare(fuzzer_state_t *fstate) {
    GError *error = NULL;
    char msg_buf[0x100];
    char *comm_mode_str = "SHM";
    char *fmode_str = "AFL";
    char *imode_str = "IN_PROCESS";

    if (fstate->config->communication_mode == COMMUNICATION_MODE_SEND){
        comm_mode_str = "SEND";
    }
    if (fstate->config->fuzzer_mode == FUZZER_MODE_STANDALONE_ACTIVE ||
            fstate->config->fuzzer_mode == FUZZER_MODE_STANDALONE_PASSIVE) {
        fmode_str = "STANDALONE";
    }
    if (fstate->config->input_mode == INPUT_MODE_CMD) {
        imode_str = "CMD";
    }
    
    sprintf(msg_buf, "[\"frida:rpc\", %lu, \"call\", \"prepare\", [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%d\"]]",
            fstate->req_id, comm_mode_str, fmode_str, imode_str, fstate->shm_id, fstate->commap_id, 
            fstate->config->verbose);
    fstate->req_id++;

    if (fstate->config->verbose) plog("[*] SEND: %s\n", msg_buf);
    frida_script_post(fstate->script, msg_buf, NULL);
    if (error != NULL) {
        plog("[!] Error on setup: %s\n", error->message);
        g_error_free(error);
        do_exit(fstate);
    }

    while (!fstate->is_ready) {
        usleep(5000);
    }

    // wait until harness signals us that it's ready
    //sem_wait(fstate->comm_sem);
    plog("[*] Harness preparation done\n");
}

sem_t *_open_sem(char *type) {
    char sem_name[64];
    sem_t *ret_sem = NULL;

    bzero(sem_name, 64);

    if ((strlen(type) + sizeof(SEM_NAME_PREFIX) + 1) >= 64) {
        plog("[!] sem type might be too long for sem name (type: %s, resulting name: %s-%s)\n",
            type, SEM_NAME_PREFIX, type);
        return NULL;
    }

    snprintf(sem_name, 64, "%s-%s", SEM_NAME_PREFIX, type);

    // TODO: not sure if this is the best way to do this, but semaphores might
    // still live on in the kernel even after all programs using it have been
    // closed (at least on iOS it seems)
    sem_unlink(sem_name);
    ret_sem = sem_open(sem_name, O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO, 0);
    if (ret_sem == SEM_FAILED) {
        plog("[!] sem_open (%s) failed, errno=%s", type, strerror(errno));
        return NULL;
    }

    return ret_sem;
}

void create_communication_map(fuzzer_state_t *fstate) {
    char *shm_id = malloc(128);

    #ifdef __APPLE__
        snprintf(shm_id, 128, "/fp_comm_shm_%d_%ld", getpid(), random());

        // 0777 is a temporary workaround for iOS (with AFL running as root and the target running as the mobile user)
        int commap_fd = shm_open(shm_id, O_CREAT | O_RDWR, 0777);

        if (commap_fd == -1) {
            plog("[!] shm_open(%s) failed, unable to set up commap. (%s)\n", shm_id, strerror(errno));
            do_exit(fstate);
        }
        if (ftruncate(commap_fd, COMMAP_SIZE)) {
            plog("[!] ftruncate() failed in commap setup\n");
            do_exit(fstate);
        }
        fstate->commap = (communication_map_t *)mmap(0, COMMAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, commap_fd, 0);
        if (fstate->commap == MAP_FAILED) {
            plog("[!] mmap failed during commap setup! (%s)\n", strerror(errno));
            close(commap_fd);
            commap_fd = -1;
            shm_unlink(shm_id);
            do_exit(fstate);
        }
        fstate->commap_fd = commap_fd;
        fstate->commap_id = shm_id;

    #else
        int commap_id = shmget(IPC_PRIVATE, COMMAP_SIZE, IPC_CREAT | IPC_EXCL | 0644);
        plog("[*] Created commap = %d\n", commap_id);

        snprintf(shm_id, 128, "%d", commap_id);
        fstate->commap_id = shm_id;
        fstate->commap = shmat(commap_id, NULL, 0);
    #endif

    bzero((void *)fstate->commap, COMMAP_SIZE);

    strncpy((char *)fstate->commap->sem_name, SEM_NAME_PREFIX, 12);
    fstate->commap->sem_name[12] = 0;

    fstate->exec_sem = _open_sem("exec");
    fstate->iteration_sem = _open_sem("iter");

    if (fstate->exec_sem == NULL || fstate->iteration_sem == NULL) {
        do_exit(fstate);
    }
}

void _busy_wait_for_exec_finished(fuzzer_state_t *fstate, bool timeout) {
    uint32_t sleep_ctr = 0;

    struct timeval *cov_timer = _start_measure();

    while (!fstate->exec_finished && (sleep_ctr <= fstate->config->fuzzer_timeout || !timeout)) {
        usleep(fstate->config->fuzzer_sleep);
        sleep_ctr++;
    }

    fstate->coverage_time += _stop_measure(cov_timer);

    if (!fstate->exec_finished) { 
        plog("[!] fuzz_iteration_in_process_send exec_finished timeout\n");
    }
    fstate->exec_finished = false;
}

bool fuzz_iteration_in_process_send(fuzzer_state_t *fstate, uint8_t *buf, uint32_t len) {
    GError *error = NULL;
    bool ret = true;
    // We cannot transfer binary data using frida's send method, so the payload
    // is encoded in base64 here. The fuzzer agent script needs to decode that.
    gchar *b64_payload = g_base64_encode(buf, len);
    // Due to the base64 encoding we need to allocate more space than the actual
    // payload requires.
    size_t sendbuf_len = (FUZZING_PAYLOAD_SIZE / 3) * 4;

    if (fstate->send_buf == NULL) {
        fstate->send_buf = (char *) malloc(sendbuf_len);
    }
    snprintf(fstate->send_buf, sendbuf_len, "[\"frida:rpc\", %lu, \"call\", \"fuzz\", [\"%s\"]]", fstate->req_id, b64_payload);
    plog_debug("[*] frida post: %s\n", fstate->send_buf);
    // TODO: can we send the payload as raw buffer in the data parameter?
    frida_script_post(fstate->script, fstate->send_buf, NULL);
    if (error != NULL) {
        plog("[!] Error posting to frida script \"%s\".\n", fstate->send_buf);
        g_error_free(error);
        ret = false;
    }
    fstate->req_id++;

    // We're doing busy waiting here instead of using mutexes as the send mode
    // is often used with a remote USB device where we don't have shared mem.
    _busy_wait_for_exec_finished(fstate, true);

    return ret;
}

bool fuzz_iteration_in_process_shm(fuzzer_state_t *fstate, uint8_t *buf, uint32_t len) {
    memcpy(fstate->commap->payload, buf, len);
    fstate->commap->payload[len] = 0x00;
    fstate->commap->payload_len = len;

    // Signal the waiting frida agent to start fuzzing
    plog_debug("[2] PRE SEM_POST in fuzz_iteration_in_process_shm: %llu\n", millis());
    if (sem_post(fstate->exec_sem) == -1) {
        plog("[!] Error in shm fuzz iteration while posting to semaphore (%s)\n", strerror(errno));
        return false;
    }
    plog_debug("[*] POST SEM_POST in fuzz_iteration_in_process_shm: %llu\n", millis());

    struct timeval *cov_timer = _start_measure();

    // Wait for the agent or an error callback to unlock the semaphore again
    // (interceptor leave, or any kind of received error message will do this)
    plog_debug("[*] PRE SEM_WAIT in fuzz_iteration_in_process_shm: %llu\n", millis());
    if (sem_wait(fstate->iteration_sem) == -1) {
        plog("[!] Error in shm fuzz iteration while waiting for semaphore (%s)\n", strerror(errno));
        return false;
    }
    plog_debug("[*] POST SEM_WAIT in fuzz_iteration_in_process_shm: %llu\n", millis());

     fstate->coverage_time += _stop_measure(cov_timer);
    return true;
}

void _system_cmd(char *command, bool should_log) {
    if (should_log) plog("[*] system(\"%s\")\n", command);
    #ifdef __APPLE__
        #include "TargetConditionals.h"
        #ifdef TARGET_OS_IPHONE
            pid_t pid;
            char *argv[] = {"/bin/sh", "-c", command, NULL};

            posix_spawn(&pid, argv[0], NULL, NULL, argv, environ);
            waitpid(pid, NULL, 0);
        #endif
    #else
        int ret = system(command);
        if (ret < 0) {
            plog("[!] Error calling system(\"%s\"): %s\n", command, strerror(errno));
        }
    #endif
}

// TODO: buf and len are currently unused as the filename of the current iteration 
// is written to the command string that is passed to system()
bool fuzz_iteration_cmd_send(fuzzer_state_t *fstate, uint8_t *buf, uint32_t len) {
    char *command = fstate->config->command;

    _system_cmd(command, fstate->config->verbose);

    _busy_wait_for_exec_finished(fstate, true);

    return true;
}

bool fuzz_iteration_cmd_shm(fuzzer_state_t *fstate, uint8_t *buf, uint32_t len) {
    char *command = fstate->config->command;

    _system_cmd(command, fstate->config->verbose);

    struct timeval *cov_timer = _start_measure();

    // Wait for the agent or an error callback to unlock the semaphore again
    // (interceptor leave, or any kind of received error message will do this)
    if (sem_wait(fstate->iteration_sem) == -1) {
        plog("[!] Error in shm fuzz iteration while waiting for semaphore (%s)\n", strerror(errno));
        return false;
    }

    fstate->coverage_time += _stop_measure(cov_timer);
    return true;
}

void _wait_for_exec(fuzzer_state_t *fstate, bool timeout) {
    if (fstate->config->communication_mode == COMMUNICATION_MODE_SEND) {
        _busy_wait_for_exec_finished(fstate, false);
    }
}

bool do_fuzz_iteration(fuzzer_state_t *fstate, uint8_t *buf, uint32_t len) {
    if (fstate->config->fuzzer_mode == FUZZER_MODE_STANDALONE_PASSIVE) {
        _wait_for_exec(fstate, false);
        return true;
    }
    if (fstate->config->input_mode == INPUT_MODE_IN_PROCESS) {
        if (fstate->config->communication_mode == COMMUNICATION_MODE_SEND) {
            if (!fuzz_iteration_in_process_send(fstate, buf, len)) {
                plog("[!] do_fuzz_iteration: error in fuzz_iteration_in_process_send\n");
                return false;
            }
        } else { // COMMUNICATION_MODE_SHM
            if (!fuzz_iteration_in_process_shm(fstate, buf, len)) {
                plog("[!] do_fuzz_iteration: error in fuzz_iteration_in_process_shm\n");
                return false;
            }
        }
    } else { // INPUT_MODE_CMD
        if (fstate->config->communication_mode == COMMUNICATION_MODE_SEND) {
            if (!fuzz_iteration_cmd_send(fstate, buf, len)) {
                plog("[!] do_fuzz_iteration: error in fuzz_iteration_cmd_send\n");
                return false;
            }
        } else {
            if (!fuzz_iteration_cmd_shm(fstate, buf, len)) {
                plog("[!] do_fuzz_iteration: error in fuzz_iteration_cmd_shm\n");
                return false;
            }
        }
    }

    return false;
}
