#include "fpicker.h"

#include <dirent.h>
#include <sys/wait.h>

void stdln_init(fuzzer_state_t *fstate) {
    if (fstate->config->fuzzer_mode == FUZZER_MODE_STANDALONE_PASSIVE) {
        // in passive mode we will store collected corpora in the out dir
        fstate->config->corpus_dir = fstate->config->out_dir;
    }

    if (fstate->config->coverage_mode == COVERAGE_MODE_STALKER_SUMMARY) {
        fstate->coverage.basic_blocks = (basic_block_t *) malloc(BASIC_BLOCK_MAX_COUNT * sizeof(basic_block_t));
        fstate->coverage.basic_block_count = 0;
    } else {
        fstate->coverage_bitmap = malloc(COVERAGE_BITMAP_SIZE);
        plog("[!] Standalone passive in coverage mode AFL bitmap not implemented yet.\n");
        do_exit(fstate);
    }
    
    fstate->corpus_count = 0;
    fstate->last_err = NULL;

    if (fstate->config->standalone_mutator == STANDALONE_MUTATOR_CUSTOM) {
        // initialize the custom mutation tmp buffer
        fstate->custom_mutator_bufsize = CUSTOM_MUTATOR_TMP_BUFSIZE;
        fstate->custom_mutator_buf = malloc(fstate->custom_mutator_bufsize);
        bzero(fstate->custom_mutator_buf, fstate->custom_mutator_bufsize);
    }
}

coverage_t *stdln_parse_coverage_from_json(JsonArray *arr) {
    guint len = json_array_get_length(arr);

    coverage_t *cov = malloc(sizeof(coverage_t));
    cov->basic_block_count = len;

    basic_block_t *blocks = malloc(sizeof(basic_block_t) * len);
    for (int i = 0; i < len; i++) {
        JsonArray *entry = json_array_get_array_element(arr, i);
        blocks[i].start = strtol(json_array_get_string_element(entry, 0), NULL, 0);
        blocks[i].end= strtol(json_array_get_string_element(entry, 1), NULL, 0);
    }
   
    cov->basic_blocks = blocks;
    return cov;
}

corpus_entry_t *stdln_parse_corpus_from_json(JsonObject *obj) {
    corpus_entry_t *corp = NULL;
    gsize b64_len = 0;
    const char *data = NULL;
    char *data_dec = NULL;
    
    data = json_object_get_string_member(obj, "data");
    if (data == NULL) {
        return corp;
    }

    corp = malloc(sizeof(corpus_entry_t));
    data_dec = (char *)g_base64_decode(data, &b64_len);

    corp->data = malloc(b64_len + 1);
    bzero(corp->data, b64_len + 1);
    memcpy(corp->data, data_dec, b64_len);

    corp->length = b64_len;

    corp->name = malloc(64);
    bzero(corp->name, 64);
    snprintf(corp->name, 64, "passive-%ld", time(NULL));

    g_free(data_dec);

    return corp;
}

module_t *stdln_parse_modules_from_json(JsonArray *arr) {
    guint len = json_array_get_length(arr);

    // TODO: for now we only consider the first module (the fuzzed binary itself)
    // in the future we might want to let the user specify which modules should
    // be considered, e.g. by providing a list as parameter
    len = 1;

    module_t *last_mod = NULL;
    module_t *first_mod = NULL;
    for (int i = 0; i < len; i++) {
        JsonObject *obj = json_array_get_object_element(arr, i);
        module_t *mod = malloc(sizeof(module_t));

        const char *name = json_object_get_string_member(obj, "path");
        const char *start = json_object_get_string_member(obj, "base");
        const char *end = json_object_get_string_member(obj, "end");
        size_t len = strlen(name) + 1;
        
        mod->name = malloc(len);
        strncpy(mod->name, name, len);
        mod->name[len-1] = 0;

        plog("[*] MODULE=%s, start=%s, end=%s\n", name, start, end);
        
        mod->start = strtol(start, NULL, 0);
        mod->end = strtol(end, NULL, 0);
        mod->next = NULL;

        if (last_mod == NULL) {
            first_mod = mod;
            last_mod = mod;
        } else {
            last_mod->next = mod;
            last_mod = last_mod->next;
        }
    }

    return first_mod;
}

void free_corpus(corpus_entry_t *corp) {
    if (corp == NULL) return;
    free(corp->data);
    free(corp->name);
    free(corp);
}

void free_cov(coverage_t *cov) {
    if (cov == NULL) return;
    free(cov->basic_blocks);
    free(cov);
}

void stdln_add_corpus_entry(fuzzer_state_t *fstate, uint8_t *content, long fsize, char *name) {
    corpus_entry_t *corp = malloc(sizeof(corpus_entry_t));
    corp->data = malloc(fsize);
    memcpy(corp->data, content, fsize);

    size_t name_len = strlen(name) + 1;
    corp->name = malloc(name_len);
    bzero(corp->name, name_len);
    strncpy(corp->name, name, name_len - 1);

    corp->next = NULL;
    corp->length = fsize;
    corp->exclusion_factor= 0;
    corp->excluded = false;

    // if the corpus is empty, this is the first one
    if(fstate->corpus == NULL) {
        fstate->corpus = corp;
    }

    if (fstate->last_corpus != NULL) {
        fstate->last_corpus->next = corp;
        fstate->last_corpus = corp;
    } else {
        fstate->last_corpus = corp;
    }

    fstate->corpus_count++;
}

void stdln_load_corpus(fuzzer_state_t *fstate) {
    struct dirent *dir = NULL;
    DIR *corpus_dir = opendir(fstate->config->corpus_dir);
    if (!corpus_dir) {
        plog("[!] Error. Cannot open corpus directory at %s\n", fstate->config->corpus_dir);
        do_exit(fstate);
    }

    // Add each file in the corpus directory to corpus list
    while ((dir = readdir(corpus_dir)) != NULL) {
        if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0 || strcmp(dir->d_name, ".cur_input") == 0) {
            continue;
        }

        if (fstate->config->verbose) {
            plog("[*] Found corpus file %s\n", dir->d_name);
        }

        char filename[0x200];
        snprintf(filename, 0x200, "%s/%s", fstate->config->corpus_dir, dir->d_name);
        FILE *f = fopen(filename, "rb");
        if (f == NULL) {
            plog("[!] Error opening corpus file %s\n", filename);
            continue;
        }

        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        rewind(f);

        uint8_t *content = malloc(fsize);
        size_t len = fread(content, 1, fsize, f);
        if (len < 0) {
            plog("[!] Error reading from corpus file %s (%s)\n", filename, strerror(errno));
            continue;
        }
        fclose(f);

        stdln_add_corpus_entry(fstate, content, fsize, dir->d_name);
    }

    closedir(corpus_dir);
}

void stdln_store_crash(fuzzer_state_t *fstate, corpus_entry_t *corp) {
    char filename[0x200];

    if (corp == NULL) {
        return;
    }

    sprintf(filename, "%s/crash-%s", fstate->config->out_dir, corp->name);
    FILE *f = fopen(filename, "wb");
    if (f == NULL) {
        plog("[!] Error opening crash file %s (%s)\n", filename, strerror(errno));
    }

    // TODO: store error message
    // TODO: store coverage if possible
    fwrite("Payload:\n", strlen("Payload:\n"), 1, f);
    fwrite(corp->data, corp->length, 1, f);

    fclose(f);
}

coverage_t *stdln_wait_for_coverage(fuzzer_state_t *fstate, corpus_entry_t *corp) {
    coverage_t *retcov = NULL;

    // when our target crashes we (currently) do not get coverage information but
    // we can store information related to the crash
    if (fstate->exec_ret_status != 0) {
        // TODO: filter crashing inputs
        stdln_store_crash(fstate, corp);
        fstate->exec_ret_status = 0;
    } else {
        if (fstate->config->communication_mode == COMMUNICATION_MODE_SHM) {
            JsonParser *parser = json_parser_new();
            JsonNode *root = NULL;
            JsonArray *ar = NULL;

            // in the SHM case the coverage JSON string is supplied in the SHM
            // position where the payload was before
            char *json_string = fstate->commap->payload;
            json_parser_load_from_data(parser, json_string, fstate->commap->payload_len, NULL);
            root = json_parser_get_root(parser);
            if (root == NULL) {
                return (coverage_t *) NULL;
            }

            ar = json_node_get_array(json_parser_get_root(parser));
            if (ar == NULL) {
                return (coverage_t *) NULL;
            }

            retcov = stdln_parse_coverage_from_json(ar);
            g_object_unref(parser);
        } else {
            retcov = fstate->last_coverage;
            fstate->last_coverage = NULL;
        }
    }

    return retcov;
}

coverage_t *stdln_fuzz_payload(fuzzer_state_t *fstate, corpus_entry_t *corp) {
    if (fstate->config->input_mode == INPUT_MODE_CMD) {
        FILE *f = fopen(fstate->cur_input_file, "wb");
        fwrite(corp->data, corp->length, 1, f);
        fclose(f);
    }
    do_fuzz_iteration(fstate, corp->data, corp->length);
    return stdln_wait_for_coverage(fstate, corp);
}

coverage_t *stdln_passive_fuzz(fuzzer_state_t *fstate, corpus_entry_t **retcorp) {
    // it's fine if passive_corp is NULL, stdln_wait_for_coverage can handle that
    corpus_entry_t *corp = NULL;
    do_fuzz_iteration(fstate, NULL, 0);
    corp = fstate->passive_corp;
    *retcorp = corp;
    fstate->passive_corp = NULL;
    return stdln_wait_for_coverage(fstate, corp);
}

bool stdln_is_bb_in_fuzzer_coverage(fuzzer_state_t *fstate, basic_block_t *bb) {
    for (int i = 0; i < fstate->coverage.basic_block_count; i++) {
        basic_block_t *cur_bb = &fstate->coverage.basic_blocks[i];
        if (bb->start == cur_bb->start && bb->end == cur_bb->end) {
            return true;
        }
    }
    return false;
}

bool stdln_is_bb_in_module(fuzzer_state_t *fstate, basic_block_t *bb) {
    module_t *cur_mod = fstate->modules;
    while (cur_mod != NULL) {
        if (bb->start >= cur_mod->start && bb->end <= cur_mod->end) {
            return true;
        }
        cur_mod = cur_mod->next;
    }
    return false;
}

void stdln_add_coverage_to_state(fuzzer_state_t *fstate, coverage_t *cov) {
    // if our coverage is still empty, just add all
    if (fstate->coverage.basic_block_count == 0) {
        for (int i = 0; i < cov->basic_block_count; i++) {
            fstate->coverage.basic_blocks[fstate->coverage.basic_block_count].start =
                cov->basic_blocks[i].start;
            fstate->coverage.basic_blocks[fstate->coverage.basic_block_count].end =
                cov->basic_blocks[i].end;

            fstate->coverage.basic_block_count++;
        }
        return;
    }

    // for each entry in this coverage we check if it is not yet in the fuzzer's 
    // accumulated coverage, TODO: make this more clever/better performing if required
    for (int i = 0; i < cov->basic_block_count; i++) {
        if (!stdln_is_bb_in_module(fstate, &cov->basic_blocks[i]) || stdln_is_bb_in_fuzzer_coverage(fstate, &cov->basic_blocks[i])) {
        } else {
            fstate->coverage.basic_blocks[fstate->coverage.basic_block_count].start =
                cov->basic_blocks[i].start;
            fstate->coverage.basic_blocks[fstate->coverage.basic_block_count].end =
                cov->basic_blocks[i].end;

            fstate->coverage.basic_block_count++;
        }
    }
}

void stdln_write_coverage_to_disk(fuzzer_state_t *fstate, char *name, coverage_t *cov) {
    // implemented as documented by https://www.ayrx.me/drcov-file-format
    size_t filename_len = strlen(fstate->config->out_dir) + strlen(name) + 32;
    char *cov_filename = malloc(filename_len);
    bzero(cov_filename, filename_len);
    snprintf(cov_filename, filename_len, "%s/cov-%s-%ld", fstate->config->out_dir, name, time(NULL));

    char row[256];
    FILE *f = fopen(cov_filename, "wb");
    fwrite(DRCOV_HEADER, strlen(DRCOV_HEADER), 1, f);

    // we only prepare the drcov module list once and save it for later
    if (fstate->drcov_modules_str == NULL) {
        uint32_t module_count = 0;
        module_t *m = fstate->modules;
        while (m != NULL) {
            module_count++;
            m = m->next;
        }
        // allocate 256 bytes per row (+ header) in the module table, should be 
        // enough even for the long module names that Apple sometimes has...
        fstate->drcov_modules_str = malloc(256 * (module_count + 1));
        bzero(fstate->drcov_modules_str, 256 * module_count);

        // write module table header
        snprintf(fstate->drcov_modules_str, 256, DRCOV_MODULE_TABLE_HEAD, module_count);

        // assemble drcov module list entries and leave entry, checksum and timestamp empty
        m = fstate->modules;
        uint32_t idx = 0;
        while(m != NULL) {
            bzero(row, 256);
            snprintf(row, 256, "%d, 0x%llx, 0x%llx, 0x0000000000000000, 0x00000000, 0x00000000, %s\n", idx, m->start, m->end, m->name);
            strncat(fstate->drcov_modules_str, row, 256);
            m = m->next;
        }
    }

    fwrite(fstate->drcov_modules_str, strlen(fstate->drcov_modules_str), 1, f);

    bzero(row, 256);
    snprintf(row, 256, "BB Table: %zu bbs\n", cov->basic_block_count);
    fwrite(row, strlen(row), 1, f);

    // convert our internal bb coverage representation to drcov format
    for (int i = 0; i < cov->basic_block_count; i++) {
        basic_block_t cur_bb = cov->basic_blocks[i];
        bb_entry_t bb;

        // check which module the BB belongs to
        uint32_t module_id = 0;
        bool found_module = false;
        module_t *m = fstate->modules;
        while (m != NULL) {
            if (cur_bb.start >= m->start && cur_bb.end <= m->end) {
                found_module = true;
                break;
            }
            module_id++;

            m = m->next;
        }

        // leave out BBs that do not belog to any of the known modules
        if (!found_module) {
            continue;
        }

        bb.start = (uint32_t) cur_bb.start - m->start;
        bb.size = (uint16_t) (cur_bb.end- cur_bb.start);
        bb.mod_id = module_id;

        fwrite((void *)&bb, sizeof(bb), 1, f);
    }
    
    if (fstate->config->verbose) {
        plog("[*] Wrote coverage to %s\n", cov_filename);
    }
    free(cov_filename);
    fclose(f);
}

void stdln_get_corpus_coverage(fuzzer_state_t *fstate) {
    corpus_entry_t *corp = fstate->corpus;

    // iterate over each file in corpus collection and store the resulting coverage
    while(corp != NULL) {
        plog("[*] Getting corpus coverage (%s)\n", corp->name);

        // TODO: maybe repeat this to catch coverage differents between runs for the
        // same input and notify the user about instability
        coverage_t *cur_cov = stdln_fuzz_payload(fstate, corp);
        // TODO: handle coverage_bitmap case 
        if (cur_cov == NULL) {
            plog("[!] Error getting coverage for payload %s (probably due to crash)\n", corp->name);
        } else if ((void *)cur_cov == (void *)0x01) {
            plog("[!] RETRYING getting coverage for payload %s\n", corp->name);
        } else {
            // add the newly gathered coverage to the fuzzing state's coverage collection
            stdln_add_coverage_to_state(fstate, cur_cov);

            // store coverage information on disk as DRCOV file
            stdln_write_coverage_to_disk(fstate, corp->name, cur_cov);
        }

        corp = corp->next;
    }

    plog("[*] Using %lu input files covering a total of %lu basic blocks\n", 
            fstate->corpus_count, fstate->coverage.basic_block_count);
}

size_t _mutate_custom_cmd(char *cmd, corpus_entry_t *in, char *out, size_t outsize) {
    size_t len = 0;

    int in_pipe[2];
    int out_pipe[2];

    int s = pipe(in_pipe);
    if (s < 0) {
        plog("[!] Error creating in_pipe in %s (%s)\n", __func__, strerror(errno));
        return len;
    }
    s = pipe(out_pipe);
    if (s < 0) {
        plog("[!] Error creating out_pipe in %s (%s)\n", __func__, strerror(errno));
        return len;
    }

    pid_t p = fork();
    if (p < 0) {
        plog("[!] Unable to fork in %s. Error: %s\n", __func__, strerror(errno));
        return len;
    }

    if (p == 0) {
        close(in_pipe[1]);
        dup2(in_pipe[0], 0);
        close(out_pipe[0]);
        dup2(out_pipe[1], 1);

        execl("/bin/sh", "sh", "-c", cmd, NULL);
        exit(1);
    }

    close(in_pipe[0]);
    close(out_pipe[1]);

    // write cmd to child process
    len = write(in_pipe[1], in->data, in->length);
    if (write < 0) {
        plog("[!] Unable to write to child process in %s (%s)\n", __func__, strerror(errno));
        return len;
    }
    close(in_pipe[1]);

    // read output
    len = read(out_pipe[0], out, outsize);
    close(out_pipe[0]);

    // kill child
    kill(p, SIGKILL);
    waitpid(0, NULL, WNOHANG);

    return len;
}

corpus_entry_t *stdln_mutate_corpus_entry(fuzzer_state_t *fstate, corpus_entry_t *incorp, uint64_t seed) {
    corpus_entry_t *newcorp = malloc(sizeof(corpus_entry_t));
    newcorp->length = incorp->length;

    if (fstate->config->standalone_mutator == STANDALONE_MUTATOR_RAND) {
        newcorp->data = malloc(newcorp->length);
        memcpy(newcorp->data, incorp->data, newcorp->length);

        int count = rand() % 12;
        for (int i = 0; i < count; i++) {
            uint64_t pos = rand() % newcorp->length;
            uint8_t val = rand() % 0xff; 

            if (pos < newcorp->length)
                newcorp->data[pos] = val;
            else
                plog("[*] Mutation weirdness: pos: %llu, newcorp->lengh: %zu\n", pos, newcorp->length);
        }

        size_t namelen = strlen(incorp->name) + 32;
        newcorp->name = malloc(namelen);
        bzero(newcorp->name, namelen);
        sprintf(newcorp->name, "%s_%llu-%d", incorp->name, seed, count);

    } else if (fstate->config->standalone_mutator == STANDALONE_MUTATOR_CUSTOM) {
        size_t payload_len = _mutate_custom_cmd(fstate->config->custom_mutator_cmd, incorp,
                                                fstate->custom_mutator_buf, fstate->custom_mutator_bufsize);
                                                
        newcorp->data = malloc(payload_len);
        bzero(newcorp->data, payload_len);
        newcorp->length = payload_len;
        memcpy(newcorp->data, fstate->custom_mutator_buf, payload_len);
        bzero(fstate->custom_mutator_buf, fstate->custom_mutator_bufsize);


        size_t namelen = 128;
        newcorp->name = malloc(namelen);
        bzero(newcorp->name, namelen);
        sprintf(newcorp->name, "%llu_%ld", seed, time(NULL));

    } else { // STANDALONE_MUTATOR_NULL
        newcorp->length = incorp->length;
        newcorp->data = malloc(newcorp->length);
        memcpy(newcorp->data, incorp->data, newcorp->length);

        size_t namelen = strlen(incorp->name) + 1;
        newcorp->name = malloc(namelen);
        strncpy(newcorp->name, incorp->name, namelen);
    }

    return newcorp;
}

void stdln_add_entry_to_corpus(fuzzer_state_t *fstate, corpus_entry_t *newcorp) {
    char filename[0x200];

    snprintf(filename, 0x200, "%s/%s", fstate->config->corpus_dir, newcorp->name);

    FILE *f = fopen(filename, "wb");
    fwrite(newcorp->data, 1, newcorp->length, f);
    fclose(f);

    plog("[*] Added new file %s to corpus\n", newcorp->name);

    stdln_add_corpus_entry(fstate, newcorp->data, newcorp->length, newcorp->name);
}

bool stdln_is_coverage_new(fuzzer_state_t *fstate, coverage_t *cov) {
    // right now we just run over our complete coverage and as soon as we see that the
    // new coverage contains a start-end combination that we don't know yet we consider this
    // a new coverage
    for(int i = 0; i < cov->basic_block_count; i++) {
         if (!stdln_is_bb_in_module(fstate, &cov->basic_blocks[i])) {
             continue;
         }
        
        bool did_find_bb_in_state = false;
        for(int j = 0; j < fstate->coverage.basic_block_count; j++) {
            if ((cov->basic_blocks[i].start == fstate->coverage.basic_blocks[j].start) &&
                    (cov->basic_blocks[i].end == fstate->coverage.basic_blocks[j].end)) {
                did_find_bb_in_state = true;
            }
        }
        if (!did_find_bb_in_state) {
            return true;
        }
    }

    return false;
}

void stdln_fuzz_loop(fuzzer_state_t *fstate) {

    gettimeofday(&fstate->t_total_time, NULL);
    while(true) {
        uint64_t seed = fstate->config->seed;
        srand(seed);
        corpus_entry_t *corp = fstate->corpus;

        size_t payload_count = 0;
        struct timeval *cur_loop_timer = _start_measure();

        while (corp != NULL) {
            struct timeval *mut_timer = _start_measure();
            corpus_entry_t *mutated_payload = stdln_mutate_corpus_entry(fstate, corp, seed);
            fstate->mutation_time += _stop_measure(mut_timer);
            fstate->mutation_count++;

            coverage_t *cur_cov = stdln_fuzz_payload(fstate, mutated_payload);
            if (cur_cov == NULL) {
                plog("[!] Error getting coverage for mutated corpus %s\n", corp->name);
            } else {
                // check if this is new coverage we didn't see before
                if (stdln_is_coverage_new(fstate, cur_cov)) {
                    plog("[!] New coverage found, nice!\n");
                    // add the new coverage to the fuzzing state's coverage collection
                    stdln_add_coverage_to_state(fstate, cur_cov);
                    // store the coverage information on disk as DRCOV file
                    stdln_write_coverage_to_disk(fstate, corp->name, cur_cov);
                    // add the mutated file to corpus
                    stdln_add_entry_to_corpus(fstate, mutated_payload);
                }
            }

            free_corpus(mutated_payload);
            free_cov(cur_cov);

            corp = corp->next;

            payload_count++;
        }

        fstate->total_payload_count += payload_count;


        struct timeval t_elapsed, t_now;
        gettimeofday(&t_now, NULL);
        timersub(&t_now, &fstate->t_total_time, &t_elapsed);
        int fcps = fstate->total_payload_count / (t_elapsed.tv_sec != 0 ? t_elapsed.tv_sec : 1);
        int mut_avg = fstate->mutation_time / fstate->total_payload_count;
        int cov_avg = fstate->coverage_time / fstate->total_payload_count;
        uint64_t cur_loop_time = _stop_measure(cur_loop_timer);
        plog("[t=%lu] [BBs=%zu] [seed=%llu] [fc=%llu] [fcps=%d] [cur_loop=%llu] [mut_avg=%d] "
                "[cov_avg=%d] [corpus=%zu]\n", 
                time(NULL), fstate->coverage.basic_block_count, seed, fstate->total_payload_count, 
                fcps, cur_loop_time, mut_avg, cov_avg, fstate->corpus_count);

        fstate->config->seed = seed + 1;
    }
}

void stdln_passive_loop(fuzzer_state_t *fstate) {
    gettimeofday(&fstate->t_total_time, NULL);
    while(true) {
        struct timeval *cur_loop_timer = _start_measure();

        corpus_entry_t *retcorp = NULL;
        coverage_t *cur_cov = stdln_passive_fuzz(fstate, &retcorp);
        if (cur_cov == NULL) {
            plog("[!] No coverage returned for this execution.\n");
        } else {
            // check if this is new coverage we didn't see before
            if (stdln_is_coverage_new(fstate, cur_cov)) {
                plog("[!] New coverage found, nice!\n");
                // add the new coverage to the fuzzing state's coverage collection
                stdln_add_coverage_to_state(fstate, cur_cov);
                // store the coverage information on disk as DRCOV file
                stdln_write_coverage_to_disk(fstate, "PASSIVE", cur_cov);
                // TODO: give the user the possibility to store EACH payload?
                if (retcorp != NULL) {
                    stdln_add_entry_to_corpus(fstate, retcorp);
                }
            }
        }

        fstate->total_payload_count += 1;
        free_cov(cur_cov);

        struct timeval t_elapsed, t_now;
        gettimeofday(&t_now, NULL);
        timersub(&t_now, &fstate->t_total_time, &t_elapsed);
        int fcps = fstate->total_payload_count / (t_elapsed.tv_sec != 0 ? t_elapsed.tv_sec : 1);
        int cov_avg = fstate->coverage_time / fstate->total_payload_count;
        uint64_t cur_loop_time = _stop_measure(cur_loop_timer);
        plog("[t=%lu] [BBs=%zu] [fc=%llu] [fcps=%d] [cur_loop=%llu] [cov_avg=%d]\n", 
                time(NULL), fstate->coverage.basic_block_count, fstate->total_payload_count, 
                fcps, cur_loop_time, cov_avg);
    }
}

// taken from https://gist.github.com/bg5sbk/11058000
char* str_replace(char* string, const char* substr, const char* replacement) {
	char* tok = NULL;
	char* newstr = NULL;
	char* oldstr = NULL;
	int   oldstr_len = 0;
	int   substr_len = 0;
	int   replacement_len = 0;

	newstr = strdup(string);
	substr_len = strlen(substr);
	replacement_len = strlen(replacement);

	if (substr == NULL || replacement == NULL) {
		return newstr;
	}

	while ((tok = strstr(newstr, substr))) {
		oldstr = newstr;
		oldstr_len = strlen(oldstr);
		newstr = (char*)malloc(sizeof(char) * (oldstr_len - substr_len + replacement_len + 1));

		if (newstr == NULL) {
			free(oldstr);
			return NULL;
		}

		memcpy(newstr, oldstr, tok - oldstr);
		memcpy(newstr + (tok - oldstr), replacement, replacement_len);
		memcpy(newstr + (tok - oldstr) + replacement_len, tok + substr_len, oldstr_len - substr_len - (tok - oldstr));
		memset(newstr + oldstr_len - substr_len + replacement_len, 0, 1);

		free(oldstr);
	}

	return newstr;
}

void run_standalone_active(fuzzer_state_t *fstate) {
    stdln_init(fstate);

    // Wait until the harness signals that it's ready
    while (!fstate->is_ready) {
        usleep(5000);
    }

    plog("[*] Fuzzer is ready.\n");

    if (fstate->config->input_mode == INPUT_MODE_CMD) {
        // store filename of .cur_input file for cmd input mode
        fstate->cur_input_file = malloc(0x100);
        snprintf(fstate->cur_input_file, 0x100, "%s/.cur_input", fstate->config->corpus_dir);

        // replace @@ in command string with .cur_input filename
        char *new_command = str_replace(fstate->config->command, "@@", fstate->cur_input_file);
        free(fstate->config->command);
        fstate->config->command = new_command;
    }

    stdln_load_corpus(fstate);

    stdln_get_corpus_coverage(fstate);

    stdln_fuzz_loop(fstate);
}

void run_standalone_passive(fuzzer_state_t *fstate) {
    stdln_init(fstate);

    // Wait until the harness signals that it's ready
    while (!fstate->is_ready) {
        usleep(5000);
    }

    stdln_passive_loop(fstate);
}