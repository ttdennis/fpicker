let pc = undefined;

if (Process.arch == "x64") {
  pc = "rip";
} else if (Process.arch.startsWith("arm")) {
  pc = "pc";
} else {
  console.log("[!] Unknown architecture!");
}

module.exports = new CModule(`
  #include <gum/gumstalker.h>
  #include <stdint.h>
  #include <stdio.h>

  static void afl_map_fill (GumCpuContext * cpu_context, gpointer user_data);

  struct _user_data {
    uint8_t *afl_area_ptr;
    uint64_t base;
    uintptr_t module_start;
    uintptr_t module_end;
    uintptr_t prev_loc;
    // pointer to a JS NativeCallback that calls console.log, do
    // not use in production
    void (*log)(long);
  };

  bool is_within_module(uintptr_t pc, uintptr_t s, uintptr_t e) {
    return (pc <= e) && (pc >= s);
  }

  void transform (GumStalkerIterator * iterator, GumStalkerOutput * output, gpointer user_data) {
    cs_insn * insn;
    struct _user_data *ud = (struct _user_data*)user_data;

    gum_stalker_iterator_next (iterator, &insn);

    // for some reason the range exclusion does not work reliably on iOS (?)
    // as a workaround we do it manually here
    if (is_within_module(insn->address, ud->module_start, ud->module_end)) {
      gum_stalker_iterator_put_callout (iterator, afl_map_fill, user_data, NULL);
    }

    gum_stalker_iterator_keep (iterator);

    while (gum_stalker_iterator_next (iterator, &insn)) {
      gum_stalker_iterator_keep (iterator);
    }
  }

  static void afl_map_fill (GumCpuContext * cpu_context, gpointer user_data) {
    struct _user_data *ud = (struct _user_data*)user_data;

    uintptr_t cur_loc = cpu_context->${pc} - ud->base;
    uintptr_t prev_loc = ud->prev_loc;
    uint8_t * afl_area_ptr = ud->afl_area_ptr;

    cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
    cur_loc &= 65536 - 1;
    afl_area_ptr[cur_loc ^ prev_loc]++;
    prev_loc = cur_loc >> 1;
  }
`);