module.exports = new CModule(`
  #define PROT_READ       0x01
  #define PROT_WRITE      0x02
  #define MAP_SHARED      0x0001
  #define MAP_FAILED      ((void *)-1)
  #define O_RDWR 0x02

  void *mmap(void *addr, int len, int prot, int flags, int fd, int offset);
  int shm_open(const char*, int, ...);

  void *darwin_shm(char *shm_name, int size) {
    void *ptr;
    int shm_fd = -1;

    shm_fd = shm_open(shm_name, O_RDWR, 0600);
    ptr = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);

    if (ptr == MAP_FAILED) {
      return 0;
    }
    return ptr;
  }
`, {
  "mmap": Module.getExportByName(null, "mmap"),
  "shm_open": Module.getExportByName(null, "shm_open"),
});
