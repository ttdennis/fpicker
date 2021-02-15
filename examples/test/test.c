#include <stdio.h>
#include <string.h>
#include <unistd.h>
#ifdef __APPLE__
  #include <os/log.h>
#endif

int stlen(char *a) {
    return strlen(a);
}

int bb(char a) {
    if (a == 'a') {
        return 1;
    } else {
        if (a == 'A') {
            return 0;
        }
        return 11;
    }
}

int proc_fn(char *buf, int len) {
    char local_buf[32];

#ifdef __APPLE__
    os_log(OS_LOG_DEFAULT, "[TEST]: %{public}s (%d)", buf, len);
#endif
    printf("%s(%d)\n", buf, len);

    if (stlen(buf) == 23001) return 2;

    if (stlen(buf) == 4 && buf[3] == 'X') return 1;

    if (buf[3] == 'X') {
        printf("\n");
        return 1;
    }


    if (stlen(buf) > 0 && buf[0] == 'A' && buf[1] == 'b') {
        memcpy(local_buf+34, buf, stlen(buf));
    }

    bb('u');

    return 1;
}

int main(int argc, char** argv) {
    if (argc > 1) proc_fn(argv[1], strlen(argv[1]));

    // keep the program running for debugging purposes
    while(1) {
        sleep(5);
    }
}
