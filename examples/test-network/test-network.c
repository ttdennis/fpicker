#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
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

    if (stlen(buf) > 0 && buf[0] == 'A') {
        memcpy(local_buf, buf, stlen(buf));
    }

    bb('u');

    return 1;
}

int main(int argc, char** argv) {
    int sockfd, connfd;
    socklen_t len;
    struct sockaddr_in server, client;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    bzero(&server, sizeof(server));

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(atoi(argv[1]));

    if ((bind(sockfd, (struct sockaddr*)&server, sizeof(server))) != 0) {
        printf("Socket bind failed\n");
        exit(1);
    }

    if (listen(sockfd, 5) != 0) {
        printf("Listen failed\n");
        exit(1);
    }

    while(1) {
        len = sizeof(client);
        connfd = accept(sockfd, (struct sockaddr*)&client, &len);
        if (connfd < 0) {
            printf("Accept failed\n");
            exit(1);
        }

        char buf[0x100];
        while (read(connfd, buf, 0x100)) {
            proc_fn(buf, strlen(buf));
            bzero(buf, 0x100);
        }

        close(connfd);
    }
}
