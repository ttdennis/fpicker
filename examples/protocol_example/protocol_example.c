#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_CONNECTIONS 0x10

typedef struct _connection_t {
    short handle;
    int fd;
    char addr[7];
} connection_t;

connection_t g_connections[MAX_CONNECTIONS];
short g_num_connections = 0;

int create_connection(int connfd) {
    // assign some kind of value as handle (+ 100 chosen arbitrarily)
    int handle = connfd + 100;

    g_connections[g_num_connections].handle = handle;
    g_connections[g_num_connections].fd = connfd;
    snprintf(g_connections[g_num_connections].addr, 6, "BT%d", connfd); 
    g_connections[g_num_connections].addr[6] = 0;

    printf("Got new connection:\n\tfd: %d\n\thandle: %d\n\taddr: %s\n",
        g_connections[g_num_connections].fd,
        g_connections[g_num_connections].handle,
        g_connections[g_num_connections].addr);

    return handle;
}

void disconnect(short handle) {
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (g_connections[i].handle == handle) {
            g_connections[i].handle = 0;
            g_connections[i].fd = 0;
            memset(g_connections[i].addr, 0x00, 7);
        }
    }
}

void protocol_handler(short handle, size_t len, char *data) {
    connection_t *con = NULL;

    // look up connection from handle
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (g_connections[i].handle == handle) {
            con = &g_connections[i];
            break;
        }
    }

    if (con == NULL) {
        printf("Received data for unknown handle\n");
        return;
    }

    if (data[0] != 'U') {
        printf("Received non-U input :O\n");
        disconnect(handle);
        return;
    }

    if (rand() % 50 > 35) {
        printf("Random condition that leads to a disconnect!\n");
        disconnect(handle);
        return;
    }

    printf("[%s]: %s", con->addr, data);
}

void *connection_handler(void *data) {
    char buf[0x100];
    connection_t *conn = (connection_t*)data;
    while (read(conn->fd, buf, 0x100)) {
        protocol_handler(conn->handle, strlen(buf), buf);
        bzero(buf, 0x100);
    }

    close(conn->fd);
    return NULL;
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

    while (1) {
        int handle;
        pthread_t thread;

        len = sizeof(client);
        connfd = accept(sockfd, (struct sockaddr*)&client, &len);

        if (connfd < 0) {
            printf("Accept failed\n");
            exit(1);
        }

        // create new connection handle object
        if (g_num_connections == MAX_CONNECTIONS - 1) {
            printf("Max number of connections reached!\n");
            close(connfd);

            continue;
        }

        handle = create_connection(connfd);

        if (pthread_create(&thread, NULL, connection_handler, (void*)&g_connections[g_num_connections]) < 0) {
            printf("Cannot create thread for protocol_handler\n");
            exit(1);
        }

        // pthread_join(thread, NULL);
    }
}
