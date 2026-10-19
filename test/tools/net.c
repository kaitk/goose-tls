/* Blocking TCP for the test server only (echo_server.goose): the package
   itself never touches a socket. POSIX; returns -errno on failure. */
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#pragma pack(push, 1)
typedef struct { uint8_t *data; int64_t len; } net_bytes;
#pragma pack(pop)

/* A listener on 127.0.0.1:port, or on every address when any is set. */
int64_t net_listen(int32_t port, uint8_t any) {
    signal(SIGPIPE, SIG_IGN);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -errno;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    a.sin_addr.s_addr = htonl(any ? INADDR_ANY : INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) < 0 || listen(fd, 64) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }
    return fd;
}

/* The next connection, with a receive timeout so that a stalled client
   doesn't hold the one-connection-at-a-time server forever. */
int64_t net_accept(int64_t lfd) {
    int fd;
    do fd = accept((int)lfd, NULL, NULL); while (fd < 0 && errno == EINTR);
    if (fd < 0) return -errno;
    struct timeval tv = { 10, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    return fd;
}

int64_t net_recv(int64_t fd, net_bytes buf) {
    ssize_t n;
    do n = recv((int)fd, buf.data, (size_t)buf.len, 0); while (n < 0 && errno == EINTR);
    return n < 0 ? -errno : n;
}

int64_t net_send(int64_t fd, net_bytes data) {
    int64_t done = 0;
    while (done < data.len) {
        ssize_t n = send((int)fd, data.data + done, (size_t)(data.len - done), 0);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return -errno;
        done += n;
    }
    return done;
}

void net_close(int64_t fd) {
    close((int)fd);
}
