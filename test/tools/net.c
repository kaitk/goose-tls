/* Blocking TCP for the test programs only (echo_server.goose, client.goose):
   the package itself never reads or writes a socket. POSIX, and recvmsg's and
   sendmsg's kTLS record types on Linux; returns -errno on failure. */
#include <errno.h>
#ifdef __linux__
#include <linux/tls.h>
#endif
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
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

/* A connection to host's port, the first of its addresses that answers, with
   the same receive timeout; -errno, or -EHOSTUNREACH when the name doesn't
   resolve. */
int64_t net_connect(net_bytes host, int32_t port) {
    signal(SIGPIPE, SIG_IGN);
    char name[256], service[16];
    if (host.len <= 0 || host.len >= (int64_t)sizeof name) return -EINVAL;
    memcpy(name, host.data, (size_t)host.len);
    name[host.len] = 0;
    snprintf(service, sizeof service, "%d", (int)port);
    struct addrinfo hints, *list = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(name, service, &hints, &list) != 0) return -EHOSTUNREACH;
    int fd = -1, e = EHOSTUNREACH;
    for (struct addrinfo *a = list; a && fd < 0; a = a->ai_next) {
        fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0) {
            e = errno;
            continue;
        }
        if (connect(fd, a->ai_addr, a->ai_addrlen) < 0) {
            e = errno;
            close(fd);
            fd = -1;
        }
    }
    freeaddrinfo(list);
    if (fd < 0) return -e;
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

/* The type of the record net_recv_record last gave: 23 for data. */
static __thread int64_t record_type = 23;

int64_t net_record_type(void) { return record_type; }

/* A receive on a kTLS socket: data, or one record that isn't, whose type
   net_record_type gives, from the kernel's TLS_GET_RECORD_TYPE. */
int64_t net_recv_record(int64_t fd, net_bytes buf) {
#ifdef __linux__
    char control[CMSG_SPACE(sizeof(unsigned char))];
    struct iovec iov = { buf.data, (size_t)buf.len };
    struct msghdr m;
    memset(&m, 0, sizeof m);
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = control;
    m.msg_controllen = sizeof control;
    ssize_t n;
    do n = recvmsg((int)fd, &m, 0); while (n < 0 && errno == EINTR);
    if (n < 0) return -errno;
    record_type = 23;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c))
        if (c->cmsg_level == SOL_TLS && c->cmsg_type == TLS_GET_RECORD_TYPE)
            record_type = *(unsigned char *)CMSG_DATA(c);
    return n;
#else
    (void)fd, (void)buf;
    return -ENOSYS;
#endif
}

/* Sends data as one record of the type through a kTLS socket's kernel, with
   TLS_SET_RECORD_TYPE. */
int64_t net_send_record(int64_t fd, int64_t type, net_bytes data) {
#ifdef __linux__
    char control[CMSG_SPACE(sizeof(unsigned char))];
    struct iovec iov = { data.data, (size_t)data.len };
    struct msghdr m;
    memset(&m, 0, sizeof m);
    memset(control, 0, sizeof control);
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = control;
    m.msg_controllen = sizeof control;
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    c->cmsg_level = SOL_TLS;
    c->cmsg_type = TLS_SET_RECORD_TYPE;
    c->cmsg_len = CMSG_LEN(sizeof(unsigned char));
    *(unsigned char *)CMSG_DATA(c) = (unsigned char)type;
    ssize_t n;
    do n = sendmsg((int)fd, &m, 0); while (n < 0 && errno == EINTR);
    return n < 0 ? -errno : n;
#else
    (void)fd, (void)type, (void)data;
    return -ENOSYS;
#endif
}
