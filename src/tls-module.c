#include "tls-module.h"
#include "custom-trace.h"
#include <netinet/in.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>

tls_connection_ctx *create_tls_ctx(int pack_max_size, struct pollfd *pollfd) {
    tls_connection_ctx *ctx = (tls_connection_ctx *) calloc(1, sizeof(tls_connection_ctx));
    if (!ctx) {
        PERROR("Memory allocation error\n");
        return NULL;
    }

    ctx->read_data = (char *) malloc(pack_max_size);
    if (!ctx->read_data) {
        PERROR("Memory allocation error\n");
        free(ctx);
        return NULL;
    }

    ctx->send_data = (char *) malloc(pack_max_size);
    if (!ctx->send_data) {
        PERROR("Memory allocation error\n");
        free(ctx->read_data);
        free(ctx);
        return NULL;
    }

    ctx->pollfd = pollfd;

    return ctx;
}

tls_connection_ctx **create_multi_tls_ctxs(int nb, int pack_max_size, struct pollfd *pollfd) {
    int i;
    tls_connection_ctx **ctxs = (tls_connection_ctx **) calloc(nb, sizeof(tls_connection_ctx *));

    for (i = 0; i < nb; ++i) {
        ctxs[i] = create_tls_ctx(pack_max_size, &pollfd[i]);

        if (!ctxs[i]) {
            break;
        }
    }

    if (i < nb) {
        for (int j = 0; j < i; ++j) {
            destroy_tls_ctx(ctxs[j]);
        }

        return NULL;
    }

    return ctxs;
}

void destroy_tls_ctx(tls_connection_ctx *ctx) {
    free(ctx->read_data);
    free(ctx->send_data);
    free(ctx);
}

void destroy_multi_tls_ctxs(int nb, tls_connection_ctx **ctxs) {
    for (int i = 0; i < nb; ++i) {
        destroy_tls_ctx(ctxs[i]);
    }
}

int create_tls_socket(tls_connection_ctx *ctx) {
    struct pollfd *pollfd = ctx->pollfd;

    if (!pollfd) {
        PERROR("Poll structure is not determined\n");
        return -1;
    }

    pollfd->fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

    if (pollfd->fd < 0) {
        return -1;
    }

    return 0;
}

int connect_tls_socket(tls_connection_ctx *ctx, uint32_t addr) {
    struct sockaddr_in servaddr;
    struct pollfd *pollfd = ctx->pollfd;

    if (!pollfd) {
        PERROR("Poll structure is not determined\n");
        return -1;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(addr);
    servaddr.sin_port = htons(PORT_TLS);

    if (connect(pollfd->fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        if (errno != EINPROGRESS) {
            return -1;
        }
    }

    memcpy(&ctx->addr, &servaddr, sizeof(struct sockaddr_in));

    return 0;
}

void close_tls_socket(tls_connection_ctx *ctx) {
    struct pollfd *pollfd = ctx->pollfd;

    if (!pollfd) {
        PERROR("Poll structure is not determined\n");
        return;
    }

    close(pollfd->fd);
    pollfd->fd = -1;
}

void mark_tls_socket_active_out(tls_connection_ctx *ctx) {
    struct pollfd *pollfd = ctx->pollfd;

    if (!pollfd) {
        PERROR("Poll structure is not determined\n");
        return ;
    }

    ctx->ready_to_write = 0;
    pollfd->events = POLLOUT;
    pollfd->revents = 0;
}

void mark_tls_socket_not_active(tls_connection_ctx *ctx) {
    struct pollfd *pollfd = ctx->pollfd;

    if (!pollfd) {
        PERROR("Poll structure is not determined\n");
        return;
    }

    ctx->ready_to_write = 0;
    pollfd->events = 0;
    pollfd->revents = 0;
}

void mark_tls_socket_ready_write(tls_connection_ctx *ctx) {
    struct pollfd *pollfd = ctx->pollfd;

    ctx->ready_to_write = 1;
    pollfd->events = 0;
    pollfd->revents = 0;
}