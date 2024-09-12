#ifndef _TLS_MODULE_H_
#define _TLS_MODULE_H_

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>

#define PORT_TLS 443

typedef struct tls_connection_ctx_ {
    struct pollfd *pollfd;
    char *send_data;
    char *read_data;
    char ready_to_write;
    int sock_to_url;
    struct sockaddr_in addr;
} tls_connection_ctx;

#define is_tls_socket_valid(ctx) (ctx->pollfd->fd > 0)
#define is_tls_socket_ready_write(ctx) (ctx->ready_to_write == 1)

tls_connection_ctx *create_tls_ctx(int pack_max_size, struct pollfd *pollfd);
tls_connection_ctx **create_multi_tls_ctxs(int nb, int pack_max_size, struct pollfd *pollfd);
void destroy_tls_ctx(tls_connection_ctx *ctx);
void destroy_multi_tls_ctxs(int nb, tls_connection_ctx **ctxs);
int create_tls_socket(tls_connection_ctx *ctx);
int connect_tls_socket(tls_connection_ctx *ctx, uint32_t addr);
void close_tls_socket(tls_connection_ctx *ctx);
void mark_tls_socket_active_out(tls_connection_ctx *ctx);
void mark_tls_socket_not_active(tls_connection_ctx *ctx);
void mark_tls_socket_ready_write(tls_connection_ctx *ctx);

#endif
