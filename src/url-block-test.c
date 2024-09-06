#include <linux/limits.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>

#define PORT_TLS 443
#define PACKET_MAX_SIZE 1500

void print_help()
{
    printf("Commands:\n"
           "-file /example.txt            Domains file path\n");
    exit(EXIT_FAILURE);
}

typedef struct tls_data {
    uint8_t content_type;
    uint16_t tls_version;
    uint16_t tls_length;

    uint8_t handshake_type;
    uint8_t handshake_length_1;
    uint16_t handshake_length_2;
    uint16_t handshake_version;

    uint8_t random[32];

    uint8_t session_id_length;
    uint8_t session_id[32];

    uint16_t cipher_suites_length;
    uint16_t cipher_suites;

    uint8_t compression_methods_length;
    uint8_t compression_methods;

    uint16_t extensions_length;

    uint16_t extensions_type;
    uint16_t extension_length;

    uint16_t sni_list_length;
    uint8_t sni_type;
    uint16_t sni_length;
} __attribute__((packed)) tls_data_t;

int tls_client_hello(char *send_data, char *sni)
{
    int sni_len = strlen(sni);

    tls_data_t *buff;
    buff = (tls_data_t *)send_data;

    buff->content_type = 22;
    buff->tls_version = htons(0x0301);
    buff->tls_length = htons(sizeof(tls_data_t) + sni_len - 5);

    buff->handshake_type = 1;
    buff->handshake_length_1 = 0;
    buff->handshake_length_2 = htons(sizeof(tls_data_t) + sni_len - 5 - 4);
    buff->handshake_version = htons(0x0303);

    for (int i = 0; i < (int)sizeof(buff->random); i++) {
        buff->random[i] = rand();
    }

    buff->session_id_length = 32;
    for (int i = 0; i < (int)sizeof(buff->session_id); i++) {
        buff->session_id[i] = rand();
    }

    buff->cipher_suites_length = htons(2);
    buff->cipher_suites = htons(0x1302);

    buff->compression_methods_length = 1;
    buff->compression_methods = 0;

    buff->extensions_length = htons(9 + sni_len);

    buff->extensions_type = htons(0);
    buff->extension_length = htons(5 + sni_len);

    buff->sni_list_length = htons(3 + sni_len);
    buff->sni_type = 0;
    buff->sni_length = htons(sni_len);

    strcpy(send_data + sizeof(tls_data_t), sni);

    return sizeof(tls_data_t) + sni_len;
}

#define one_pack_size 500

int main(int argc, char *argv[])
{
    char *selectel_ip = "188.93.16.211";

    printf("\nUrl block test started\n");

    int32_t is_domains_file_path = 0;
    char domains_file_path[PATH_MAX];

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-file")) {
            if (i != argc - 1) {
                printf("Get urls from file %s\n", argv[i + 1]);
                if (strlen(argv[i + 1]) < PATH_MAX) {
                    is_domains_file_path = 1;
                    strcpy(domains_file_path, argv[i + 1]);
                }
                i++;
            }
            continue;
        }
        printf("Unknown command %s\n", argv[i]);
        print_help();
    }

    if (!is_domains_file_path) {
        printf("Programm need domains file path\n");
        print_help();
    }

    printf("\n");

    FILE *fp = fopen(domains_file_path, "r");
    if (!fp) {
        printf("Error opening file %s\n", domains_file_path);
        return 0;
    }

    char sni[one_pack_size][PACKET_MAX_SIZE];
    for (int i = 0; i < one_pack_size; i++) {
        fscanf(fp, "%s", sni[i]);
    }

    struct pollfd pollfd_out[one_pack_size];
    memset(pollfd_out, 0, sizeof(struct pollfd) * one_pack_size);

    struct pollfd pollfd_in[one_pack_size];
    memset(pollfd_in, 0, sizeof(struct pollfd) * one_pack_size);

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(selectel_ip);
    servaddr.sin_port = htons(PORT_TLS);

    for (int i = 0; i < one_pack_size; i++) {
        int sockfd;
        sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

        pollfd_out[i].fd = sockfd;
        pollfd_out[i].events = POLLOUT;

        pollfd_in[i].fd = sockfd;
        pollfd_in[i].events = POLLIN;

        if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
            if (errno != EINPROGRESS) {
                close(sockfd);
                printf("karen\n");
                fflush(stdout);
            }
        }
    }

    while (poll(pollfd_out, one_pack_size, 100) > 0) {
        for (int i = 0; i < one_pack_size; i++) {
            if (pollfd_out[i].revents == POLLOUT) {
                pollfd_out[i].revents = 0;
                pollfd_out[i].events = 0;
            }
        }
    }

    char send_data[one_pack_size][PACKET_MAX_SIZE];
    for (int i = 0; i < one_pack_size; i++) {
        int send_size = 0;
        send_size = tls_client_hello(send_data[i], sni[i]);

        write(pollfd_out[i].fd, send_data[i], send_size);
    }

    char read_flags[one_pack_size];
    memset(read_flags, 0, one_pack_size);

    while (poll(pollfd_in, one_pack_size, 100) > 0) {
        for (int i = 0; i < one_pack_size; i++) {
            if (pollfd_in[i].revents == POLLIN) {
                pollfd_in[i].revents = 0;
                pollfd_in[i].events = 0;

                read_flags[i] = 1;
            }
        }
    }

    int block_count = 0;
    for (int i = 0; i < one_pack_size; i++) {
        if (read_flags[i] == 0) {
            //printf("block:%s\n", sni[i]);
            block_count++;
        }
    }

    printf("block_count %d\n", block_count);

    for (int i = 0; i < one_pack_size; i++) {
        close(pollfd_out[i].fd);
    }
}
