#include "url-block-test.h"

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

void print_help()
{
    printf("Commands:\n"
           "-file /example.txt            Domains file path\n");
    exit(EXIT_FAILURE);
}

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

    char sni[MAX_SOCKET_COUNT][PACKET_MAX_SIZE];
    char send_data[MAX_SOCKET_COUNT][PACKET_MAX_SIZE];
    int sockfd[MAX_SOCKET_COUNT];
    struct pollfd pollfd[MAX_SOCKET_COUNT];
    char read_flags[MAX_SOCKET_COUNT];

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(selectel_ip);
    servaddr.sin_port = htons(PORT_TLS);

    int end_of_file = 0;

    while (!end_of_file) {
        int readed_urls = 0;
        for (int i = 0; i < MAX_SOCKET_COUNT; i++) {
            int fscanf_res = fscanf(fp, "%s", sni[i]);
            if (fscanf_res == EOF) {
                end_of_file = 1;
                break;
            }
            readed_urls++;
        }

        printf("\nreaded_urls %d\n", readed_urls);

        memset(pollfd, 0, sizeof(struct pollfd) * MAX_SOCKET_COUNT);

        for (int i = 0; i < readed_urls; i++) {
            sockfd[i] = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            if (sockfd[i] == -1) {
                printf("socket open error\n");
                fflush(stdout);
            }

            pollfd[i].fd = sockfd[i];
            pollfd[i].events = POLLOUT;

            if (connect(sockfd[i], (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
                if (errno != EINPROGRESS) {
                    close(sockfd[i]);
                    printf("socket connect error\n");
                    fflush(stdout);
                }
            }
        }

        printf("start POLLOUT\n");
        fflush(stdout);

        int poll_res = 0;
        while ((poll_res = poll(pollfd, readed_urls, POLL_SLEEP_TIME)) > 0) {
            //printf("%d\n", poll_res);
            for (int i = 0; i < readed_urls; i++) {
                if (pollfd[i].revents == POLLOUT) {
                    pollfd[i].events = 0;
                }
            }
        }

        printf("end POLLOUT\n");
        fflush(stdout);

        printf("start write\n");
        fflush(stdout);

        for (int i = 0; i < readed_urls; i++) {
            int send_size = 0;
            send_size = tls_client_hello(send_data[i], sni[i]);

            int sended = 0;
            sended = write(sockfd[i], send_data[i], send_size);
            if (sended < 1) {
                printf("socket write error\n");
                fflush(stdout);
            }
        }

        printf("end write\n");
        fflush(stdout);

        memset(read_flags, 0, MAX_SOCKET_COUNT);

        memset(pollfd, 0, sizeof(struct pollfd) * MAX_SOCKET_COUNT);
        for (int i = 0; i < readed_urls; i++) {
            pollfd[i].fd = sockfd[i];
            pollfd[i].events = POLLIN;
        }

        printf("start POLLIN\n");
        fflush(stdout);

        poll_res = 0;
        while ((poll_res = poll(pollfd, readed_urls, POLL_SLEEP_TIME)) > 0) {
            //printf("%d\n", poll_res);
            for (int i = 0; i < readed_urls; i++) {
                if (pollfd[i].revents == POLLIN) {
                    pollfd[i].events = 0;

                    read_flags[i] = 1;
                }
            }
        }

        printf("end POLLIN\n");
        fflush(stdout);

        int block_count = 0;
        for (int i = 0; i < readed_urls; i++) {
            if (read_flags[i] == 0) {
                //printf("block:%s\n", sni[i]);
                block_count++;
            }
        }

        printf("block_count %d\n", block_count);

        for (int i = 0; i < readed_urls; i++) {
            close(sockfd[i]);
        }
    }
}
