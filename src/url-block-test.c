#include "url-block-test.h"

//SIS
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
           "-file /example.txt            Domains file path\n"
           "-check_net 0.0.0.0/0          Сheck net\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    printf("\nUrl block test started\n");

    //Args
    int32_t is_domains_file_path = 0;
    char domains_file_path[PATH_MAX];

    uint32_t check_net_ip = 0;
    uint32_t check_net_prefix = 0;

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
        if (!strcmp(argv[i], "-check_net")) {
            if (i != argc - 1) {
                printf("Check net %s\n", argv[i + 1]);
                char *slash_ptr = strchr(argv[i + 1], '/');
                if (slash_ptr) {
                    sscanf(slash_ptr + 1, "%u", &check_net_prefix);
                    *slash_ptr = 0;
                    if (strlen(argv[i + 1]) < INET_ADDRSTRLEN) {
                        check_net_ip = inet_addr(argv[i + 1]);
                    }
                    *slash_ptr = '/';
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

    if (!check_net_ip || !check_net_prefix) {
        printf("Programm need check_net\n");
        print_help();
    }
    //Args

    printf("\n");

    //URLs read
    FILE *fp = fopen(domains_file_path, "r");
    if (!fp) {
        printf("Error opening file %s\n", domains_file_path);
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    int64_t urls_file_size_add = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *file_data = (char *)malloc(urls_file_size_add);

    if (fread(file_data, sizeof(char), urls_file_size_add, fp) != (size_t)urls_file_size_add) {
        printf("Can't read url file\n");
        exit(EXIT_FAILURE);
    }

    int urls_count = 0;

    for (int32_t i = 0; i < (int32_t)urls_file_size_add; i++) {
        if (file_data[i] == '\n') {
            file_data[i] = 0;
            urls_count++;
        }
    }

    char **urls = (char **)malloc(urls_count * sizeof(char *));

    char *processed_urls = (char *)malloc(urls_count);
    memset(processed_urls, 0, urls_count);

    char *url_start = file_data;

    for (int32_t i = 0; i < urls_count; i++) {
        urls[i] = url_start;

        url_start = strchr(url_start, 0) + 1;
    }

    printf("URLs count %d\n", urls_count);
    //URLs read

    //Calc start end subnet
    uint32_t subnet_ip = check_net_ip;
    int32_t subnet_prefix = check_net_prefix;

    uint32_t start_subnet_ip = ntohl(subnet_ip);

    int32_t subnet_size = 1;
    subnet_size <<= 32 - subnet_prefix;
    uint32_t end_subnet_ip = start_subnet_ip + subnet_size - 1;

    struct in_addr start_subnet_ip_addr;
    start_subnet_ip_addr.s_addr = htonl(start_subnet_ip);

    struct in_addr end_subnet_ip_addr;
    end_subnet_ip_addr.s_addr = htonl(end_subnet_ip);

    printf("Check subnet");
    printf(" %s", inet_ntoa(start_subnet_ip_addr));
    printf(" - ");
    printf("%s\n", inet_ntoa(end_subnet_ip_addr));
    //Calc start end subnet

    struct pollfd *pollfd = (struct pollfd *)malloc(MAX_SOCKET_COUNT * sizeof(struct pollfd));
    char *send_data = (char *)malloc(MAX_SOCKET_COUNT * PACKET_MAX_SIZE);
    char *read_data = (char *)malloc(PACKET_MAX_SIZE);
    char *ready_to_write = (char *)malloc(MAX_SOCKET_COUNT);
    int *sock_to_url = (int *)malloc(MAX_SOCKET_COUNT * sizeof(int));

    for (int k = 0; k < 5; k++) {
        int url_index = 0;
        int exit_flag = 0;

        printf("\nTry %d\n", k);

        while (!exit_flag) {
            for (int i = 0; i < MAX_SOCKET_COUNT; i++) {
                pollfd[i].fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            }

            int create_err = 0;
            int connect_err = 0;

            for (int i = 0; i < MAX_SOCKET_COUNT; i++) {
                if (pollfd[i].fd != -1) {
                    uint32_t start_subnet_ip_n = htonl(start_subnet_ip++);

                    struct sockaddr_in servaddr;
                    memset(&servaddr, 0, sizeof(servaddr));
                    servaddr.sin_family = AF_INET;
                    servaddr.sin_addr.s_addr = start_subnet_ip_n;
                    servaddr.sin_port = htons(PORT_TLS);

                    if (start_subnet_ip == end_subnet_ip) {
                        start_subnet_ip = ntohl(subnet_ip);
                    }

                    if (connect(pollfd[i].fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
                        if (errno != EINPROGRESS) {
                            close(pollfd[i].fd);
                            pollfd[i].fd = -1;
                            connect_err++;
                        }
                    }
                } else {
                    create_err++;
                }
            }

            //Ready to write
            for (int i = 0; i < MAX_SOCKET_COUNT; i++) {
                if (pollfd[i].fd != -1) {
                    pollfd[i].events = POLLOUT;
                } else {
                    pollfd[i].events = 0;
                }
                pollfd[i].revents = 0;
            }

            memset(ready_to_write, 0, MAX_SOCKET_COUNT);

            int pollout_err = 0;

            while (poll(pollfd, MAX_SOCKET_COUNT, POLL_SLEEP_TIME) > 0) {
                for (int i = 0; i < MAX_SOCKET_COUNT; i++) {
                    if (pollfd[i].revents != 0 && pollfd[i].revents != POLLOUT) {
                        close(pollfd[i].fd);
                        pollfd[i].fd = -1;
                        pollfd[i].events = 0;
                        pollfd[i].revents = 0;
                        pollout_err++;
                    }
                    if (pollfd[i].revents == POLLOUT) {
                        pollfd[i].events = 0;
                        pollfd[i].revents = 0;

                        ready_to_write[i] = 1;
                    }
                }
            }
            //Ready to write

            int required_num_soc = MAX_SOCKET_COUNT;

            int write_err = 0;
            int timeout_err = 0;

            //Write
            for (int i = 0; i < MAX_SOCKET_COUNT; i++) {
                if (pollfd[i].fd != -1) {
                    if (ready_to_write[i] == 1) {
                        if (url_index >= urls_count) {
                            required_num_soc = i;

                            exit_flag = 1;

                            break;
                        }

                        sock_to_url[i] = url_index;

                        char *send_data_local = &send_data[i * PACKET_MAX_SIZE];

                        int send_size = 0;
                        send_size = tls_client_hello(send_data_local, urls[url_index]);

                        int sended = 0;
                        sended = write(pollfd[i].fd, send_data_local, send_size);
                        if (sended != send_size) {
                            close(pollfd[i].fd);
                            pollfd[i].fd = -1;
                            write_err++;
                        }

                        url_index++;
                    } else {
                        close(pollfd[i].fd);
                        pollfd[i].fd = -1;
                        timeout_err++;
                    }
                }
            }
            //Write

            //Ready to read
            for (int i = 0; i < required_num_soc; i++) {
                if (pollfd[i].fd != -1) {
                    pollfd[i].events = POLLIN;
                } else {
                    pollfd[i].events = 0;
                }
                pollfd[i].revents = 0;
            }

            int pollin_err = 0;

            while (poll(pollfd, required_num_soc, POLL_SLEEP_TIME) > 0) {
                for (int i = 0; i < required_num_soc; i++) {
                    if (pollfd[i].revents != 0 && pollfd[i].revents != POLLIN) {
                        close(pollfd[i].fd);
                        pollfd[i].fd = -1;
                        pollfd[i].events = 0;
                        pollfd[i].revents = 0;
                        pollin_err++;
                    }
                    if (pollfd[i].revents == POLLIN) {
                        int readed = 0;
                        readed = read(pollfd[i].fd, read_data, PACKET_MAX_SIZE);
                        if (readed == 7) {
                            if (read_data[0] == 0x15 && read_data[1] == 0x3) {
                                processed_urls[sock_to_url[i]] = 2;
                            }
                        }

                        close(pollfd[i].fd);
                        pollfd[i].fd = -1;
                        pollfd[i].events = 0;
                        pollfd[i].revents = 0;
                    }
                }
            }
            //Ready to read

            //Find blocked
            for (int i = 0; i < required_num_soc; i++) {
                if (pollfd[i].fd != -1 && pollfd[i].events == POLLIN) {
                    if (processed_urls[sock_to_url[i]] != 2) {
                        processed_urls[sock_to_url[i]] = 1;
                    }
                }
            }
            //Find blocked

            //Close
            for (int i = 0; i < MAX_SOCKET_COUNT; i++) {
                if (pollfd[i].fd != -1) {
                    close(pollfd[i].fd);
                }
            }
            //Close

            //Stat
            int in_work_count = 0;
            int blocked_count = 0;
            int notblocked_count = 0;
            for (int32_t i = 0; i < urls_count; i++) {
                if (processed_urls[i] == 0) {
                    in_work_count++;
                }
                if (processed_urls[i] == 1) {
                    blocked_count++;
                }
                if (processed_urls[i] == 2) {
                    notblocked_count++;
                }
            }
            printf("\n");
            printf("in_work_count %d ", in_work_count);
            printf("blocked_count %d ", blocked_count);
            printf("notblocked_count %d ", notblocked_count);
            printf("url_index %d ", url_index);
            printf("\n");
            printf("opened %d ", MAX_SOCKET_COUNT);
            printf("create_err %d ", create_err);
            printf("connect_err %d ", connect_err);
            printf("pollout_err %d ", pollout_err);
            printf("write_err %d ", write_err);
            printf("timeout_err %d ", timeout_err);
            printf("pollin_err %d ", pollin_err);
            printf("\n");
            //Stat
        }
    }

    return 0;
}
