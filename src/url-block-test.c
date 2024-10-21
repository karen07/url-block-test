#include "url-block-test.h"

int32_t tls_client_hello(char *send_data, char *sni)
{
    int32_t sni_len = strlen(sni);

    tls_data_t *buff;
    buff = (tls_data_t *)send_data;

    buff->content_type = 22;
    buff->tls_version = htons(0x0301);
    buff->tls_length = htons(sizeof(tls_data_t) + sni_len - 5);

    buff->handshake_type = 1;
    buff->handshake_length_1 = 0;
    buff->handshake_length_2 = htons(sizeof(tls_data_t) + sni_len - 5 - 4);
    buff->handshake_version = htons(0x0303);

    for (int32_t i = 0; i < (int32_t)sizeof(buff->random); i++) {
        buff->random[i] = rand();
    }

    buff->session_id_length = 32;
    for (int32_t i = 0; i < (int32_t)sizeof(buff->session_id); i++) {
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

void print_help(void)
{
    printf("Commands:\n"
           "-file /example.txt            Domains file path\n"
           "-check_net 0.0.0.0/0          Check net\n"
           "-check_ip_file /example.txt   Check IPs file path\n");
    exit(EXIT_FAILURE);
}

int32_t in_subnet(uint32_t ip, char *subnet_in)
{
    char subnet[100];
    strcpy(subnet, subnet_in);

    uint32_t ip_h = ntohl(ip);

    uint32_t subnet_ip = 0;
    uint32_t subnet_prefix = 0;

    char *slash_ptr = strchr(subnet, '/');
    if (slash_ptr) {
        sscanf(slash_ptr + 1, "%u", &subnet_prefix);
        *slash_ptr = 0;
        if (strlen(subnet) < INET_ADDRSTRLEN) {
            subnet_ip = inet_addr(subnet);
        }
        *slash_ptr = '/';
    }

    uint32_t netip = ntohl(subnet_ip);
    uint32_t netmask = (0xFFFFFFFF << (32 - subnet_prefix) & 0xFFFFFFFF);

    if ((netip & netmask) == (ip_h & netmask)) {
        return 1;
    } else {
        return 0;
    }
}

int main(int32_t argc, char *argv[])
{
    printf("\nUrl block test started\n");

    //Args
    int32_t is_domains_file_path = 0;
    char domains_file_path[PATH_MAX];

    int32_t is_check_ip_file_path = 0;
    char check_ip_file_path[PATH_MAX];

    uint32_t check_net_ip = 0;
    uint32_t check_net_prefix = 0;

    for (int32_t i = 1; i < argc; i++) {
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
        if (!strcmp(argv[i], "-check_ip_file")) {
            if (i != argc - 1) {
                printf("Get IPs from file %s\n", argv[i + 1]);
                if (strlen(argv[i + 1]) < PATH_MAX) {
                    is_check_ip_file_path = 1;
                    strcpy(check_ip_file_path, argv[i + 1]);
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

    if (is_check_ip_file_path == 0) {
        if (!check_net_ip || !check_net_prefix) {
            printf("Programm need check_net\n");
            print_help();
        }
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

    int32_t urls_count = 0;

    for (int32_t i = 0; i < (int32_t)urls_file_size_add; i++) {
        if (file_data[i] == '\n') {
            file_data[i] = 0;
            urls_count++;
        }
    }

    char **urls = (char **)malloc(urls_count * sizeof(char *));

    char *url_start = file_data;
    for (int32_t i = 0; i < urls_count; i++) {
        urls[i] = url_start;

        url_start = strchr(url_start, 0) + 1;
    }
    //URLs read

    uint32_t *IPs = NULL;
    int32_t ips_count = 0;
    int32_t current_ips_num = 0;

    if (is_check_ip_file_path) {
        //IPs read
        FILE *fp = fopen(check_ip_file_path, "r");
        if (!fp) {
            printf("Error opening file %s\n", check_ip_file_path);
            return 0;
        }

        fseek(fp, 0, SEEK_END);
        int64_t ips_file_size_add = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        char *file_data = (char *)malloc(ips_file_size_add);

        if (fread(file_data, sizeof(char), ips_file_size_add, fp) != (size_t)ips_file_size_add) {
            printf("Can't read url file\n");
            exit(EXIT_FAILURE);
        }

        for (int32_t i = 0; i < (int32_t)ips_file_size_add; i++) {
            if (file_data[i] == '\n') {
                file_data[i] = 0;
                ips_count++;
            }
        }

        IPs = (uint32_t *)malloc(ips_count * sizeof(uint32_t));

        char *url_start = file_data;
        for (int32_t i = 0; i < ips_count; i++) {
            IPs[i] = inet_addr(url_start);

            url_start = strchr(url_start, 0) + 1;
        }
        //IPs read
    } else {
        //Calc start end subnet
        /*subnet_ip = check_net_ip;

        start_subnet_ip = ntohl(subnet_ip);

        ips_count = 1;
        ips_count <<= 32 - check_net_prefix;
        end_subnet_ip = start_subnet_ip + ips_count - 1;

        struct in_addr start_subnet_ip_addr;
        start_subnet_ip_addr.s_addr = htonl(start_subnet_ip);

        struct in_addr end_subnet_ip_addr;
        end_subnet_ip_addr.s_addr = htonl(end_subnet_ip);

        printf("Check subnet");
        printf(" %s", inet_ntoa(start_subnet_ip_addr));
        printf(" - ");
        printf("%s\n", inet_ntoa(end_subnet_ip_addr));*/
        //Calc start end subnet
    }

    printf("URLs count: %d\n", urls_count);
    printf("IPs  count: %d\n", ips_count);

    char *processed_urls = (char *)malloc(urls_count);
    memset(processed_urls, 0, urls_count);

    struct pollfd *pollfd = (struct pollfd *)malloc(MAX_SOCKET_COUNT * sizeof(struct pollfd));
    char *send_data = (char *)malloc(MAX_SOCKET_COUNT * PACKET_MAX_SIZE);
    char *read_data = (char *)malloc(PACKET_MAX_SIZE);
    char *ready_to_write = (char *)malloc(MAX_SOCKET_COUNT);
    int32_t *sock_to_url = (int32_t *)malloc(MAX_SOCKET_COUNT * sizeof(int32_t));
    int32_t *sock_to_ip = (int32_t *)malloc(MAX_SOCKET_COUNT * sizeof(int32_t));

    for (int32_t k = 0; k < 5; k++) {
        int32_t url_index = 0;
        int32_t exit_flag = 0;

        printf("\nTry %d\n", k);

        while (!exit_flag) {
            for (int32_t i = 0; i < MAX_SOCKET_COUNT; i++) {
                pollfd[i].fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            }

            int32_t create_err = 0;
            int32_t connect_err = 0;

            for (int32_t i = 0; i < MAX_SOCKET_COUNT; i++) {
                if (pollfd[i].fd != -1) {
                    int32_t ret = 0;
                    do {
                        ret = 0;
                        ret += in_subnet(IPs[current_ips_num], "10.0.0.0/8");
                        ret += in_subnet(IPs[current_ips_num], "172.16.0.0/12");
                        ret += in_subnet(IPs[current_ips_num], "192.168.0.0/16");
                        ret += in_subnet(IPs[current_ips_num], "100.64.0.0/10");
                        if (ret > 0) {
                            //struct in_addr end_subnet_ip_addr;
                            //end_subnet_ip_addr.s_addr = IPs[current_ips_num];
                            //printf("%s\n", inet_ntoa(end_subnet_ip_addr));
                            current_ips_num++;
                        }
                    } while (ret > 0);

                    struct sockaddr_in servaddr;
                    memset(&servaddr, 0, sizeof(servaddr));
                    servaddr.sin_family = AF_INET;
                    servaddr.sin_addr.s_addr = IPs[current_ips_num];
                    servaddr.sin_port = htons(PORT_TLS);

                    sock_to_ip[i] = IPs[current_ips_num];

                    current_ips_num++;

                    if (current_ips_num == ips_count) {
                        current_ips_num = 0;
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
            for (int32_t i = 0; i < MAX_SOCKET_COUNT; i++) {
                if (pollfd[i].fd != -1) {
                    pollfd[i].events = POLLOUT;
                } else {
                    pollfd[i].events = 0;
                }
                pollfd[i].revents = 0;
            }

            memset(ready_to_write, 0, MAX_SOCKET_COUNT);

            int32_t pollout_err = 0;

            while (poll(pollfd, MAX_SOCKET_COUNT, POLL_SLEEP_TIME) > 0) {
                for (int32_t i = 0; i < MAX_SOCKET_COUNT; i++) {
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

            int32_t required_num_soc = MAX_SOCKET_COUNT;

            int32_t write_err = 0;
            int32_t timeout_err = 0;

            //Write
            for (int32_t i = 0; i < MAX_SOCKET_COUNT; i++) {
                if (pollfd[i].fd != -1) {
                    if (ready_to_write[i] == 1) {
                        if (url_index >= urls_count) {
                            required_num_soc = i;

                            exit_flag = 1;

                            break;
                        }

                        sock_to_url[i] = url_index;

                        char *send_data_local = &send_data[i * PACKET_MAX_SIZE];

                        int32_t send_size = 0;
                        send_size = tls_client_hello(send_data_local, urls[url_index]);

                        int32_t sended = 0;
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
            for (int32_t i = 0; i < required_num_soc; i++) {
                if (pollfd[i].fd != -1) {
                    pollfd[i].events = POLLIN;
                } else {
                    pollfd[i].events = 0;
                }
                pollfd[i].revents = 0;
            }

            int32_t pollin_err = 0;

            while (poll(pollfd, required_num_soc, POLL_SLEEP_TIME) > 0) {
                for (int32_t i = 0; i < required_num_soc; i++) {
                    if (pollfd[i].revents != 0 && pollfd[i].revents != POLLIN) {
                        close(pollfd[i].fd);
                        pollfd[i].fd = -1;
                        pollfd[i].events = 0;
                        pollfd[i].revents = 0;
                        pollin_err++;
                    }
                    if (pollfd[i].revents == POLLIN) {
                        int32_t readed = 0;
                        readed = read(pollfd[i].fd, read_data, PACKET_MAX_SIZE);
                        if (readed == 7) {
                            if (read_data[0] == 0x15 && read_data[1] == 0x3) {
                                processed_urls[sock_to_url[i]] = 2;
                                struct in_addr end_subnet_ip_addr;
                                end_subnet_ip_addr.s_addr = sock_to_ip[i];
                                printf("%s\n", inet_ntoa(end_subnet_ip_addr));
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
            for (int32_t i = 0; i < required_num_soc; i++) {
                if (pollfd[i].fd != -1 && pollfd[i].events == POLLIN) {
                    if (processed_urls[sock_to_url[i]] != 2) {
                        processed_urls[sock_to_url[i]] = 1;
                    }
                }
            }
            //Find blocked

            //Close
            for (int32_t i = 0; i < MAX_SOCKET_COUNT; i++) {
                if (pollfd[i].fd != -1) {
                    close(pollfd[i].fd);
                }
            }
            //Close

            //Stat
            int32_t in_work_count = 0;
            int32_t blocked_count = 0;
            int32_t notblocked_count = 0;
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
            printf("current_ips_num %d ", current_ips_num);
            printf("\n");
            //Stat
        }
    }

    FILE *blocked_fp = fopen("blocked.txt", "w");
    if (!blocked_fp) {
        printf("Error opening file blocked.txt\n");
        return 0;
    }

    for (int32_t i = 0; i < urls_count; i++) {
        if (processed_urls[i] == 1) {
            fprintf(blocked_fp, "%s\n", urls[i]);
        }
    }

    return 0;
}
