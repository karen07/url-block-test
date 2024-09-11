#include "url-block-test.h"
#include "custom-trace.h"
#include "tls-module.h"
#include "utils.h"

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/poll.h>

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

static inline int parse_programm_args(int argc, char *argv[], programm_args *args) {
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-file")) {
            if (i != argc - 1) {
                PDEBUG("Get urls from file %s\n", argv[i + 1]);
                if (strlen(argv[i + 1]) < PATH_MAX) {
                    args->is_domains_file_path = 1;
                    strcpy(args->domains_file_path, argv[i + 1]);
                }
                i++;
            }
            continue;
        } else if (!strcmp(argv[i], "-check_net")) {
            if (i != argc - 1) {
                PDEBUG("Check net %s\n", argv[i + 1]);
                char *slash_ptr = strchr(argv[i + 1], '/');
                if (slash_ptr) {
                    sscanf(slash_ptr + 1, "%u", &args->check_net_prefix);
                    *slash_ptr = 0;
                    if (strlen(argv[i + 1]) < INET_ADDRSTRLEN) {
                        args->check_net_ip = inet_addr(argv[i + 1]);
                    }
                    *slash_ptr = '/';
                }
                i++;
            }
        } else {
            PERROR("Unknown command %s\n", argv[i]);
            return -1;
        }
    }

    return 0;
}

int main(int argc, char *argv[])
{
    programm_args args;
    domain_list *dlist;
    subnet_ctx subnet;
    tls_connection_ctx **tls_ctxs;
    struct pollfd *pollset;

    PINFO("\nUrl block test started\n");

    // Parsing the command line
    if (parse_programm_args(argc, argv, &args)) {
        print_help();
        return -1;
    }

    // Check the option of file name with list of domains
    if (!args.is_domains_file_path) {
        printf("Programm need domains file path\n");
        print_help();
        return -1;
    }

    // Check the option of specified TLS subnet
    if (!args.check_net_ip || !args.check_net_prefix) {
        printf("Programm need check_net\n");
        print_help();
        return -1;
    }

    PINFO("\n");

    dlist = create_domain_list(args.domains_file_path);
    if (!dlist) {
        PERROR("Error while creating url list\n");
        return -1;
    }

    PINFO("URLs count %lu\n", get_url_number_in_list(dlist));
    //URLs read

    //Calc start end subnet
    calc_ip_addr_range(args.check_net_ip, args.check_net_prefix, &subnet);
    PINFO("Check subnet");
    PINFO(" %s", inet_ntoa(subnet.start_subnet_ip_addr));
    PINFO(" - ");
    PINFO("%s\n", inet_ntoa(subnet.end_subnet_ip_addr));
    
    pollset = (struct pollfd *) malloc(MAX_SOCKET_COUNT * sizeof(struct pollfd));

    if (!pollset) {
        PERROR("Memory allocation error\n");
        return -1;
    }

    tls_ctxs = create_multi_tls_ctxs(MAX_SOCKET_COUNT, PACKET_MAX_SIZE, pollset);

    if (!tls_ctxs) {
        PERROR("TLS contexts creation is failed\n");
        return -1;
    }

    uint32_t start_subnet_ip_tmp = subnet.start_subnet_ip;
    for (int k = 0; k < 5; k++) {
        int url_index = 0;
        int exit_flag = 0;

        printf("\nTry %d\n", k);

        while (!exit_flag) {
            int create_err = 0;
            int connect_err = 0;

            for (int i = 0; i < MAX_SOCKET_COUNT; i++) {
                tls_connection_ctx *ctx = tls_ctxs[i];

                create_tls_socket(ctx);
                mark_tls_socket_not_active(ctx);

                if (is_tls_socket_valid(ctx)) {
                    uint32_t start_subnet_ip_n = start_subnet_ip_tmp++;

                    if (connect_tls_socket(ctx, start_subnet_ip_n)) {
                        close_tls_socket(ctx);
                        ++connect_err;
                    } else {
                        mark_tls_socket_active_out(ctx);
                    }
                    
                    if (start_subnet_ip_tmp == subnet.end_subnet_ip) {
                        start_subnet_ip_tmp = subnet.start_subnet_ip;
                    }
                } else {
                    create_err++;
                }
            }

            int pollout_err = 0;
            while (poll(pollset, MAX_SOCKET_COUNT, POLL_SLEEP_TIME) > 0) {
                for (int i = 0; i < MAX_SOCKET_COUNT; i++) {
                    tls_connection_ctx *ctx = tls_ctxs[i];
                    if (pollset[i].revents != 0 && pollset[i].revents != POLLOUT) {
                        close_tls_socket(ctx);
                        mark_tls_socket_not_active(ctx);
                        pollout_err++;
                    } else if (pollset[i].revents == POLLOUT) {
                        mark_tls_socket_ready_write(ctx);
                    }
                }
            }

            int required_num_soc = MAX_SOCKET_COUNT;
            int write_err = 0;
            int timeout_err = 0;

            //Write
            for (int i = 0; i < MAX_SOCKET_COUNT; i++) {
                tls_connection_ctx *ctx = tls_ctxs[i];
                if (is_tls_socket_valid(ctx)) {
                    if (is_tls_socket_ready_write(ctx)) {
                        if (url_index >= get_url_number_in_list(dlist)) {
                            required_num_soc = i;
                            exit_flag = 1;
                            break;
                        }

                        ctx->sock_to_url = url_index;

                        char *send_data_local = ctx->send_data;

                        int send_size = 0;
                        send_size = tls_client_hello(send_data_local, get_url_from_list(dlist, url_index));

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
