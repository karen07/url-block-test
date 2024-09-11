#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/limits.h>

#include "custom-trace.h"

typedef struct subnet_ctx_ {
    uint32_t start_subnet_ip;
    uint32_t end_subnet_ip;
    struct in_addr start_subnet_ip_addr;
    struct in_addr end_subnet_ip_addr;
} subnet_ctx;

typedef struct programm_args_ {
    int32_t is_domains_file_path;
    char domains_file_path[PATH_MAX];
    uint32_t check_net_ip;
    uint32_t check_net_prefix;
} programm_args;

typedef struct domain_list_ {
    uint64_t count;
    char **urls;
} domain_list;

#define get_url_from_list(list, index) (list->count > index ? (list->urls[index]) : NULL)
#define get_url_number_in_list(list) (list->count)


static inline domain_list *create_domain_list(char *file_name) {
    domain_list *list;
    char *file_data;
    int64_t urls_file_size_add;

    int urls_count = 0;
    FILE *fp = fopen(file_name, "r");
    if (!fp) {
        PERROR("Error opening file %s\n", file_name);
        return NULL;
    }

    list = (domain_list *) calloc(1, sizeof(domain_list));

    if (!list) {
        PERROR("Memory allocation error\n");
        goto error_allocate_domain_list;
    }

    fseek(fp, 0, SEEK_END);
    urls_file_size_add = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    file_data = (char *) malloc(urls_file_size_add);

    if (!file_data) {
        PERROR("Memory allocation error\n");
        goto error_allocate_file_data;
    }

    if (fread(file_data, sizeof(char), urls_file_size_add, fp) != (size_t)urls_file_size_add) {
        PERROR("Can't read url file\n");
        goto error_fread;
    }

    for (int32_t i = 0; i < (int32_t)urls_file_size_add; i++) {
        if (file_data[i] == '\n') {
            file_data[i] = 0;
            ++urls_count;
        }
    }

    list->urls = malloc(urls_count * sizeof(char*));
    list->count = urls_count;

    if (!list->urls) {
        PERROR("Memory allocation error\n");
        goto error_fread;
    }

    for (int32_t i = 0; i < urls_count; i++) {
        list->urls[i] = file_data;

        file_data = strchr(file_data, 0) + 1;
    }

    fclose(fp);

    return list;

error_fread:
    free(file_data);

error_allocate_file_data:
    free(list);

error_allocate_domain_list:
    fclose(fp);

    return NULL;
}

static inline void destroy_domain_list(domain_list *list) {
    if (list->count > 0) {
        free(list->urls[0]);
        free(list->urls);
    }

    free(list);
}

static inline void calc_ip_addr_range(uint32_t subnet, uint32_t mask, subnet_ctx *ctx) {
    uint32_t subnet_ip = subnet;
    int32_t subnet_prefix = mask;
    struct in_addr *start_subnet_ip_addr = &ctx->start_subnet_ip_addr;
    struct in_addr *end_subnet_ip_addr = &ctx->end_subnet_ip_addr;
    int32_t subnet_size = 1;

    ctx->start_subnet_ip = ntohl(subnet_ip);
    subnet_size <<= 32 - subnet_prefix;
    ctx->end_subnet_ip = ctx->start_subnet_ip + subnet_size - 1;

    start_subnet_ip_addr->s_addr = htonl(ctx->start_subnet_ip);
    end_subnet_ip_addr->s_addr = htonl(ctx->end_subnet_ip);
}

#endif
