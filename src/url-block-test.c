#include <stdio.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <string.h>
#include <curl/curl.h>

#define PACKET_MAX_SIZE 1500

void print_help()
{
    printf("Commands:\n"
           "-file /example.txt            Domains file path\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
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

    FILE *fp;

    fp = fopen(domains_file_path, "r");
    if (!fp) {
        printf("Error opening file %s\n", domains_file_path);
        return 0;
    }

    char line_buf[PACKET_MAX_SIZE];
    char curl_slist_append_data[PACKET_MAX_SIZE * 3];
    char curl_easy_setopt_data[PACKET_MAX_SIZE * 3];

    int32_t count = 0;

    while (fscanf(fp, "%s", line_buf) != EOF) {
        count++;

        CURL *curl;
        CURLcode res = CURLE_OK;

        sprintf(curl_slist_append_data, "new.%s:443:speedtest.selectel.ru:443", line_buf);

        struct curl_slist *host = curl_slist_append(NULL, curl_slist_append_data);

        curl = curl_easy_init();
        if (curl) {
            sprintf(curl_easy_setopt_data, "https://new.%s/100MB", line_buf);

            curl_easy_setopt(curl, CURLOPT_CONNECT_TO, host);
            curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 200);
            curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
            curl_easy_setopt(curl, CURLOPT_URL, curl_easy_setopt_data);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

            res = curl_easy_perform(curl);

            curl_easy_cleanup(curl);
        }
        curl_slist_free_all(host);

        if (res == CURLE_OPERATION_TIMEDOUT) {
            printf("%d new.%s\n", count, line_buf);
        }
    }

    return 0;
}
