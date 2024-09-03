#include <stdio.h>
#include <curl/curl.h>

int main(void)
{
    CURL *curl;
    CURLcode res = CURLE_OK;

    struct curl_slist *host =
        curl_slist_append(NULL, "manifest.googlevideo.com:443:speedtest.selectel.ru:443");

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_CONNECT_TO, host);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_URL, "https://manifest.googlevideo.com/100MB");

        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        res = curl_easy_perform(curl);

        curl_easy_cleanup(curl);
    }

    curl_slist_free_all(host);

    return (int)res;
}
