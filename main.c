#include <stdio.h>
#include <string.h>
#include "verify_sign.h"

static char public_key[] =  "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFzNHFZL29ub2RrQk5zOEl4ZEF6NQpHSGQ2b05OMGJ1NEYrVE1LMlRKNXBtcy9zNm9tbGIxNUZSaXQxRU1iVGhlWUZnN1FTUHBick54ZUJmdmZPOEZPCmZObk85dXF5TkZ3TU9DQWZNY0FJcGQ2S1ZiWjJlTWVQRVpZVjZoalJtWk9SMmE0Rkh6T09mM0d6T0t0UWFwODIKNG1NL3lHdGhYOHFiT2xtSEx2clgzMkhNelNIRTA5MWkxRVRuTHZRaE1JQUZXREp5N0lWNXorMVd3MUNrTHlRSApGRE5rODJ5bTRDWFJHbUJpTDhvcjljYmFReGgwMWtiVW1jNkJ6eW02M1VaVDFRMHdTa0RuYTdJMXZGMDBNaitRCnphZzBORi9YNld4YVZraE9BL0E0ejRTUHdiYWZ3SW13NHNVRmpqOXpTam9BL0w0Y3VmUGhURGFyK29Md0lkS0sKcXdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==";
static char demosign[] = "g8u7rEfr4aZgPyEpbF+dmtxp5xmpZPtxGbEbGiY1rIRjKVGIJAQLc+NwyF7vaVuAze5Pt6ygzTKhIRYEeNy8CRzCCMG+B213eBgEP8u4ZCB/GgAA1KQJaEWXVuyOjL/Rr4zSEc68ziehnpudfbW5DhoN1/XTfSnLazQOjLub3ak8kwsDCwg5n8hktwuxkOtbde1KCFTylDiFBYRaKOQpTuZGASJ1y+brLQNzI5iDToXeF8E6Yx6c4OIEbNcj8CkxCITciuw8jsTr4UIfcm0/KUIj+AZWORzkg//k/kxs38MhLQJZhJxBltV+wib9e3ryTiLqIbJpiOJEWbj8awUodQ==";

int test()
{
    int rc = digest_verify(1, public_key, strlen(public_key), demosign, strlen(demosign), "demo.luac");
    if (rc == VERIFY_OK) {
        printf("Verify OK\n");
    }else{
        printf("Verify NOT OK\n");
    }
    return 0;
}

int test2()
{
    int pkey_len = 0;
    int sign_len = 0;
    char *pkey = digest_base64_decode(public_key, strlen(public_key), &pkey_len);
    char *sign = digest_base64_decode(demosign, strlen(demosign), &sign_len);
    int rc = digest_verify(0, pkey, pkey_len, sign, sign_len, "demo.luac");
    if (rc == 1) {
        printf("Verify OK\n");
    }else{
        printf("Verify NOT OK\n");
    }
    return 0;
}

int demo()
{
    const int LINESIZE = 512;
    FILE *fp = NULL;
    char line[LINESIZE];

    fp = fopen("signature.txt", "r");
    if(fp){
        while (fgets(line, sizeof(line), fp)) {
            char filename[LINESIZE];
            char signature[LINESIZE];
            memset(filename, 0, LINESIZE);
            memset(signature, 0, LINESIZE);
            char *ptr = strstr(line, "    ");
            if (ptr == NULL) {
                printf("signature file parsing error\n");
                break;
            }
            memcpy(signature, line, (ptr - line));
            memcpy(filename, ptr + 4 , strlen(line) - (ptr - line) - 5);
            printf("verifying: %s by %s\n", filename, signature);
            if (digest_verify(1, public_key, strlen(public_key), signature, strlen(signature), filename)){
                printf("%s verify OK\n", filename);
            }else{
                printf("%s verify NOT OK\n", filename);
            }

        }
        fclose(fp);
    }
    return 0;
}
int main()
{
    test2();
    return 0;
}
