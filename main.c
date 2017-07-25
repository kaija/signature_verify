#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "verify_sign.h"

static char public_key[] =  "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFzNHFZL29ub2RrQk5zOEl4ZEF6NQpHSGQ2b05OMGJ1NEYrVE1LMlRKNXBtcy9zNm9tbGIxNUZSaXQxRU1iVGhlWUZnN1FTUHBick54ZUJmdmZPOEZPCmZObk85dXF5TkZ3TU9DQWZNY0FJcGQ2S1ZiWjJlTWVQRVpZVjZoalJtWk9SMmE0Rkh6T09mM0d6T0t0UWFwODIKNG1NL3lHdGhYOHFiT2xtSEx2clgzMkhNelNIRTA5MWkxRVRuTHZRaE1JQUZXREp5N0lWNXorMVd3MUNrTHlRSApGRE5rODJ5bTRDWFJHbUJpTDhvcjljYmFReGgwMWtiVW1jNkJ6eW02M1VaVDFRMHdTa0RuYTdJMXZGMDBNaitRCnphZzBORi9YNld4YVZraE9BL0E0ejRTUHdiYWZ3SW13NHNVRmpqOXpTam9BL0w0Y3VmUGhURGFyK29Md0lkS0sKcXdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==";
static char demosign[] = "g8u7rEfr4aZgPyEpbF+dmtxp5xmpZPtxGbEbGiY1rIRjKVGIJAQLc+NwyF7vaVuAze5Pt6ygzTKhIRYEeNy8CRzCCMG+B213eBgEP8u4ZCB/GgAA1KQJaEWXVuyOjL/Rr4zSEc68ziehnpudfbW5DhoN1/XTfSnLazQOjLub3ak8kwsDCwg5n8hktwuxkOtbde1KCFTylDiFBYRaKOQpTuZGASJ1y+brLQNzI5iDToXeF8E6Yx6c4OIEbNcj8CkxCITciuw8jsTr4UIfcm0/KUIj+AZWORzkg//k/kxs38MhLQJZhJxBltV+wib9e3ryTiLqIbJpiOJEWbj8awUodQ==";

int test()
{
    int rc = digest_verify(1, public_key, strlen(public_key), 1, demosign, strlen(demosign), "demo.luac");
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
    int rc = digest_verify(0, pkey, pkey_len, 0, sign, sign_len, "demo.luac");
    if (rc == VERIFY_OK) {
        printf("Verify OK\n");
    }else{
        printf("Verify NOT OK\n");
    }
    return 0;
}
/*
int digest_simple(char *path, char *file)
{
    const int LINESIZE = 512;//signature + file path
    FILE *fp = NULL;
    char line[LINESIZE];
    int nok_count = 0;
    int miss_count = 0;
    int res = 0;
    if (path) {
        chdir(path);
    }
    if (file) {
        fp = fopen(file, "r");
    }else{
        fp = fopen("signature.txt", "r");
    }
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            char filename[LINESIZE];
            char signature[LINESIZE];
            memset(filename, 0, LINESIZE);
            memset(signature, 0, LINESIZE);
            char *ptr = strstr(line, "  ");
            if (ptr == NULL) {
                DBG("signature file parsing error\n");
                break;
            }
            memcpy(signature, line, (ptr - line));
            memcpy(filename, ptr + 2 , strlen(line) - (ptr - line) - 3);
            DBG("Verifying: %s\n", filename);
            if ( 0 != access(filename, F_OK)) {
                miss_count ++;
                continue;
            }
            if (digest_verify(1, public_key, strlen(public_key), 1, signature, strlen(signature), filename) == VERIFY_OK){
                DBG("%s Verify OK\n", filename);
            }else{
                DBG("%s Verify NOT OK\n", filename);
                nok_count ++;
            }

        }
        fclose(fp);
    }
    if (nok_count != 0) {
        DBG("%d file verify failure\n", nok_count);
        res = -1;
    }
    if (miss_count != 0) {
        DBG("%d file missing\n", miss_count);
        res = -1;
    }
    return res;
}
*/
int main()
{
    if (digest_simple("./demo", NULL, public_key) != 0) {
        printf("signature failure\n");
    }else{
        printf("signature verify OK\n");
    }
    return 0;
}
