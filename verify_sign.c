#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/engine.h>

#include "verify_sign.h"


static int digest_verify_init(EVP_MD_CTX *ctx, const EVP_MD *type, EVP_PKEY *pkey) {
    int rc = 0;
    ERR_clear_error();
    rc = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    if (rc != 1) {
        return -EFAULT;
    }
    rc = EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    if (rc != 1) {
        return -EFAULT;
    }
    return 0;
}

static int digest_verify_update(EVP_MD_CTX *ctx, char *msg_payload, unsigned int msg_len) {
    int rc = 0;
    rc = EVP_DigestVerifyUpdate(ctx, msg_payload, msg_len);
    if (rc != 1) {
        return -EFAULT;
    }
    return 0;
}

static int digest_verify_final(EVP_MD_CTX *ctx, char *sig_payload, unsigned int sig_len) {
    unsigned int rc = 0;
    ERR_clear_error();
    rc = EVP_DigestVerifyFinal(ctx, (unsigned char *)sig_payload, sig_len);
    if (rc != 1) {
        return 1;
    }
    return 0;
}

static BIO* digest_load_bio_file(char *path)
{
    int rc = 0;
    BIO *pkey = NULL;
    pkey = BIO_new(BIO_s_file());
    rc = BIO_read_filename(pkey, path);
    if (rc != 1) {
        return NULL;
    }
    return pkey;
}
static BIO* digest_load_bio_buf(char *buf, int len)
{
    BIO *pkey = NULL;
    pkey = BIO_new_mem_buf(buf, len);
    return pkey;
}
static BIO* digest_load_bio_b64_buf(char *buf, int len, char **pbuf)
{
    BIO *b64, *bmem, *pkey;
    int publen;
    //convert base64
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf(buf, len);
    bmem = BIO_push(b64, bmem);
    //malloc space for decode pub key, base64 decode message length should shorter than origin
    *pbuf = malloc(len);
    publen = BIO_read(bmem, *pbuf, len);
    BIO_free_all(bmem);
    pkey = BIO_new_mem_buf(*pbuf, publen);
    return pkey;
}

char* digest_base64_decode(char *buf, int len, int *olen)
{
    char *out = NULL;
    BIO *b64, *bmem;
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf(buf, len);
    bmem = BIO_push(b64, bmem);
    out = malloc(len);
    if (out) {
        memset(out, 0, len);
        *olen = BIO_read(bmem, out, len);
    }
    BIO_free_all(bmem);
    return out;
}

char *read_file(char *file, int *len)
{
    FILE *fp = NULL;
    void *ptr = NULL;
    int size = 0;
    fp = fopen(file, "r");
    if (fp) {
        fseek (fp, 0, SEEK_END);
        size = ftell(fp);
        rewind(fp);
        ptr = malloc(size);
        fread(ptr, 1, size, fp);
        fclose(fp);
    }
    *len = size;
    return ptr;
}


int digest_verify(int base64, char *pubkey, int len, char *signature, int slen, char *file)
{
    int res = 0;
    const int BUFSIZE = 512;
    char src_buf[BUFSIZE];
    FILE *fp = NULL;
    BIO *pub = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *ctx = NULL;
    char *buf = NULL;
    if (base64 == 1) {
        pub = digest_load_bio_b64_buf(pubkey, len, &buf);
    } else {
        pub = digest_load_bio_buf(pubkey, len);
    }
    if ( pub == NULL) res = VERIFY_PUBKEY;
    pkey = PEM_read_bio_PUBKEY(pub, NULL, NULL, NULL);
    if ( pkey == NULL) res = VERIFY_PUBKEY;
    //release buf
    if (buf) free(buf);
    if (pub) BIO_free(pub);

    if (pkey) {
        char *out = NULL;
        if (base64 == 1) {
            out = digest_base64_decode(signature, slen, &len);
        } else {
            out = malloc(slen);//TBD check null
            memcpy(out, signature, slen);
            len = slen;
        }
        fp = fopen(file, "r");
        if (fp ) {
            ctx = EVP_MD_CTX_create();
            if (digest_verify_init(ctx, EVP_sha256(), pkey) == 0 ) {
                for (;;) {
                    int blen = fread(src_buf, 1, BUFSIZE, fp);
                    if (blen < 1) break;
                    if (digest_verify_update(ctx, src_buf, blen) != 0 ) {
                        break;
                    }
                }
                if (digest_verify_final(ctx, out, len) == 0) {
                    res = 1;
                }
            }
            EVP_MD_CTX_cleanup(ctx);
            EVP_MD_CTX_destroy(ctx);
            fclose(fp);
        }
        if (out) free(out);
        EVP_PKEY_free(pkey);
    }
    EVP_cleanup();
    return res;
}
