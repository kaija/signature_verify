/** @file verify_sign.h
 * @brief verify base64 encoded signature by using base64 encoded public key
 * @author kaija (kaija.chang@gmail.com)
 */
#ifndef __VERIFY_SIGN_H
#define __VERIFY_SIGN_H

#ifdef DEBUGSIG
# define DBG(fmt, args...)    fprintf(stderr, fmt, ## args)
#else
# define DBG(fmt, args...)    do {} while (0)
#endif

enum {
	VERIFY_OK,          /** verify pass */
	VERIFY_FAIL,        /** verify failure */
	VERIFY_PUBKEY,      /** public key read error */
	VERIFY_SIG_FORMAT,  /** signature format parse error */
    VERIFY_FILE_MISS    /** signature file missing */
};

/*
 * @fn int digest_verify(int base64, char *pubkey, int len, char *signature, int slen, char *file)
 * @param base64 1 means base64 encoded public key
 * @param pubkey public key buffer
 * @param len public key length
 * @param signature_base64 1 means base64 encoded signature buffer
 * @param signature signature buffer
 * @param slen signature buffer length
 * @param file signed file path
 * @retval 0 Verify failure
 * @retval 1 Verify success
 */
int digest_verify(int base64, char *pubkey, int len, int signature_base64, char *signature, int slen, char *file);

/*
 * @fn char* digest_base64_decode(char *buf, int len, int *olen)
 * @param buf input encoded base64 buffer
 * @param len input buffer length
 * @param olen output buffer length
 * @return decoded base64 buffer. need to be free after use
 */
char* digest_base64_decode(char *buf, int len, int *olen);

/*
 * @fn char* digest_read_file(char *file, int *len)
 * @param file read file name
 * @param len output buffer length
 * @return file buffer. need to be free after use
 */
char* digest_read_file(char *file, int *len);

/*
 * @fn int digest_simple(char *path, char *file, char *public_key)
 * @param path the verify file path
 * @param file the signature file name. ( default: signature.txt)
 * @param public_key base64 encoded public key buffer
 * @retval VERIFY_OK all signature verify pass
 * @retval VERIFY_FAIL not all signature verify pass
 */
int digest_simple(char *path, char *file, char *public_key);



#endif
