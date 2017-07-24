#ifndef __VERIFY_SIGN_H
#define __VERIFY_SIGN_H
/**
 * @brief verify base64 encoded signature by using base64 encoded public key
 * @author kaija (kaija.chang@gmail.com)
 * @param base64 1 means base64 encoded public key
 * @param pubkey public key buffer
 * @param len public key length
 * @param signature signature buffer
 * @param slen signature buffer length
 * @param file signed file path
 * @retval 0 Verify failure
 * @retval 1 Verify success
 */

int digest_verify(int base64, char *pubkey, int len, char *signature, int slen, char *file);
#endif
