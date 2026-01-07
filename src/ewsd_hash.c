#include "ewsd_hash.h"

#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>

#include "ewsd_log.h"

/* Build option: -DEWSD_ENABLE_HASH=0/1 */
#ifndef EWSD_ENABLE_HASH
#define EWSD_ENABLE_HASH 1
#endif

#if EWSD_ENABLE_HASH

/* Hash decrypt key (client/server must match). */
const char *key = "007208e6b9ff54e974c08635397b12f4";

int verify_hash(const char *recv_params, const char *recv_hash) 
{
    if (!recv_params || !recv_hash) {
        log_to_file("Invalid parameters for hash verification.");
        return 0;
    }

    char *cleaned_params = strdup(recv_params);
    if (!cleaned_params) {
        log_to_file("Memory allocation failed for cleaned_params.");
        return 0;
    }

    char *src = cleaned_params;
    char *dst = cleaned_params;
    while (*src) {
        if (src[0] == '\\' && src[1] == '/') {
            src++;
        }
        *dst++ = *src++;
    }
    *dst = '\0';

    unsigned char recalculated_hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    HMAC(EVP_sha256(), key, strlen(key),
         (unsigned char *)cleaned_params, strlen(cleaned_params),
         recalculated_hash, &hash_len);

    char recalculated_hash_hex[2 * hash_len + 1];
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(&recalculated_hash_hex[i * 2], "%02x", recalculated_hash[i]);
    }
    recalculated_hash_hex[2 * hash_len] = '\0';

    int result = strcmp(recv_hash, recalculated_hash_hex) == 0;

    free(cleaned_params);

    return result;
}

#else  /* EWSD_ENABLE_HASH == 0 */

int verify_hash(const char *recv_params, const char *recv_hash)
{
    (void)recv_params;
    (void)recv_hash;
    return 1;
}

#endif
