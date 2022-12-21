#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

int dce_aes_gcm(const unsigned char *key,
                bool decrypt,
                const unsigned char *iv,
                uintptr_t iv_len,
                const unsigned char *aad,
                uintptr_t aad_len,
                const unsigned char *source,
                unsigned char *dest,
                uintptr_t data_len,
                uint8_t *tag);

int dce_sm4_gcm(const unsigned char *key,
                bool decrypt,
                const unsigned char *iv,
                uintptr_t iv_len,
                const unsigned char *aad,
                uintptr_t aad_len,
                const unsigned char *source,
                unsigned char *dest,
                uintptr_t data_len,
                uint8_t *tag);

int dce_aes_xts(const unsigned char *keys,
                bool decrypt,
                const unsigned char *iv,
                const unsigned char *source,
                unsigned char *dest,
                uintptr_t data_len);

int dce_sm4_xts(const unsigned char *keys,
                bool decrypt,
                const unsigned char *iv,
                const unsigned char *source,
                unsigned char *dest,
                uintptr_t data_len);
