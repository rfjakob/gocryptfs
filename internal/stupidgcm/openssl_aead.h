#include <openssl/evp.h>

int openssl_aead_seal(
    const EVP_CIPHER* evpCipher,
    const unsigned char* const plaintext,
    const int plaintextLen,
    const unsigned char* const authData,
    const int authDataLen,
    const unsigned char* const key,
    const int keyLen,
    const unsigned char* const iv,
    const int ivLen,
    unsigned char* const ciphertext,
    const int ciphertextBufLen);

int openssl_aead_open(
    const EVP_CIPHER* evpCipher,
    const unsigned char* const ciphertext,
    const int ciphertextLen,
    const unsigned char* const authData,
    const int authDataLen,
    unsigned char* const tag,
    const int tagLen,
    const unsigned char* const key,
    const int keyLen,
    const unsigned char* const iv,
    const int ivLen,
    unsigned char* const plaintext,
    const int plaintextBufLen);

void noop_c_function(void);
