// +build !without_openssl

#include "openssl_aead.h"
#include <openssl/evp.h>
#include <stdio.h>
//#cgo pkg-config: libcrypto

static void panic(const char* const msg)
{
    fprintf(stderr, "panic in C code: %s\n", msg);
    __builtin_trap();
}

// We only support 16-byte tags
static const int supportedTagLen = 16;

// https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption#Authenticated_Encryption_using_GCM_mode
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
    const int ciphertextBufLen)
{
    // Create scratch space "ctx"
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        panic("EVP_CIPHER_CTX_new failed");
    }

    // Set cipher
    if (EVP_EncryptInit_ex(ctx, evpCipher, NULL, NULL, NULL) != 1) {
        panic("EVP_EncryptInit_ex set cipher failed");
    }

    // Check keyLen by trying to set it (fails if keyLen != 32)
    if (EVP_CIPHER_CTX_set_key_length(ctx, keyLen) != 1) {
        panic("keyLen mismatch");
    }

    // Set IV length so we do not depend on the default
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, ivLen, NULL) != 1) {
        panic("EVP_CTRL_AEAD_SET_IVLEN failed");
    }

    // Set key and IV
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        panic("EVP_EncryptInit_ex set key & iv failed");
    }

    // Provide authentication data
    int outLen = 0;
    if (EVP_EncryptUpdate(ctx, NULL, &outLen, authData, authDataLen) != 1) {
        panic("EVP_EncryptUpdate authData failed");
    }
    if (outLen != authDataLen) {
        panic("EVP_EncryptUpdate authData: unexpected length");
    }

    // Encrypt "plaintext" into "ciphertext"
    if (plaintextLen > ciphertextBufLen) {
        panic("plaintext overflows output buffer");
    }
    if (EVP_EncryptUpdate(ctx, ciphertext, &outLen, plaintext, plaintextLen) != 1) {
        panic("EVP_EncryptUpdate ciphertext failed");
    }
    if (outLen != plaintextLen) {
        panic("EVP_EncryptUpdate ciphertext: unexpected length");
    }
    int ciphertextLen = outLen;

    // Finalise encryption
    // Normally ciphertext bytes may be written at this stage, but this does not occur in GCM mode
    if (EVP_EncryptFinal_ex(ctx, ciphertext + plaintextLen, &outLen) != 1) {
        panic("EVP_EncryptFinal_ex failed");
    }
    if (outLen != 0) {
        panic("EVP_EncryptFinal_ex: unexpected length");
    }

    // Get MAC tag and append it to the ciphertext
    if (ciphertextLen + supportedTagLen > ciphertextBufLen) {
        panic("tag overflows output buffer");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, supportedTagLen, ciphertext + plaintextLen) != 1) {
        panic("EVP_CTRL_AEAD_GET_TAG failed");
    }
    ciphertextLen += supportedTagLen;

    // Free scratch space
    EVP_CIPHER_CTX_free(ctx);

    return ciphertextLen;
}

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
    const int plaintextBufLen)
{
    // Create scratch space "ctx"
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        panic("EVP_CIPHER_CTX_new failed");
    }

    // Set cipher
    if (EVP_DecryptInit_ex(ctx, evpCipher, NULL, NULL, NULL) != 1) {
        panic("EVP_DecryptInit_ex set cipher failed");
    }

    // Check keyLen by trying to set it (fails if keyLen != 32)
    if (EVP_CIPHER_CTX_set_key_length(ctx, keyLen) != 1) {
        panic("keyLen mismatch");
    }

    // Set IV length so we do not depend on the default
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, ivLen, NULL) != 1) {
        panic("EVP_CTRL_AEAD_SET_IVLEN failed");
    }

    // Set key and IV
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        panic("EVP_DecryptInit_ex set key & iv failed");
    }

    // Provide authentication data
    int outLen = 0;
    if (EVP_DecryptUpdate(ctx, NULL, &outLen, authData, authDataLen) != 1) {
        panic("EVP_DecryptUpdate authData failed");
    }
    if (outLen != authDataLen) {
        panic("EVP_DecryptUpdate authData: unexpected length");
    }

    // Decrypt "ciphertext" into "plaintext"
    if (ciphertextLen > plaintextBufLen) {
        panic("ciphertextLen overflows output buffer");
    }
    if (EVP_DecryptUpdate(ctx, plaintext, &outLen, ciphertext, ciphertextLen) != 1) {
        panic("EVP_DecryptUpdate failed");
    }
    int plaintextLen = outLen;

    // Check tag
    if (tagLen != supportedTagLen) {
        panic("unsupported tag length");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tagLen, tag) != 1) {
        panic("EVP_CTRL_AEAD_SET_TAG failed");
    }
    if (EVP_DecryptFinal_ex(ctx, plaintext + plaintextLen, &outLen) != 1) {
        // authentication failed
        return -1;
    }
    if (outLen != 0) {
        panic("EVP_EncryptFinal_ex: unexpected length");
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintextLen;
}

// This functions exists to benchmark the C call overhead from Go.
void noop_c_function(void) {
    return;
}
