enum aeadType {
    aeadTypeChacha = 1,
    aeadTypeGcm = 2,
};

int aead_seal(
    const enum aeadType cipherId,
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

int aead_open(
    const enum aeadType cipherId,
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
