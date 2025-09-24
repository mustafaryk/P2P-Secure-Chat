#ifndef _ENCRYPTION_H
#define _ENCRYPTION_H
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
int generate_key_pair(EVP_PKEY** public_key, EVP_PKEY** private_key);
int asymmetric_encrypt(EVP_PKEY* public_key, unsigned char* plain_text, int plain_text_length, unsigned char** cipher_text, int* cipher_text_length);
int asymmetric_decrypt(EVP_PKEY *private_key, unsigned char *ciphertext, int ciphertext_len, unsigned char **plaintext, int *plaintext_len);
void free_key_pair(EVP_PKEY* public_key, EVP_PKEY* private_key);
int make_symmetric_key(unsigned char* key, int key_size);
int generate_iv(unsigned char* iv, int iv_length);
int symmetric_encrypt(unsigned char* plain_text, int plain_text_length, unsigned char* cipher_text, int* cipher_text_length, unsigned char* iv, unsigned char* key);
int symmetric_decrypt(unsigned char* plain_text, int* plain_text_length, unsigned char* cipher_text, int cipher_text_length, unsigned char* iv, unsigned char* key);
#endif