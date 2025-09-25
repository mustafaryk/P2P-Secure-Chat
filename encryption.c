#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include "encryption.h"


int generate_key_pair(EVP_PKEY **public_key, EVP_PKEY **private_key) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    // 1. Create context for RSA key generation
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new_id failed\n");
        return 1;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init failed\n");
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_rsa_keygen_bits failed\n");
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    // 2. Generate key pair
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen failed\n");
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    EVP_PKEY_CTX_free(ctx);

    // 3. Assign keys
    *private_key = pkey;

    // Extract public key
	unsigned char *pub_buf = NULL;
	int pub_len = i2d_PUBKEY(pkey, &pub_buf);  // DER encode public key
	const unsigned char *p = pub_buf;
	*public_key = d2i_PUBKEY(NULL, &p, pub_len);

    if (!*public_key) {
        fprintf(stderr, "d2i_PUBKEY failed\n");
        EVP_PKEY_free(pkey);
        return 1;
    }

    return 0;
}

int asymmetric_encrypt(EVP_PKEY* public_key, unsigned char* plain_text, int plain_text_length, unsigned char** cipher_text, int* cipher_text_length){
	
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(public_key, NULL);
    if (!ctx){
		fprintf(stderr, "Unable to allocate memory for context");
		return 1;
	}

    if (EVP_PKEY_encrypt_init(ctx) <= 0){
		EVP_PKEY_CTX_free(ctx);
		fprintf(stderr, "Unable to create a context for encryption");
		return 1;
	}

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0){
		EVP_PKEY_CTX_free(ctx);
		fprintf(stderr, "Unable to assign padding for encyption context");
		return 1;
	}
	
    
    if (EVP_PKEY_encrypt(ctx, NULL, (size_t*)cipher_text_length, plain_text, plain_text_length) <= 0){
		EVP_PKEY_CTX_free(ctx);
		fprintf(stderr, "Unable to find required buffer size");
		return 1;
	}

    *cipher_text = malloc(*cipher_text_length);
    if (!*cipher_text){
		fprintf(stderr, "Unable to allocate memory for cipher text");
		EVP_PKEY_CTX_free(ctx);
		return 1;
	}
	
    if (EVP_PKEY_encrypt(ctx, *cipher_text, (size_t*)cipher_text_length, plain_text, plain_text_length) <= 0){
		EVP_PKEY_CTX_free(ctx);
		free(*cipher_text);
		fprintf(stderr, "Unable to encrypt plain text");
		return 1;
	}

    EVP_PKEY_CTX_free(ctx);
    return 0;
	
}

int asymmetric_decrypt(EVP_PKEY *private_key, unsigned char *ciphertext, int ciphertext_len, unsigned char **plaintext, int *plaintext_len){
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (!ctx){
		fprintf(stderr, "Unable to allocate memory for context");
		return 1;
	}

    if (EVP_PKEY_decrypt_init(ctx) <= 0){
		EVP_PKEY_CTX_free(ctx);
		fprintf(stderr, "Unable to create a context for decryption");
		return 1;
	}

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0){
		EVP_PKEY_CTX_free(ctx);
		fprintf(stderr, "Unable to assign padding for decryption context");
		return 1;
	}

    if (EVP_PKEY_decrypt(ctx, NULL, (size_t*)plaintext_len, ciphertext, ciphertext_len) <= 0){
		EVP_PKEY_CTX_free(ctx);
		fprintf(stderr, "Unable to find required buffer size");
		return 1;
	}

    *plaintext = malloc(*plaintext_len);
    if (!*plaintext){
		fprintf(stderr, "Unable to allocate memory for plain text");
		EVP_PKEY_CTX_free(ctx);
		return 1;
	}

    if (EVP_PKEY_decrypt(ctx, *plaintext, (size_t*)plaintext_len, ciphertext, ciphertext_len) <= 0){
		EVP_PKEY_CTX_free(ctx);
		free(*plaintext);
		fprintf(stderr, "Unable to decrypt plain text");
		return 1;
	}

    EVP_PKEY_CTX_free(ctx);
    return 0;
}

void free_key_pair(EVP_PKEY* public_key, EVP_PKEY* private_key){
	EVP_PKEY_free(public_key);
	EVP_PKEY_free(private_key);
}

int make_symmetric_key(unsigned char* key, int key_size){
	if (RAND_bytes(key, key_size) !=1){
		fprintf(stderr, "error generating key");
		return 1;
	}
	return 0;
}

int generate_iv(unsigned char* iv, int iv_length){
	if (RAND_bytes(iv, iv_length) !=1){
		fprintf(stderr, "error generating iv");
		return 1;
	}
	return 0;
	
}

int symmetric_encrypt(unsigned char* plain_text, int plain_text_length, unsigned char* cipher_text, int* cipher_text_length, unsigned char* iv, unsigned char* key){	//key has to be 32 bytes and IV 16 bytes
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int len;
	if (!ctx){
		fprintf(stderr, "error creating context");
		return 1;
	}
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	
	EVP_EncryptUpdate(ctx, cipher_text, &len, plain_text, plain_text_length);
	*cipher_text_length = len;
	EVP_EncryptFinal_ex(ctx, cipher_text + len, &len);
	*cipher_text_length += len;
	
	EVP_CIPHER_CTX_free(ctx);
	
	return 0;
	
}

int symmetric_decrypt(unsigned char* plain_text, int* plain_text_length, unsigned char* cipher_text, int cipher_text_length, unsigned char* iv, unsigned char* key){
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int len;
	if (!ctx){
		fprintf(stderr, "error creating context");
		return 1;
	}
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	
	EVP_DecryptUpdate(ctx, plain_text, &len, cipher_text, cipher_text_length);
	*plain_text_length = len;
	EVP_DecryptFinal_ex(ctx, plain_text + len, &len);
	*plain_text_length += len;
	
	EVP_CIPHER_CTX_free(ctx);
	
	return 0;
	
}