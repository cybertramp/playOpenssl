/*
 * main.c
 *
 *  Created on: Jul 11, 2019
 *      Author: greendot
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
        	unsigned char *iv, unsigned char *ciphertext){
	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;

	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
	ciphertext_len = len;

	EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
	ciphertext_len += len;
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int main(int argc, char *argv[]){

	unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
	unsigned char *iv = (unsigned char *)"0123456789012345";
	unsigned char *plaintext =(unsigned char *)"The quick brown fox jumps over the lazy dog";
	unsigned char ciphertext[128];
	unsigned char decryptedtext[128];

	int decryptedtext_len;
	int ciphertext_len;

	printf("+) Password: %s\n",key);
	printf("+) IV: %s\n",iv);
	printf("+) Plain text: %s\n",plaintext);
	ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv, ciphertext);
	printf("+) Ciphertext(%d) is: %s\n",ciphertext_len,ciphertext);

	decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
	decryptedtext[decryptedtext_len] = '\0';
	printf("+) Decryptedtext(%d) is: %s\n",decryptedtext_len, decryptedtext);

	return 0;

}
