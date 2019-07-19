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
	if(argc < 2){
		fprintf(stderr,"usage %s [keyfile] [datafile]\n", argv[0]);
		return 1;
	}
	unsigned char *iv = (unsigned char *)"0123456789012345";
	unsigned char ciphertext[128];
	unsigned char decryptedtext[128];

	int decryptedtext_len;
	int ciphertext_len;
	int i;
	const int bufSize = 32768;
	int bytesRead[2] = {0,0};
	FILE *fp[2];
	unsigned char *buf[2];

	for(i=0;i<2;++i){
		fp[i] = fopen(argv[i+1], "rb");
		if(!fp[i]) return 1;
		buf[i] = malloc(bufSize);
		if(!buf[i]) return 1;
		bytesRead[i] = fread(buf[i], 1, bufSize, fp[i]);
	}
	printf("+) Key(%d) is: %s\n",bytesRead[0],buf[0]);
	printf("+) Plaintext(%d) is: %s\n",bytesRead[1],buf[1]);
	printf("+) Ecrypting..\n");

	// buf[0] => key, buf[1] => msg

	ciphertext_len = encrypt (buf[1],bytesRead[1], buf[0], iv, ciphertext);
	printf("+) Ciphertext(%d) is: %s\n",ciphertext_len,ciphertext);

	printf("+) Decrypting..\n");
	decryptedtext_len = decrypt(ciphertext, ciphertext_len, buf[0], iv, decryptedtext);
	decryptedtext[decryptedtext_len] = '\0';
	printf("+) Decryptedtext(%d) is: %s\n",decryptedtext_len, decryptedtext);

	for(i=0;i<2;++i){
		fclose(fp[i]);
		free(buf[i]);
	}
	return 0;
}
