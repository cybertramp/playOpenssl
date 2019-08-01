/*
 * main.c
 *
 *  Created on: Jul 12, 2019
 *      Author: greendot
 */

#define MAX_FILE_SIZE 4096

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

int encrypt(unsigned char *keyfile, unsigned char *plainfile, unsigned char *encrypted, int secret_len){

	const int bufSize = 32768;
	int bytesRead = 0;
	FILE *fp[3];
	unsigned char *buf;

	// File load
	fp[0] = fopen(keyfile, "rb");
	fp[1] = fopen(plainfile, "rb");
	if(!(fp[0] || fp[1])) return 1;
	buf = malloc(bufSize);
	if(!buf) return 1;
	bytesRead = fread(buf, 1, bufSize, fp[1]);

	// Read from fp[1] to rsa_pkey
	RSA *rsa_pkey= RSA_new();
	rsa_pkey = PEM_read_RSA_PUBKEY(fp[0], &rsa_pkey, NULL, NULL);

	// Load pem key from file
	secret_len = RSA_public_encrypt(bytesRead,buf,encrypted,rsa_pkey,RSA_PKCS1_PADDING);

	// File write
	fp[2] = fopen(plainfile, "rb");

	// clean
	fclose(fp[0]);
	fclose(fp[1]);
	free(buf);
	return secret_len;
}

int decrypt(unsigned char *keyfile, unsigned char *secretfile, unsigned char *decrypted, int plaintext_len){

	const int bufSize = 32768;
	int bytesRead = 0;
	FILE *fp[2];
	unsigned char *buf;

	// File load
	fp[0] = fopen(keyfile, "rb");
	fp[1] = fopen(secretfile, "rb");
	if(!(fp[0] || fp[1])) return 1;
	buf = malloc(bufSize);
	if(!buf) return 1;
	bytesRead = fread(buf, 1, bufSize, fp[1]);

	// Read from fp[1] to rsa_pkey
	RSA *rsa_pkey= RSA_new();
	rsa_pkey = PEM_read_RSAPrivateKey(fp[0], &rsa_pkey, NULL, NULL);

	// Load pem key from file
	plaintext_len = RSA_private_decrypt(bytesRead,buf,decrypted,rsa_pkey,RSA_PKCS1_PADDING);

	// clean
	fclose(fp[0]);
	fclose(fp[1]);
	free(buf);
	return plaintext_len;

}

int main(int argc, char *argv[]){
	int plainlen=0;
	int secretlen=0;
	unsigned char plain[MAX_FILE_SIZE];
	unsigned char secret[MAX_FILE_SIZE];

	FILE *file;

	if(argc < 2){
		fprintf(stderr,"usage %s [option] [keyfile] [datafile] [outfile]\n", argv[0]);
		printf("-c: encryption\n");
		printf("-d: decryption\n");
		return 1;
	}


	if(strcmp(argv[1], "-e")==0){	// encryption
		printf("+) Encryption!\n");
		secretlen = encrypt(argv[2],argv[3],secret,secretlen);
		printf("Secret(%dbytes): %s\n", secretlen,secret);

		file = fopen(argv[4],"wb");
		fwrite(secret,secretlen,1,file);
		fclose(file);

	}
	if(strcmp(argv[1], "-d")==0){	// decryption
		printf("+) Decryption!\n");
		plainlen = decrypt(argv[2],argv[3],plain,plainlen);
		printf("Plain(%dbytes): %s\n", plainlen,plain);

		file = fopen(argv[4],"wb");
		fwrite(plain,plainlen,1,file);
		fclose(file);
	}
	return 0;
}
