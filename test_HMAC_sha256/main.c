/*
 * main.c
 *
 *  Created on: Jul 10, 2019
 *      Author: greendot
 */

# define BLOCK_SIZE 32		// 256bits

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>


int hmac_sha256(char *keyfile, char *datafile, unsigned char *hash){

	int i;
	const int bufSize = 32768;
	int bytesRead[2] = {0,0};
	unsigned char *digest;
	FILE *fp[2];
	unsigned char *buf[2];

	fp[0] = fopen(keyfile, "rb");
	fp[1] = fopen(datafile, "rb");

	for(int i=0;i<2;i++){
		if(!fp[i]) return 1;
		buf[i] = malloc(bufSize);
		if(!buf[i]) return 1;
		bytesRead[i] = fread(buf[i], 1, bufSize, fp[i]);
	}

	digest=HMAC(EVP_sha256(),
				buf[0],
				bytesRead[0],
				buf[1],
				bytesRead[1],
				NULL,
				NULL);

	for(i=0;i<SHA256_DIGEST_LENGTH;++i)
		sprintf(hash+(i*2), "%02x",digest[i]);

	for(int i=0;i<2;i++){
		fclose(fp[i]);
		free(buf[i]);
	}
}

int main(int argc, char *argv[]){

	unsigned char hash_sha256[64] = {0,};

	if(argc < 2){
		printf("Please input parameter.\n");
		printf("%s keyfile datafile\n",argv[0]);
		return 1;
	}
	printf("+) keyFile: %s\n",argv[1]);
	printf("+) Filename: %s\n",argv[2]);
	hmac_sha256(argv[1],argv[2],hash_sha256);
	printf("+) SHA256: %s\n",hash_sha256);


}


