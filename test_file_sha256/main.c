/*
 * main.c
 *
 *  Created on: Jul 10, 2019
 *      Author: greendot
 */

# define BLOCK_SIZE 32		// 256bits

#include <stdio.h>
#include <openssl/sha.h>

int genSHA2file(char *filename,unsigned char *hash){

	int i;
	unsigned char digest[SHA256_DIGEST_LENGTH];
	int bytesRead = 0;

	FILE *fp = fopen(filename, "rb");
	if(!fp) return 1;

	const int bufSize = 32768;
	unsigned char *buf = malloc(bufSize);
	if(!buf) return 1;
	bytesRead = fread(buf, 1, bufSize, fp);

	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, buf, bytesRead);
	SHA256_Final(digest, &ctx);

	// put hash var from DIGEST
	for(i=0;i<SHA256_DIGEST_LENGTH;++i)
		sprintf(hash+(i*2), "%02x",digest[i]);

	fclose(fp);
	free(buf);
}

int main(int argc, char *argv[]){
	//
	unsigned char hash_sha256[64] = {0,};

	if(argc < 2){
		printf("Please input parameter.\n");
		return 1;
	}

	printf("+) Filename: %s\n",argv[1]);
	genSHA2file(argv[1],hash_sha256);
	printf("+) SHA256: %s\n",hash_sha256);


}


