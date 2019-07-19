/*
 * main.c
 *
 *  Created on: Jul 9, 2019
 *      Author: greendot
 *      Generate sha256 Hash from input argv.
 */

// MD is 32bytes * 8 = 256bits

#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

void genSHA2(char *str){
	int i;
	unsigned char digest[SHA256_DIGEST_LENGTH];
	char hash_sha256[256] = {0};

	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, str, strlen(str));
	SHA256_Final(digest, &ctx);

	for(i=0;i<SHA256_DIGEST_LENGTH;++i)
		sprintf(hash_sha256+(i*2), "%02x",digest[i]);
	printf("+) Input string: %s\n+) SHA256: %s\nString length: %d\n",str,hash_sha256,strlen(str));
}

int main(int argc, char *argv[]){
	genSHA2(argv[1]);
	return 0;
}

