/*
 * main.c
 *
 *  Created on: Jul 9, 2019
 *      Author: greendot
 */

// MD is 64bytes * 8 = 512bits

#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

void genSHA512(char *str){
	int i;
	unsigned char digest[SHA512_DIGEST_LENGTH];
	char hash_sha512[512] = {0};

	SHA512_CTX ctx;
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, str, strlen(str));
	SHA512_Final(digest, &ctx);

	for(i=0;i<SHA512_DIGEST_LENGTH;++i)
		sprintf(hash_sha512+(i*2), "%02x",digest[i]);
	printf("+) Input string: %s\n+) SHA512: %s\n",str,hash_sha512);

}

int main(int argc, char *argv[]){
	genSHA512(argv[1]);
	return 0;
}
