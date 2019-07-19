/*
 * main.c
 *
 *  Created on: Jul 9, 2019
 *      Author: greendot
 *      Generate MD5 Hash from input argv.
 */

// MD is 16bytes * 8 = 128bits

#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>

void genMD5(char *str){
	int i;
	unsigned char digest[MD5_DIGEST_LENGTH];
	char hash_md5[128] = {0};

	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, str, strlen(str));
	MD5_Final(digest, &ctx);

	for(i=0;i<MD5_DIGEST_LENGTH;++i)
		sprintf(hash_md5+(i*2), "%02x",digest[i]);

	printf("+) Input string: %s\n+) MD5: %s\n",str,hash_md5);

}

int main(int argc, char *argv[]){
	genMD5(argv[1]);
	return 0;
}

