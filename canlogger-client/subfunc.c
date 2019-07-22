/*
 * subfunc.c
 *
 *  Created on: Jul 16, 2019
 *      Author: greendot
 */

#include "main.h"

int rsa_encrypt(unsigned char *key, unsigned char *plain, int plain_len, unsigned char *secret){

	int res_len = 0;

	//// File load
	FILE *fp = fopen(key, "r");
	if(!fp){
		printf("+) [error] %s not exists!\n",key);
		return 1;
	}


	//// Read from fp to rsa_pkey
	RSA *rsa_pkey= RSA_new();
	rsa_pkey = PEM_read_RSAPrivateKey(fp, &rsa_pkey, NULL, NULL);

	//// Load pem key from file
	res_len = RSA_private_encrypt(plain_len,plain,secret,rsa_pkey,RSA_PKCS1_PADDING);

	//// clean
	fclose(fp);
	return res_len;
}
int rsa_decrypt(unsigned char *key, unsigned char *secret, int secret_len, unsigned char *plain){

	int res_len = 0;

	//// File load
	FILE *fp = fopen(key, "r");
	if(!fp){
		printf("+) [error] %s not exists!\n",key);
		return 1;
	}

	//// Read from fp to rsa_pkey
	RSA *rsa_pkey= RSA_new();
	rsa_pkey = PEM_read_RSAPublicKey(fp, &rsa_pkey, NULL, NULL);
	//// Load pem key from file
	res_len = RSA_public_decrypt(secret_len,secret,plain,rsa_pkey,RSA_PKCS1_PADDING);

	//// clean
	fclose(fp);
	return res_len;

}

int aes_encrypt(unsigned char *sessionkey, unsigned char *filename,unsigned char **secret){

	int i,j;
	unsigned char key[16];
	unsigned char iv[16];

	//const int bufSize = 32768;
	int filesize = 0;
	int bytesRead =0;
	unsigned char *buf;

	//// Parsing from sessionkey
	for (i = 0; i < 16; i++) {
		sscanf(sessionkey + 2*i, "%02x", &key[i]);
		//printf("%02x ", i, key[i]);
	}
	//printf("\n");
	for (i = 16; i < 32; i++) {
		sscanf(sessionkey + 2*i, "%02x", &iv[i-16]);
		//printf("%02x ", i, iv[i-16]);
	}
	//printf("\n");

	//// data File read
	FILE *fp;
	fp = fopen(filename, "rb");
	if(!fp){
		printf("+) [error] %s not exists!\n",filename);
		return -1;
	}

	fseek(fp, 0L, SEEK_END);
	filesize = ftell(fp);
	//set back to normal
	fseek(fp, 0L, SEEK_SET);

	buf = malloc(filesize);
	if(!buf){
		printf("+) [error] memory allocation error!\n");
		return -1;
	}
	*secret = malloc(filesize*2);
	if(!secret){
		printf("+) [error] memory allocation error!\n");
		return -1;
	}

	fread(buf,1,filesize, fp);//Read Entire File

	//// encryption precess
	EVP_CIPHER_CTX *ctx;
	int len1 = 0;
	int len2 = 0;
	int ciphertext_len=0;

	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_EncryptUpdate(ctx, *secret, &len1, buf, filesize);
	EVP_EncryptFinal_ex(ctx, *secret + len1, &len2);
	EVP_CIPHER_CTX_free(ctx);

	printf("%p\n",secret);
	printf("%d\n", len1+len2);

	//// clean
	free(buf);
	fclose(fp);
	return len1+len2;	// secret size
}

/* gen sha256 hash */
int Gen_hash(unsigned char *filename, unsigned char *hash_string){
	int i;
	unsigned char digest[SHA256_DIGEST_LENGTH];
	int bytesRead = 0;
	unsigned char *buf;
	const int bufsize = 32768;

	FILE *fp = fopen(filename, "r");
	if(!fp) return 1;

	printf("bufsize: %d\n", bufsize);
	buf = malloc(bufsize);
	if(!buf) return 1;


	SHA256_CTX ctx;
	SHA256_Init(&ctx);

	while((bytesRead = fread(buf, 1, bufsize, fp)))
	{
		printf("bytesRead: %d\n",bytesRead);
		SHA256_Update(&ctx, buf, bytesRead);
	}

	SHA256_Final(digest, &ctx);

	// put hash var from DIGEST
	for(i=0;i<SHA256_DIGEST_LENGTH;++i)
		sprintf(hash_string+(i*2), "%02x",digest[i]);


	fclose(fp);
	free(buf);
}

/* file exist check */
int Exist_file(char *filename){
	if(access(filename, F_OK) != -1)
		return 1;
	else
		return 0;
}
