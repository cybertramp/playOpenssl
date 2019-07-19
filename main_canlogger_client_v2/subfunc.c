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
	fflush(fp);
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
	fflush(fp);
	fclose(fp);
	return res_len;

}

int aes_encrypt(unsigned char *sessionkey, unsigned char *filename,unsigned char **secret){

	int i,j;
	unsigned char key[16];
	unsigned char iv[16];
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
	FILE *fp= fopen(filename, "rb");
	if(!fp){
		printf("+) [error] %s not exists!\n",filename);
		return -1;
	}

	// file size check
	fseek(fp, 0, SEEK_END);
	filesize = ftell(fp);

	buf = malloc(filesize);
	printf("filesize: %d\n",filesize);
	printf("secretfilesize: %d\n",(filesize + AES256_CBC_BLOCK_SIZE - filesize%AES256_CBC_BLOCK_SIZE));
	*secret = (unsigned char*)malloc(filesize + AES256_CBC_BLOCK_SIZE - (filesize%AES256_CBC_BLOCK_SIZE));
	if(*secret== NULL)
	{
		free(*secret);      /* this line is completely redundant */
		printf("\nERROR: Memory allocation did not complete successfully!");
	}
	if(!(buf)){
		printf("+) [error] memory allocation error!\n");
		return -1;
	}

	printf("allocation size: %d\n", filesize + AES256_CBC_BLOCK_SIZE - (filesize%AES256_CBC_BLOCK_SIZE));
	fseek(fp, 0, SEEK_SET);
	bytesRead = fread(buf, 1, filesize, fp);
	//// encryption precess
	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;
	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_EncryptUpdate(ctx, *secret, &len, buf, bytesRead);
	ciphertext_len = len;
	EVP_EncryptFinal_ex(ctx, *secret + len, &len);
	ciphertext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	printf("%p\n",*secret);
	//// clean
	free(buf);
	fflush(fp);
	fclose(fp);
	return ciphertext_len;
}



/* gen sha256 hash */
int Gen_hash(unsigned char *filename, unsigned char *hash_string){
	int i;
	unsigned char digest[SHA256_DIGEST_LENGTH];
	int bytesRead = 0;

	int filesize=0;

	FILE *file = fopen(filename, "r");
	if(!file) return 1;

	// file size check

	fseek(file, 0, SEEK_END);
	printf("asdf\n");
	filesize = ftell(file);


	printf("filesize: %d\n",filesize);
	unsigned char *buf = malloc(filesize);

	if(!buf) return 1;
	bytesRead = fread(buf, 1, filesize, file);

	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, buf, bytesRead);
	SHA256_Final(digest, &ctx);

	// put hash var from DIGEST
	for(i=0;i<SHA256_DIGEST_LENGTH;++i)
		sprintf(hash_string+(i*2), "%02x",digest[i]);
	fflush(file);
	fclose(file);
	free(buf);
}

/* file exist check */
int Exist_file(char *filename){
	if(access(filename, F_OK) != -1)
		return 1;
	else
		return 0;
}
