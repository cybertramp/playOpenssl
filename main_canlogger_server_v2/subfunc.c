/*
 * subfunc.c
 *
 *  Created on: Jul 16, 2019
 *      Author: greendot
 */

#include "main.h"

/* private pem key generation */
int pemGen_pri(unsigned char *filename){

	RSA *rsa = RSA_new();

	FILE *fp = fopen(filename,"w");

	if(!(rsa = RSA_generate_key(2048,3,NULL,NULL))){
		printf("+) [error] Generate RSA key failed.\n");
		return -1;
	}else{
		printf("| RSA key generated!\n");
	}

	if(RSA_check_key(rsa) < 1){
		printf("+) [error] Check RSA key failed.\n");
		return -1;
	}else{
		printf("| RSA key checked!\n");
	}

	if(!PEM_write_RSAPrivateKey(fp, rsa, NULL, 0, 0, NULL, NULL)){
		printf("+) [error] Write RSA key to pem failed.\n");
	    return -1;
	}else{
		printf("| Write successful!\n| File name: %s\n",filename);
		RSA_free(rsa);
		fflush(fp);
		fclose(fp);
	}
	return 1;
}

/* public pem key generation */
int pemGen_pub(unsigned char *filename_pri, unsigned char *filename_pub){

	RSA *rsa = RSA_new();
	FILE *fp_pri = fopen(filename_pri,"r");
	FILE *fp_pub = fopen(filename_pub,"w");

	if(!PEM_read_RSAPrivateKey(fp_pri, &rsa, NULL, NULL)){

	}else{
		printf("| RSA key read!\n");
	}
	if(!PEM_write_RSAPublicKey(fp_pub,rsa)){

	}else{
		printf("| Write successful!\n| File name: %s\n",filename_pub);
		RSA_free(rsa);
		fflush(fp_pri);
		fflush(fp_pub);
		fclose(fp_pri);
		fclose(fp_pub);
	}
	return 1;
}

int rsa_encrypt(unsigned char *key, unsigned char *plain, int plain_len, unsigned char *secret){

	int res_len = 0;
	FILE *fp;

	// File load
	fp = fopen(key, "r");
	if(!fp){
		printf("file error!\n");
		return 1;
	}

	// Read from fp to rsa_pkey
	RSA *rsa_pkey= RSA_new();
	rsa_pkey = PEM_read_RSAPrivateKey(fp, &rsa_pkey, NULL, NULL);

	// Load pem key from file
	res_len = RSA_private_encrypt(plain_len,plain,secret,rsa_pkey,RSA_PKCS1_PADDING);
	// clean
	fflush(fp);
	fclose(fp);
	return res_len;
}
int rsa_decrypt(unsigned char *key, unsigned char *secret, int secret_len, unsigned char *plain){

	int res_len = 0;
	FILE *fp;

	// File load
	fp = fopen(key, "r");
	if(!fp){
		printf("file error!\n");
		return 1;
	}

	// Read from fp to rsa_pkey
	RSA *rsa_pkey= RSA_new();
	rsa_pkey = PEM_read_RSAPublicKey(fp, &rsa_pkey, NULL, NULL);
	// Load pem key from file
	res_len = RSA_public_decrypt(secret_len,secret,plain,rsa_pkey,RSA_PKCS1_PADDING);

	// clean
	fflush(fp);
	fclose(fp);
	return res_len;

}



int aes_decrypt(unsigned char *sessionkey, unsigned char *secret,int secret_len, unsigned char **plaindata,unsigned char *filename){

	int i,j;
	unsigned char key[16];
	unsigned char iv[16];

	const int bufSize = 32768;
	int bytesRead;
	unsigned char *tmp = (unsigned char *)malloc(secret_len);

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

	//// decryption from secret
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaindata_len;

    ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    EVP_DecryptUpdate(ctx, tmp, &len, secret, secret_len);

    plaindata_len = len;
    EVP_DecryptFinal_ex(ctx, tmp + len, &len);
    plaindata_len += len;
    EVP_CIPHER_CTX_free(ctx);
    tmp[plaindata_len] = '\0';
    *plaindata = malloc(plaindata_len);
    memcpy(*plaindata,tmp,plaindata_len);

    //// data File write
	FILE *fp = fopen(filename, "wb");
	if(!fp){
		printf("+) [error] %s not exists!\n",filename);
		return -1;
	}
	bytesRead = fwrite(*plaindata, plaindata_len, 1, fp);
	printf("%p\n",*plaindata);
	//// clean
	free(tmp);
	fflush(fp);
	fclose(fp);
    return plaindata_len;
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

	printf("????\n");
	if(fseek(file, 0, SEEK_END)){
		printf("fseek error\n");
	}
	printf("????\n");
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
	free(buf);
	fclose(file);
}

/* gen aes256 session key */
int Gen_aes256_sessionkey(unsigned char *sessionkey){
	int i;
	unsigned char key[16];
	RAND_bytes(key, sizeof(key));

	unsigned char iv[16];
	RAND_bytes(iv, sizeof(iv));
	for (i = 0; i < 16; i++){
		sprintf(sessionkey + 2*i, "%02x", key[i]);
		//printf("%02x ", i, key[i]);
	}
	//printf("\n");
	for (i = 16; i < 32; i++){
		sprintf(sessionkey + 2*i, "%02x", iv[i-16]);
		//printf("%02x ", i, iv[i-16]);
	}
	//printf("\n");
	sessionkey[64] = '\0';
	return strlen(sessionkey);
}

/* file exist check */
int Exist_file(char *filename){
	if(access(filename, F_OK) != -1)
		return 1;
	else
		return 0;
}
