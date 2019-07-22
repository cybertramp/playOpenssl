/*
 * subfunc.c
 *
 *  Created on: Jul 16, 2019
 *  Author: greendot
 *  paran_son@outlook.com
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

		rsa = NULL;
		RSA_free(rsa);
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
		fclose(fp_pri);
		fclose(fp_pub);

	}

	return 1;
}

int rsa_encrypt(char *key, unsigned char *plain, int plain_len, unsigned char *secret){

	int res_len = 0;
	FILE *fp;

	// File load
	fp = fopen(key, "r");
	if(!fp){
		printf("+) [error] File error!\n");
		return 1;
	}
	// Read from fp to rsa_pkey
	RSA *rsa_pkey= RSA_new();
	rsa_pkey = NULL;
	//RSA *rsa_pkey;
	rsa_pkey = PEM_read_RSAPrivateKey(fp, &rsa_pkey, NULL, NULL);

	// Load pem key from file
	res_len = RSA_private_encrypt(plain_len,plain,secret,rsa_pkey,RSA_PKCS1_PADDING);

	// clean
	//RSA_free(rsa_pkey);
	fclose(fp);
	return res_len;
}
int rsa_decrypt(char *key, unsigned char *secret, int secret_len, unsigned char *plain){

	int res_len = 0;
	FILE *fp;

	// File load
	fp = fopen(key, "r");
	if(!fp){
		printf("+) [error] File error!\n");
		return 1;
	}

	// Read from fp to rsa_pkey
	RSA *rsa_pkey= RSA_new();
	rsa_pkey = NULL;
	rsa_pkey = PEM_read_RSAPublicKey(fp, &rsa_pkey, NULL, NULL);
	// Load pem key from file
	res_len = RSA_public_decrypt(secret_len,secret,plain,rsa_pkey,RSA_PKCS1_PADDING);

	// clean
	//memset(rsa_pkey, '\0',sizeof(rsa_pkey));
	RSA_free(rsa_pkey);
	fclose(fp);
	return res_len;

}

int aes_decrypt(unsigned char *sessionkey,unsigned char *filename, unsigned char *secret, int secret_len){

	int i=0;
	unsigned char key[16];
	unsigned char iv[16];

	unsigned char *buffer;
	int bytesRead = 0;

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
	FILE *fp = fopen(filename, "wb");
	if(!fp){
		printf("+) [error] %s not exists!\n",filename);
		return -1;
	}
	//// decryption from secret
	buffer = malloc(secret_len);
	EVP_CIPHER_CTX *ctx;
    int len1 = 0;
    int len2 = 0;
    int plaindata_len=0;

    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,key,iv);
    EVP_DecryptUpdate(ctx, buffer, &len1, secret, secret_len);
    EVP_DecryptFinal_ex(ctx, buffer + len1, &len2);

    EVP_CIPHER_CTX_free(ctx);

    //plaindata[secret_len] = '\0';
    plaindata_len = len1+len2;
    //// data File write

	bytesRead = fwrite(buffer, 1, plaindata_len, fp);
	//// clean
	free(buffer);
	fclose(fp);
    return plaindata_len;
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

	buf = malloc(bufsize);
	if(!buf) return 1;


	SHA256_CTX ctx;
	SHA256_Init(&ctx);

	while((bytesRead = fread(buf, 1, bufsize, fp)))
	{
		//printf("bytesRead: %d\n",bytesRead);
		SHA256_Update(&ctx, buf, bytesRead);
	}

	SHA256_Final(digest, &ctx);

	// put hash var from DIGEST
	for(i=0;i<SHA256_DIGEST_LENGTH;++i)
		sprintf(hash_string+(i*2), "%02x",digest[i]);

	memset(buf, '\0',sizeof(buf));
	free(buf);
	fclose(fp);
	return 1;
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
