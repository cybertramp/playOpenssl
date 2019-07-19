/*
 * main.c
 *
 *  Created on: Jul 10, 2019
 *      Author: greendot
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <openssl/des.h>
#include <openssl/rand.h>

void keygen(DES_cblock k){

	int i;

	DES_cblock seed = {0x00,};

	// random seed gen
	srand((unsigned int) time(0) + getpid());
	printf("seed: ");
	for(i=0;i<8;++i){
		seed[i] = rand()%256;	// 0~255
		printf("%02x ",(seed[i]));
	}
	printf("\n");
	// set random seed
	RAND_seed(seed, sizeof(DES_cblock));
	DES_random_key(k);

}

void encrypt(DES_cblock k, unsigned char *buf){

	int i;
	unsigned char out[64];
	DES_key_schedule keysched;

	DES_set_key((DES_cblock *)k, &keysched);
	DES_ecb_encrypt((DES_cblock *)buf,(DES_cblock *)out, &keysched, DES_ENCRYPT);

	strcpy(buf, out);

}

void decrypt(DES_cblock k, unsigned char *buf){

	int i;
	unsigned char out[64];
	DES_key_schedule keysched;

	DES_set_key((DES_cblock *)k, &keysched);
	DES_ecb_encrypt((DES_cblock *)buf,(DES_cblock *)out, &keysched, DES_DECRYPT);

	strcpy(buf, out);

}

int main(int argc, char *argv[]){
	if(8<strlen(argv[1])){
		printf("Overflow message size!(over 8bytes)\n");
		return -1;
	}
	int t;

	unsigned char buf[64];
	strcpy(buf, argv[1]);
	int bytesRead = 0;

	DES_cblock key = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

	if(argc < 2){
		printf("Please input parameter.\n");
		return -1;
	}

	// create key
	printf("+) Key generating..\n");
	keygen(key);
	printf("RealKey: ");
	for(t=0;t<8;++t)
		printf("%02x ",(key[t]));
	printf("\n");

	// print plain
	printf("Plain text: ");
	for(t=0;t<8;++t)
		printf("%02x ",(buf[t]));
	printf("(%s)\n",buf);

	// encrypt
	printf("+) Encrypting..\n");
	encrypt(key,buf);
	printf("Encrypted data: ");
	for(t=0;t<8;++t)
		printf("%02x ",(buf[t]));
	printf("(%s)\n",buf);

	// decrypt
	printf("+) Decrypting..\n");
	decrypt(key,buf);
	printf("Decrypted data: ");
	for(t=0;t<8;++t)
		printf("%02x ",(buf[t]));
	printf("(%s)\n",buf);

	return 0;
}
