/*
 * main.h
 *
 *  Created on: Jul 16, 2019
 *      Author: greendot
 */

#define BUF_SIZE 1024
#define FILE_BUF_SIZE 4096
#define PUBKEY_NAME "pub.key"
#define PRIKEY_NAME "pri.key"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//time
#include <time.h>

// socket
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

// pem
#include <openssl/pem.h>
#include <openssl/rand.h>

// rsa
#include <openssl/evp.h>
#include <openssl/rsa.h>

// functions
int pemGen_pri(unsigned char *filename);
int pemGen_pub(unsigned char *filename_pri, unsigned char *filename_pub);
int rsa_encrypt(unsigned char *key, unsigned char *plain, int plain_len, unsigned char *secret);
int rsa_decrypt(unsigned char *key, unsigned char *secret, int secret_len, unsigned char *plain);
int aes_encrypt(unsigned char *sessionkey, unsigned char *filename,unsigned char *secret);
int aes_decrypt(unsigned char *sessionkey, unsigned char *secret,int secret_len, unsigned char *plaindata,unsigned char *filename);
int Gen_hash(unsigned char *filename, unsigned char *hash_string);
int Gen_aes256_sessionkey(unsigned char *sessionkey);
int Exist_file(char *filename);
