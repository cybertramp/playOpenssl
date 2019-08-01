/*
 * main.h
 *
 *  Created on: Jul 16, 2019
 *      Author: greendot
 */

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

#include <openssl/err.h>

// functions
int Digi_GenPrikey(unsigned char *filename);
int Digi_SelfSign_crt(unsigned char *filename_pkey, unsigned char *filename_crt);
int Digi_Create_csr(unsigned char *filename_pkey, unsigned char *nameCN, unsigned char *filename_csr);
int Digi_CASign_crt(unsigned char *filename_csr,unsigned char *filename_CAkey,unsigned char *filename_CAcrt,unsigned char *filename_crt);
int Digi_ChainVerify_crt(unsigned char *filename_dev, unsigned char *filename_mid, unsigned char *filename_root);
void Digi_ChainVerify_cn(unsigned char *filename_dev, unsigned char *filename_mid, unsigned char *filename_root);
int Digi_ChainVerify_period(unsigned char *filename_root, unsigned char *filename_mid, unsigned char *filename_dev);

static X509 *loadPemtoX509(unsigned char *filename);
int convert_ASN1TIME(ASN1_TIME *t, char* buf, size_t len);
int Exist_file(char *filename);
