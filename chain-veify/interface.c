/*
 * interface.c
 *
 *  Created on: Jul 23, 2019
 *      Author: greendot
 */
#include "interface.h"

void m1_m1_createCerts(void){
	m1_m2_create_rootCA();
	m1_m3_create_interCA();
	m1_m4_create_dev();
	printf("+) Created rootCA interCA dev cert\n");
}

void m1_m2_create_rootCA(void){
	unsigned char *para[2] = {"root.key","root.crt"};
	Digi_GenPrikey(para[0]);
	Digi_SelfSign_crt(para[0],para[1]);
	printf("+) Created root cert\n");
}
void m1_m3_create_interCA(void){
	unsigned char *para[6] = {"mid.key","MID","mid.csr","root.key","root.crt","mid.crt"};
	Digi_GenPrikey(para[0]);
	Digi_Create_csr(para[0],para[1],para[2]);
	Digi_CASign_crt(para[2],para[3],para[4],para[5]);
	printf("+) Created inter cert\n");
}
void m1_m4_create_dev(void){
	unsigned char *para[6] = {"dev.key","DEV","dev.csr","mid.key","mid.crt","dev.crt"};
	Digi_GenPrikey(para[0]);
	Digi_Create_csr(para[0],para[1],para[2]);
	Digi_CASign_crt(para[2],para[3],para[4],para[5]);
	printf("+) Created dev cert\n");

}
void m2_m1_VerifyCerts(void){
	m2_m2_Verify_chain();
	m2_m3_Verify_CN();
	m2_m4_Verify_period();
	printf("+) Verified rootCA interCA dev cert\n");
}
void m2_m2_Verify_chain(void){
	unsigned char *para[3]= {"dev.crt","mid.crt","root.crt"};
	Digi_ChainVerify_crt(para[0],para[1],para[2]);
	printf("+) Success chain Verify certs!\n");
}
void m2_m3_Verify_CN(void){
	unsigned char *para[3]= {"dev.crt","mid.crt","root.crt"};
	Digi_ChainVerify_cn(para[0],para[1],para[2]);
	printf("+) Success CN Verify certs!\n");
}
void m2_m4_Verify_period(void){
	unsigned char *para[3]= {"dev.crt","mid.crt","root.crt"};
	Digi_ChainVerify_period("dev.crt","mid.crt","root.crt");
	printf("+) Success expired Verify certs!\n");
}

