/*
 * subfunc.c
 *
 *  Created on: Jul 16, 2019
 *  Author: greendot
 *  paran_son@outlook.com
 */

#include "subfunc.h"

/* RSA key generation */
int Digi_GenPrikey(unsigned char *filename){

	FILE *fp = fopen(filename,"w");

	RSA *rsa = RSA_new();
	rsa = RSA_generate_key(2048,3,NULL,NULL);
	RSA_check_key(rsa);
	PEM_write_RSAPrivateKey(fp, rsa, NULL, 0, 0, NULL, NULL);


	RSA_free(rsa);
	fclose(fp);
	printf("| [%s] Private key generated.\n",filename);
	return 1;
}

/* create self-signed certification */
int Digi_SelfSign_crt(unsigned char *filename_pkey, unsigned char *filename_crt){

	EVP_PKEY *pkey = EVP_PKEY_new();

	RSA *rsa = RSA_new();
	X509_NAME *name = X509_NAME_new();
	X509 *crt= X509_new();

	FILE *fp1;
	FILE *fp2;
	fp1 = fopen(filename_pkey,"r");

	rsa = PEM_read_RSAPrivateKey(fp1, NULL, NULL, NULL);

	EVP_PKEY_assign_RSA(pkey, rsa);
	X509_set_version(crt, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(crt), 1);
	X509_gmtime_adj(X509_get_notBefore(crt), 0);
	X509_gmtime_adj(X509_get_notAfter(crt), 31536000L);

	X509_set_pubkey(crt, pkey);

	name = X509_get_subject_name(crt);

	X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"KR",        -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"MyCompany", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"ROOTCA", -1, -1, 0);

	X509_set_issuer_name(crt, name);
	X509_sign(crt, pkey, NULL);

	fp2 = fopen(filename_crt,"wb");
	PEM_write_X509(fp2, crt);

	RSA_free(rsa);
	EVP_PKEY_free(pkey);

	fclose(fp2);
	fclose(fp1);

	printf("| Self signed certificate [%s] generated.\n",filename_crt);
	return 1;

}

/* create csr from key */
int Digi_Create_csr(unsigned char *filename_pkey, unsigned char *nameCN, unsigned char *filename_csr){

	RSA *rsa = RSA_new();
	EVP_PKEY *pkey = EVP_PKEY_new();

	X509_REQ *csr = X509_REQ_new();
	X509_NAME *csr_name;

	FILE *fp1;
	FILE *fp2;
	fp1 = fopen(filename_pkey,"r");

	rsa = PEM_read_RSAPrivateKey(fp1, NULL, NULL, NULL);
	EVP_PKEY_assign_RSA(pkey, rsa);

	X509_REQ_set_version(csr, 0);
	X509_REQ_set_pubkey(csr, pkey);

	csr_name = X509_REQ_get_subject_name(csr);

	X509_NAME_add_entry_by_txt(csr_name, "C",  MBSTRING_ASC, (unsigned char *)"KR",        -1, -1, 0);
	X509_NAME_add_entry_by_txt(csr_name, "O",  MBSTRING_ASC, (unsigned char *)"MyCompany", -1, -1, 0);
	X509_NAME_add_entry_by_txt(csr_name, "CN", MBSTRING_ASC, (unsigned char *)nameCN, -1, -1, 0);

	X509_REQ_sign(csr, pkey, NULL);
	fp2 = fopen(filename_csr,"wb");
	PEM_write_X509_REQ(fp2, csr);

	printf("| Request certificate [%s] generated.\n",filename_csr);

	fclose(fp2);
	fclose(fp1);

	return 1;

}

/* create sigend from CA certification */
int Digi_CASign_crt(unsigned char *filename_csr,unsigned char *filename_CAkey,unsigned char *filename_CAcrt,unsigned char *filename_crt){

	EVP_PKEY *pkey = EVP_PKEY_new();
	X509_REQ *csr = X509_REQ_new();

	RSA *rsa = RSA_new();
	X509 *crt= X509_new();
	X509 *ca_crt = X509_new();;
	FILE *fp1;
	FILE *fp2;
	FILE *fp3;
	ca_crt = loadPemtoX509(filename_CAcrt);
	fp1 = fopen(filename_csr,"r");
	csr = PEM_read_X509_REQ(fp1,NULL,NULL,NULL);

	fp2 = fopen(filename_CAkey,"r");
	rsa = PEM_read_RSAPrivateKey(fp2, NULL, NULL, NULL);

	EVP_PKEY_assign_RSA(pkey, rsa);
	// init crt
	X509_set_version(crt, 2);
	X509_set_issuer_name(crt, X509_get_subject_name(ca_crt));
	X509_gmtime_adj(X509_get_notBefore(crt), 0);
	X509_gmtime_adj(X509_get_notAfter(crt), (long)1*365*3600);
	// adapt csr
	X509_set_subject_name(crt, X509_REQ_get_subject_name(csr));
	EVP_PKEY *req_pubkey = X509_REQ_get_pubkey(csr);
	X509_set_pubkey(crt, req_pubkey);
	EVP_PKEY_free(req_pubkey);

	X509_sign(crt, pkey, NULL);


	fp3 = fopen(filename_crt,"wb");
	PEM_write_X509(fp3, crt);

	printf("| Certificate [%s] generated.\n",filename_crt);

	fclose(fp3);
	fclose(fp2);
	fclose(fp1);
	return 1;
}


/* Verify certification from CA */
int Digi_ChainVerify_crt(unsigned char *filename_dev, unsigned char *filename_mid, unsigned char *filename_root){

	int stat = 0;
	// load root crt
	X509 *root_crt = loadPemtoX509(filename_root);
	EVP_PKEY *root_pkey = X509_get_pubkey(root_crt);

	// load mid crt
	X509 *mid_crt = loadPemtoX509(filename_mid);
	EVP_PKEY *mid_pkey = X509_get_pubkey(mid_crt);

	// load dev crt
	X509 *dev_crt = loadPemtoX509(filename_dev);

	stat = X509_verify(mid_crt,root_pkey);

	if(!stat){
		printf("| [ERR]: [%s] - [%s] Verify failed!\n",filename_root, filename_mid);
		exit(1);
	}else{
		printf("| [OK]: [%s] - [%s] Verify success!\n",filename_root, filename_mid);

	}

	stat = X509_verify(dev_crt,mid_pkey);

	if(!stat){
		printf("| [ERR]: [%s] - [%s] Verify failed!\n",filename_mid, filename_dev);
		exit(1);
	}else{
		printf("| [OK]: [%s] - [%s] Verify success!\n",filename_mid, filename_dev);
	}

	stat = X509_verify(root_crt,root_pkey);

	if(!stat){
		printf("| [ERR]: [%s] - [%s] Verify failed!\n",filename_root, filename_root);
		exit(1);
	}else{
		printf("| [OK]: [%s] - [%s] Verify success!\n",filename_root, filename_root);
	}

	EVP_PKEY_free(root_pkey);
	EVP_PKEY_free(mid_pkey);
	X509_free(root_crt);
	X509_free(mid_crt);
	X509_free(dev_crt);

	return stat;
}

/* Get certification info */
void Digi_ChainVerify_cn(unsigned char *filename_dev, unsigned char *filename_mid, unsigned char *filename_root){

	int i=0;
	X509_NAME *subjectName;
	X509_NAME *issuerName;

	char subjectCn[3][256];
	char issuerCn[3][256];

	X509 *crt[3];

	crt[0] = loadPemtoX509(filename_root);
	crt[1] = loadPemtoX509(filename_mid);
	crt[2] = loadPemtoX509(filename_dev);

	for(i=0;i<3;i++){
		subjectName = X509_get_subject_name(crt[i]);
		X509_NAME_get_text_by_NID(subjectName, NID_commonName, subjectCn[i], sizeof(subjectCn));

		issuerName = X509_get_issuer_name(crt[i]);
		X509_NAME_get_text_by_NID(issuerName, NID_commonName, issuerCn[i], sizeof(issuerCn));
		X509_free(crt[i]);

		if(i>0){
			if(strcmp(subjectCn[i-1],issuerCn[i]) == 0){
				printf("| [Depth %d] [%s(%s) => %s] CN Verify success!\n",i,issuerCn[i],subjectCn[i],subjectCn[i-1]);
			}else{
				printf("| [Depth %d] [%s(%s) => %s] CN Verify failed!\n",i,issuerCn[i],subjectCn[i],subjectCn[i-1]);
				exit(1);
			}
		}
	}

}

int Digi_ChainVerify_period(unsigned char *filename_root, unsigned char *filename_mid, unsigned char *filename_dev){

	int i=0;

	ASN1_TIME *period_start;
	ASN1_TIME *period_end;

	time_t time_now;

	X509 *crt[3];

	crt[0] = loadPemtoX509(filename_root);
	crt[1] = loadPemtoX509(filename_mid);
	crt[2] = loadPemtoX509(filename_dev);

	for(i=0;i<3;i++){
		time_now = time(0);
		localtime(&time_now);
		period_start = X509_get_notBefore(crt[i]);
		period_end = X509_get_notAfter(crt[i]);

		if(ASN1_TIME_cmp_time_t(period_start,time_now) == -1 &&
			ASN1_TIME_cmp_time_t(period_end,time_now) == 1){
			printf("| [%s] Fine! certificate is allowed!\n",filename_root);
		}else{
			printf("| [%s] Expired certificate is not allowed!\n",filename_root);
			exit(1);
		}

	}
	for(i=0;i<3;i++)
		X509_free(crt[i]);

	ASN1_TIME_free(period_start);
	ASN1_TIME_free(period_end);
}

/* mini function */
/* ===================================== */
/* ===================================== */

/* convert pem to X509 type */
static X509 *loadPemtoX509(unsigned char *filename){

	RSA *rsa = RSA_new();
	X509 *crt = X509_new();

	FILE *fp = fopen(filename,"r");
	crt = PEM_read_X509(fp, NULL, NULL, NULL);

	fclose(fp);
	return crt;

}

/* Convert ASN1TIME to str */
int convert_ASN1TIME(ASN1_TIME *t, char* buf, size_t len){
	int rc;
	BIO *b = BIO_new(BIO_s_mem());
	rc = ASN1_TIME_print(b, t);
	if (rc <= 0) {
		printf("ASN1_TIME_print failed or wrote no data.\n");
		BIO_free(b);
		return EXIT_FAILURE;
	}
	rc = BIO_gets(b, buf, len);
	if (rc <= 0) {
		printf("BIO_gets call failed to transfer contents to buf\n");
		BIO_free(b);
		return EXIT_FAILURE;
	}
	BIO_free(b);
	return EXIT_SUCCESS;
}


/* file exist check */
int Exist_file(char *filename){
	if(access(filename, F_OK) != -1)
		return 1;
	else
		return 0;
}
