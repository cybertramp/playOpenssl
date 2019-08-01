/*
 * interface.h
 *
 *  Created on: Jul 24, 2019
 *      Author: greendot
 */

#include "subfunc/subfunc.h"

void m1_m1_createCert(void);
void m1_m2_create_rootCA(void);
void m1_m3_create_interCA(void);
void m1_m4_create_dev(void);

void m2_m1_createCerts(void);
void m2_m2_Verify_chain(void);
void m2_m3_Verify_CN(void);
void m2_m4_Verify_period(void);

