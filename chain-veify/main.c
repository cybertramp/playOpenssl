/*
 * main.c
 *
 *  Created on: Jul 12, 2019
 *      Author: greendot
 *  socket_keyexchanger - client
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "interface.h"

int main(int argc, char *argv[]){

	int key=0;
	printf("\n#######################\n");
	printf("# Chain verifyer      #\n");
	printf("#######################\n\n");

	printf("+) Select\n");
	printf("| 1. Creation cert\n");
	printf("| 2. Verification cert\n");
	printf("| 3. Exit\n");
	printf("=) Choose: ");
	scanf("%d",&key);
	printf("\n");
	if(key == 1){
		key = 0;
		printf("+) Select\n");
		printf("| 1. One shot(2,3,4)\n");
		printf("| 2. Create RootCA Certificate\n");
		printf("| 3. Create IntermediateCA Certificate\n");
		printf("| 4. Create Device Certificate\n");
		printf("=) Choose: ");
		scanf("%d",&key);
		printf("\n");
		if(key == 1){
			m1_m1_createCerts();
		}else if(key == 2){
			m1_m2_create_rootCA();
		}else if(key == 3){
			m1_m3_create_interCA();
		}else if(key == 4){
			m1_m4_create_dev();
		}
	}else if(key == 2){
		key = 0;
		printf("+) Select verification\n");
		printf("| 1. One shot(2,3,4)\n");
		printf("| 2. Verify Certificate chain\n");
		printf("| 3. Verify Certificate CN\n");
		printf("| 4. Verify Certificate expiration\n");
		printf("=) Choose: ");
		scanf("%d",&key);
		printf("\n");
		if(key == 1){
			m2_m1_VerifyCerts();
		}else if(key == 2){
			m2_m2_Verify_chain();
		}else if(key == 3){
			m2_m3_Verify_CN();
		}else if(key == 4){
			m2_m4_Verify_period();
		}

	}else if(key == 3){
		printf("+) quit!\n");
	}else{
		key=0;
		printf("+) Wrong value.\n");
	}
	// program clean
	return 0;

}
