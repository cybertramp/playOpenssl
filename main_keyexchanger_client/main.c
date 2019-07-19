/*
 * main.c
 *
 *  Created on: Jul 12, 2019
 *      Author: greendot
 *  socket_keyexchanger - client
 */

#include "main.h"

int main(int argc, char *argv[]){

	unsigned char hash_local[65] = {0,};
	unsigned char hash_recv[65] = {0,};

	int data_bytes = 0;

	int socket_client;
	struct sockaddr_in server_addr;

	char buff_rcv[BUF_SIZE];
	char buff_snd[BUF_SIZE];

	unsigned char *server_ip = argv[1];
	unsigned int server_port = atoi(argv[2]);

	char flag_connect = 0;
	char flag_client = 0;

	// for time
	time_t time_now;
	struct tm *local;
	char timestring[8];
	FILE *fp;

	char msg_file_size[4] = {0,};
	int file_size=0;
	const int bufSize = BUF_SIZE;
	unsigned char *buf = malloc(bufSize);

	unsigned char sessionkey[65] = {0,};

	unsigned char sessionkey_encrypted[1024];
	unsigned char sessionkey_decrypted[1024];

	int sessionkey_len=0;
	int sessionkey_encrypted_len=0;
	int sessionkey_decrypted_len=0;

	int secret_len = 0;
	int plain_len = 0;
	unsigned char secret[1024];
	unsigned char plain[1024];

	printf("#######################\n");
	printf("# CAN Logger - client #\n");
	printf("#######################\n");

	//// Parameter check
	if(argc < 3){
		fprintf(stderr,"usage %s [IP] [PORT]\n", argv[0]);
		return 1;
	}
	//// Client start
	// socket()
	if(-1 == (socket_client = socket(PF_INET, SOCK_STREAM,0))){
		printf("+) [error] Failed create client socket!\n");
		return -1;
	}
	// set server address
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(server_port);
	server_addr.sin_addr.s_addr = inet_addr(server_ip);

	// connect()
	if(-1 == connect(socket_client, (struct sockaddr*)&server_addr, sizeof(server_addr))){
		printf("+) [error] Failed connect server!\n");
		return -1;
	}else{
		time_now = time(0);
		local = localtime(&time_now);
		sprintf(timestring, "%02d:%02d:%02d", local->tm_hour, local->tm_min, local->tm_sec);

		printf("//////////////////////////////////////////\n");
		printf("[%s] Connected to %s:%d\n",timestring,server_ip,server_port);
		printf("//////////////////////////////////////////\n");
		flag_client = 1;
		flag_connect = 1;

	}
	// loop client
	while(flag_client){
		// loop main
		while(flag_connect){
			//// Get pemkey from server
			printf("+) Get Key from server.\n");
			memset(buff_rcv,0,sizeof(buff_rcv));
			data_bytes = recv(socket_client, buff_rcv, BUF_SIZE,0);
			if(strcmp(buff_rcv,"/keycheck") == 0){
				printf("| key check request detection!\n");
				if(!(Exist_file(PUBKEY_NAME))){
					printf("| public key is not exist!\n");
					// send <keycheck-fail>
					memset(buff_snd,0,sizeof(buff_snd));
					strncpy(buff_snd, "/keycheck-fail",BUF_SIZE);
					send(socket_client, buff_snd, strlen(buff_snd)+1,0);

					// receive pub key
					printf("| Key download start!\n");

					// file size
					recv(socket_client,msg_file_size,sizeof(msg_file_size),0);
					file_size = *((int*)msg_file_size);

					printf("| File size: %d\n",file_size);

					if((fp = fopen(PUBKEY_NAME,"wb")) == NULL){
						printf("+) [error] File not exist!\n");
						break;
					}else{
						data_bytes=recv(socket_client,buf,BUF_SIZE,0);
						printf("| Sended data: %d\n",data_bytes);
						fwrite(buf,1,file_size,fp);
					}
					fclose(fp);
					printf("| Key download ended!\n");
				}else{
					// send <keycheck-success>
					memset(buff_snd,0,sizeof(buff_snd));
					strncpy(buff_snd, "/keycheck-success",BUF_SIZE);
					send(socket_client, buff_snd, BUF_SIZE,0);
					printf("| Already keyfile exist!\n");
				}
			}

			//// Verify pemkey MAC
			printf("+) Verify key MAC\n");
			memset(buff_rcv,0,sizeof(buff_rcv));
			data_bytes = recv(socket_client,buff_rcv, BUF_SIZE,0);
			strncpy(hash_recv, buff_rcv,sizeof(hash_recv));
			Gen_hash(PUBKEY_NAME,hash_local);
			printf("| keyfile verifying\n");
			printf("| client key hash: [%s]\n",hash_local);
			printf("| server key hash: [%s]\n",hash_recv);
			if(!(strcmp(hash_local,hash_recv) == 0)){
				memset(buff_snd,0,sizeof(buff_snd));
				strncpy(buff_snd, "/keymac-fail",BUF_SIZE);
				send(socket_client, buff_snd, BUF_SIZE,0);
				printf("| Verification failed!\n");
				if(remove(PUBKEY_NAME)){
					printf("| Success delete!\n");
				}else{
					printf("| Failed delete!\n");
					printf("| Restart !\n");
					break;
				}
				printf("| %s file deleted.\n",PUBKEY_NAME);
				printf("| Restart !\n");
				break;
			}else{
				memset(buff_snd,0,sizeof(buff_snd));
				strncpy(buff_snd, "/keymac-success",BUF_SIZE);
				send(socket_client, buff_snd, BUF_SIZE,0);
				printf("| Verification success!\n");
			}

			//// Get sessionkey
			// send <sessionkey>
			printf("+) Request sessionkey to server.\n");
			memset(buff_snd,0,sizeof(buff_snd));
			strncpy(buff_snd, "/sessionkey",BUF_SIZE);
			send(socket_client, buff_snd, BUF_SIZE,0);
			printf("| Downloading encrypted sessionkey to server.\n");
			// get msg size
			recv(socket_client,msg_file_size,sizeof(msg_file_size),0);
			sessionkey_encrypted_len = *((int*)msg_file_size);

			// get msg
			memset(buff_rcv,0,sizeof(buff_rcv));
			data_bytes = recv(socket_client,buff_rcv, BUF_SIZE,0);

			// session key decryption
			sessionkey_len=rsa_decrypt(PUBKEY_NAME,buff_rcv,sessionkey_encrypted_len,sessionkey_decrypted);
			memcpy(sessionkey,sessionkey_decrypted,sessionkey_len);
			printf("| sessionkey: [%d] [%s]\n",sessionkey_len,sessionkey);

			// transmission session key success
			printf("| Get sessionkey success!\n");

			memset(buff_snd,0,sizeof(buff_snd));
			strncpy(buff_snd, "/sessionkey-success",BUF_SIZE);
			send(socket_client, buff_snd, BUF_SIZE,0);

			//// Encryption log file
			printf("+) Encrypting log file!\n");
			// log file encryption
			secret_len = aes_encrypt(sessionkey,"can.log",secret);

			//// Upload encrypted log file
			// receive <uploadlogfile>
			printf("+) Send ecryption data!\n");
			memset(buff_rcv,0,sizeof(buff_rcv));
			data_bytes = recv(socket_client, buff_rcv, BUF_SIZE,0);
			if(strcmp(buff_rcv,"/uploadlogfile") == 0){
				// Transmission file data size
				*((int*)msg_file_size) = secret_len;
				send(socket_client, msg_file_size, sizeof(msg_file_size),0);
				printf("| secret len: %d\n",secret_len);

				// Transmission file data
				data_bytes=send(socket_client, secret, BUF_SIZE,0);
				printf("| sended data: %d\n",data_bytes);

				//// Transmission log file MAC
				Gen_hash("can.log",hash_local);
				memset(buff_snd,0,sizeof(buff_snd));
				strncpy(buff_snd, hash_local,sizeof(hash_local));
				data_bytes=send(socket_client,buff_snd, BUF_SIZE,0);
				printf("| Local log file hash: [%s]\n",hash_local);

				// receive <uploadlogfile>
				memset(buff_rcv,0,sizeof(buff_rcv));
				data_bytes = recv(socket_client, buff_rcv, BUF_SIZE,0);
				if(strcmp(buff_rcv,"/file-mac-failed") == 0){
					printf("| MAC Verify failed.\n");
				}else if(strcmp(buff_rcv,"/file-mac-success") == 0){
					printf("| MAC Verify success.\n");
				}

			}
			printf("+) Client Socket close!\n");
			//// Exit Program
			close(socket_client);
			flag_connect = 0;
			flag_client = 0;
		}
		printf("+) Data upload finished!\n");
	}
	// program clean
	return 0;

}
