/*
 * main.c
 *
 *  Created on: Jul 12, 2019
 *      Author: greendot
 *  socket_keyexchanger - server
 */

#include "main.h"

int main(int argc, char *argv[]){

	unsigned int server_port = atoi(argv[1]);
	int socket_server;
	int socket_client;
	int client_addr_size;

	// address structure
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;

	// up / down buffer
	char buff_rcv[BUF_SIZE];
	char buff_snd[BUF_SIZE];

	char flag_listen = 0;
	char flag_connect = 0;
	char flag_server = 0;

	// for time
	time_t time_now;
	struct tm *local;
	char timestring[8];
	FILE *fp;

	char time_filename[22];
	char msg_file_size[4] = {0,};
	unsigned char *buf = malloc(BUF_SIZE);

	unsigned char sessionkey[65] = {0,};

	unsigned char hash_local[65] = {0,};
	unsigned char hash_recv[65] = {0,};

	unsigned char sessionkey_encrypted[BUF_SIZE];

	int sessionkey_len=0;
	int sessionkey_encrypted_len=0;

	int data_bytes = 0;

	int downlod_count = 0;

	int secret_len = 0;
	int plain_len = 0;

	unsigned char secret[BUF_SIZE];
	unsigned char plain[BUF_SIZE];

	printf("#######################\n");
	printf("# CAN Logger - server #\n");
	printf("#######################\n");

	//// Parameter check
	if(argc < 2){
		fprintf(stderr,"usage %s [PORT]\n", argv[0]);
		return 1;
	}
	//// Key exist check
	printf("+) RSA key checking..\n");
	if(!((Exist_file(PRIKEY_NAME) && Exist_file(PUBKEY_NAME)))){
		// file doesn't exist
		printf("| RSA key not exists.!\n");
		pemGen_pri(PRIKEY_NAME);
		pemGen_pub(PRIKEY_NAME, PUBKEY_NAME);
		printf("| RSA key generated!\n");
	}else{
		// file exist
		printf("| RSA key already exists.!\n");
	}

	//// server start
	// socket()
	if(-1 == (socket_server = socket( PF_INET, SOCK_STREAM, 0))){
		printf("+) [error] Failed create server socket!\n");
		return -1;
	}
	// for bind error deny set
	int option = 1; // SO_REUSEADDR option = TRUE
	setsockopt(socket_server, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(server_port);
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	// bind()
	if(-1 == bind(socket_server, (struct sockaddr*)&server_addr, sizeof(server_addr))){
		printf("+) [error] Failed bind server!\n");
		return -1;
	}else{

		flag_server = 1;
		flag_listen = 1;
	}
	// loop server
	while(flag_server){
		// loop listen
		while(flag_listen){
			printf("+) Server listening...\n");
			printf("| IF YOU WANT EXIT SERVER, THEN PRESS CRTL + C!\n");
			printf("| Total Download: %d\n",downlod_count);
			// listen()
			if(-1 == listen(socket_server, 5)){
				printf("+) [error] Failed listen()!\n");
				return -1;
			}
			client_addr_size = sizeof(client_addr);

			// accept()
			if(-1 == (socket_client = accept(socket_server,(struct sockaddr*)&client_addr, &client_addr_size))){
				printf("+) [error] Failed accept()!\n");
				return -1;
			}else{
				time_now = time(0);
				local = localtime(&time_now);
				sprintf(timestring, "%02d:%02d:%02d", local->tm_hour, local->tm_min, local->tm_sec);
				printf("//////////////////////////////////////////\n");
				printf("[%s] %s:%d was connected.\n",timestring,inet_ntoa(client_addr.sin_addr),client_addr.sin_port);
				printf("//////////////////////////////////////////\n");
				flag_listen=0;
				flag_connect=1;
			}
		}
		// loop main
		while(flag_connect){
			//// Check pemkey
			printf("+) Run Keycheck.\n");
			// send <keycheck>
			memset(buff_snd,0,sizeof(buff_snd));
			strncpy(buff_snd, "/keycheck",BUF_SIZE);
			data_bytes=send(socket_client,buff_snd, strlen(buff_snd)+1,0);

			// receive message
			memset(buff_rcv,0,sizeof(buff_rcv));
			data_bytes=recv(socket_client, buff_rcv, BUF_SIZE,0);

			// if <keycheck-fail>
			if(strcmp(buff_rcv,"/keycheck-fail") == 0){
				printf("| Key check fail detection!\n");
				if((fp = fopen(PUBKEY_NAME,"r")) == NULL){
					printf("+) [error] File not exist!\n");
					break;
				}else{
					// file transmission to client
					// file size
					data_bytes = fread(buf, 1, BUF_SIZE, fp);
					printf("| File size: %d\n",data_bytes);

					*((int*)msg_file_size) = data_bytes;
					send(socket_client, msg_file_size, sizeof(msg_file_size),0);
					// file data
					data_bytes=send(socket_client, buf, BUF_SIZE,0);
					printf("| Sended data: %d\n",data_bytes);

					printf("| Transmission successful!\n");
					fflush(fp);
					fclose(fp);
				}
			}else if(strcmp(buff_rcv,"/keycheck-success") == 0){
				printf("| Client: file exist!\n");
			}
			printf("| Key check success!\n");

			//// Check pemkey MAC
			printf("+) Check key MAC\n");
			Gen_hash(PUBKEY_NAME,hash_local);
			printf("| Publickey SHA256: [%s]\n",hash_local);

			memset(buff_snd,0,sizeof(buff_snd));
			strncpy(buff_snd, hash_local,sizeof(hash_local));
			data_bytes=send(socket_client,buff_snd, BUF_SIZE,0);
			printf("| Sended bytes: %d\n",data_bytes);

			memset(buff_rcv,0,sizeof(buff_rcv));
			data_bytes=recv(socket_client, buff_rcv, BUF_SIZE,0);
			if(strcmp(buff_rcv,"/keymac-fail") == 0){
				printf("| keycheck fail detection!\n");
				break;
			}else if(strcmp(buff_rcv,"/keymac-success") == 0){
				printf("| keycheck success!\n");
			}

			//// Generation sessionkey
			printf("+) Generation sessionkey.\n");
			memset(buff_rcv,0,sizeof(buff_rcv));
			data_bytes=recv(socket_client, buff_rcv, BUF_SIZE,0);
			if(strcmp(buff_rcv,"/sessionkey") == 0){
				// session key generation
				printf("| Generating sessionkey...\n");
				sessionkey_len=Gen_aes256_sessionkey(sessionkey);
				printf("| Sessionkey: [%d] [%s]\n",sessionkey_len,sessionkey);

				// session key encryption
				printf("| Ecrypting sessionkey with pri.key\n");
				sessionkey_encrypted_len=rsa_encrypt(PRIKEY_NAME,sessionkey,strlen(sessionkey),sessionkey_encrypted);

				// send encrypted session key
				*((int*)msg_file_size) = sessionkey_encrypted_len;
				send(socket_client, msg_file_size, sizeof(msg_file_size),0);

				memset(buff_snd,0,sizeof(buff_snd));
				memcpy(buff_snd, sessionkey_encrypted,sessionkey_encrypted_len);
				data_bytes=send(socket_client,buff_snd, BUF_SIZE,0);

				// receive sessionkey ok sign
				memset(buff_rcv,0,sizeof(buff_rcv));
				data_bytes=recv(socket_client, buff_rcv, BUF_SIZE,0);
				if(strcmp(buff_rcv,"/sessionkey-success") == 0){
					printf("| Client received session key!\n");
				}
			}

			//// Download log file
			// send <uploadlogfile>
			memset(buff_snd,0,sizeof(buff_snd));
			strncpy(buff_snd, "/uploadlogfile",BUF_SIZE);
			data_bytes=send(socket_client,buff_snd, strlen(buff_snd)+1,0);

			// receive secret data size
			recv(socket_client,msg_file_size,sizeof(msg_file_size),0);
			secret_len = *((int*)msg_file_size);
			printf("| secret len: %d\n",secret_len);

			// receive secret data
			data_bytes=recv(socket_client,buff_rcv,BUF_SIZE,0);
			printf("| received data: %d\n",data_bytes);

			//// Decryption log file
			// decryption
			time_now = time(0);
			local = localtime(&time_now);
			sprintf(time_filename,"%02d%02d%02d-%02d%02d%02dout.log",local->tm_year%100,local->tm_mon,local->tm_mday, local->tm_hour, local->tm_min, local->tm_sec,timestring);
			plain_len = aes_decrypt(sessionkey,buff_rcv,secret_len,plain,time_filename);
			printf("| File created [%s]\n",time_filename);

			//// MAC verify
			Gen_hash(time_filename,hash_local);
			memset(buff_rcv,0,sizeof(buff_rcv));
			data_bytes = recv(socket_client,buff_rcv, BUF_SIZE,0);
			strncpy(hash_recv, buff_rcv,sizeof(hash_recv));
			printf("| client file hash: [%s]\n",hash_local);
			printf("| server file hash: [%s]\n",hash_recv);
			if(!(strcmp(hash_local,hash_recv) == 0)){

				// send <file-mac-failed>
				memset(buff_snd,0,sizeof(buff_snd));
				strncpy(buff_snd, "/file-mac-failed",BUF_SIZE);
				data_bytes=send(socket_client,buff_snd, strlen(buff_snd)+1,0);
				remove("out.log");
				printf("| Verification failed!\n");
			}else{
				// send <file-mac-success>
				memset(buff_snd,0,sizeof(buff_snd));
				strncpy(buff_snd, "/file-mac-success",BUF_SIZE);
				data_bytes=send(socket_client,buff_snd, strlen(buff_snd)+1,0);
				printf("| Verification success!\n");
				downlod_count++;
			}

			//// Return to listening
			printf("+) Client Socket close!\n");
			close(socket_client);
			flag_connect = 0;
			flag_listen = 1;

		}
		printf("+) Data download finished!\n");
	}
	// program clean
	close(socket_server);
	return 0;
}
