/*
 * main.c
 *
 *  Created on: Jul 12, 2019
 *      Author: greendot
 *  socket_echoserver - server
 */

#define BUF_SIZE 1024

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

int main(int argc, char *argv[]){
	if(argc < 2){
		fprintf(stderr,"usage %s [port]\n", argv[0]);
		return 1;
	}

	unsigned int server_port = atoi(argv[1]);

	int socket_server;
	int socket_client;
	int client_addr_size;

	// address structure
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;

	// up / down buffer
	char buff_rcv[BUF_SIZE+5];
	char buff_snd[BUF_SIZE+5];

	char flag_listen = 0;
	char flag_connect = 0;

	printf("THIS IS SERVER.\n");

	// socket()
	if(-1 == (socket_server = socket( PF_INET, SOCK_STREAM, 0))){
		printf("Failed create server socket!\n");
		return -1;
	}

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(server_port);
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	// bind()
	if(-1 == bind(socket_server, (struct sockaddr*)&server_addr, sizeof(server_addr))){
		printf("Failed bind()!\n");
		return -1;
	}else{
		flag_listen = 1;
	}
	while(flag_listen){
		printf("listening...\n");

		// listen()
		if(-1 == listen(socket_server, 5)){
			printf("Failed bind()!\n");
			return -1;
		}
		client_addr_size = sizeof(client_addr);

		// accept()
		if(-1 == (socket_client = accept(socket_server,(struct sockaddr*)&client_addr, &client_addr_size))){
			printf("Failed Connection!\n");
			return -1;
		}else{
			flag_listen=0;
			flag_connect=1;
		}
	}
	printf("%s:%d was connected.\n",inet_ntoa(client_addr.sin_addr),client_addr.sin_port);
	while(flag_connect){
		// read from client
		memset(buff_rcv,0,sizeof(buff_rcv));
		read(socket_client, buff_rcv, BUF_SIZE);

		// print buf
		printf("from %s: %s",inet_ntoa(client_addr.sin_addr),buff_rcv);
		buff_rcv[strlen(buff_rcv)-1] = '\0';
		if(strcmp(buff_rcv,"/quit") == 0){
			flag_connect = 0;
			break;
		}
		memset(buff_rcv,0,sizeof(buff_rcv));

		// input from me
		memset(buff_snd,0,sizeof(buff_snd));
		printf("Server: ");
		fgets(buff_snd,BUF_SIZE,stdin);

		// send to client
		write(socket_client, buff_snd, strlen(buff_snd)+1);	// +1 is NULL byte
		if(strcmp(buff_snd,"/quit") == 0){
			flag_connect = 0;
			break;
		}

		printf("\n");
		sprintf(buff_snd, "%d : %s\n", strlen(buff_rcv), buff_rcv);

	}
	close(socket_client);
	close(socket_server);
	return 0;
}
