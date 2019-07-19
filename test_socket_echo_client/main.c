/*
 * main.c
 *
 *  Created on: Jul 12, 2019
 *      Author: greendot
 *  socket_echoserver - client
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
		fprintf(stderr,"usage %s [ip] [port]\n", argv[0]);
		return 1;
	}
	int socket_client;
	struct sockaddr_in server_addr;

	char buff_rcv[BUF_SIZE+5];
	char buff_snd[BUF_SIZE+5];

	unsigned char *server_ip = argv[1];
	unsigned int server_port = atoi(argv[2]);

	char flag_listen = 0;
	char flag_connect = 0;

	printf("THIS IS CLIENT.\n");

	if(-1 == (socket_client = socket(PF_INET, SOCK_STREAM,0))){
		printf("Failed create client socket!\n");
		return -1;
	}
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(server_port);
	server_addr.sin_addr.s_addr = inet_addr(server_ip);

	// connect()
	if(-1 == connect(socket_client, (struct sockaddr*)&server_addr, sizeof(server_addr))){
		printf("Failed bind()!\n");
		return -1;
	}else{
		printf("Connected to %s:%d\n",server_ip,server_port);
		flag_connect = 1;
	}


	while(flag_connect){
		// input from me
		memset(buff_snd,0,sizeof(buff_snd));
		printf("Client: ");
		fgets(buff_snd,BUF_SIZE,stdin);

		// send to server
		write(socket_client, buff_snd, strlen( buff_snd)+1);	// +1 is NULL byte
		if(strcmp(buff_snd,"/quit") == 0){
			flag_connect = 0;
			break;
		}
		printf("\n");
		sprintf(buff_snd, "%d : %s\n", strlen(buff_snd), buff_rcv);

		// read from server
		memset(buff_rcv,0,sizeof(buff_rcv));
		read(socket_client, buff_rcv, BUF_SIZE);

		// print buf
		printf("from %s: %s",inet_ntoa(server_addr.sin_addr),buff_rcv);
		buff_rcv[strlen(buff_rcv)-1] = '\0';
		if(strcmp(buff_rcv,"/quit") == 0){
			flag_connect = 0;
			break;
		}
		memset(buff_rcv,0,sizeof(buff_rcv));

	}

	close(socket_client);

	return 0;
}
