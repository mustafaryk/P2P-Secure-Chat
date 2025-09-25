#include <arpa/inet.h>  
#include <netinet/in.h>  
#include <stdio.h>  
#include <string.h>  
#include <sys/socket.h>  
#include <unistd.h>  
#include <signal.h>   
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include "encryption.h"
#include <openssl/ssl.h>


fd_set all_sockets;				//these variables are global to help with helper functions
fd_set ready_read_sockets;
fd_set ready_write_sockets;
int sfd;
int cfd;
int message_size_limit = 1024;
int max_client_queue = 5;

EVP_PKEY* your_public_key;
EVP_PKEY* your_private_key;
EVP_PKEY* their_public_key;
unsigned char* session_key;
unsigned char iv[16];

void disconnect(){
	printf("Peer has disconnected.\n");
	FD_CLR(cfd, &all_sockets);
	close(cfd);
	cfd = -1;
	printf("Waiting for connection as a server now, if you would like to connect type: \"CONNECT:IP_ADDRESS PORT_NUMBER\"\n");
}

int connect_as_server(){		//we as a peer are connecting as a server (waiting for a client)
	struct sockaddr_in ca;
	socklen_t sinlen = sizeof(struct sockaddr_in);
	cfd = accept(sfd, (struct sockaddr *)&ca, &sinlen);
	FD_SET(cfd, &all_sockets);
	
	unsigned char message[6] = "hello";
	unsigned char *pub_buf = NULL;
	int public_key_length = i2d_PUBKEY(your_public_key, &pub_buf); // DER encode

	if (public_key_length <= 0) {
		disconnect();
		fprintf(stderr, "Failed to encode public key");
		return 1;
	}

	uint32_t total_length = htonl(sizeof(message) + public_key_length);		//handshake algo
	write(cfd, &total_length, sizeof(total_length));
	write(cfd, message, sizeof(message));
	write(cfd, pub_buf, public_key_length);
	OPENSSL_free(pub_buf);
	
	uint32_t length_of_data;
	unsigned char data_sent[4096];
	unsigned char first_5_characters_and_null[6];
	read(cfd, &length_of_data, sizeof(length_of_data));
	read(cfd, first_5_characters_and_null, sizeof(first_5_characters_and_null));
	if (strcmp(first_5_characters_and_null, "hello") != 0){
		fprintf(stderr, "handshake algo went bad");
		disconnect();
		return 1;
	}
	
	int client_pub_len = length_of_data - sizeof(first_5_characters_and_null);
    unsigned char *client_pub_buf = malloc(client_pub_len);
    if (!client_pub_buf) {
        fprintf(stderr, "malloc failed");
        disconnect();
        return 1;
    }

    read(cfd, client_pub_buf, client_pub_len);

    const unsigned char *p = client_pub_buf;
    their_public_key = d2i_PUBKEY(NULL, &p, client_pub_len);
    free(client_pub_buf);
    if (!their_public_key) {
        fprintf(stderr, "Failed to decode client public key");
        disconnect();
        return 1;
    }
	
	session_key = calloc(32, sizeof(unsigned char));
	if(make_symmetric_key(session_key, 32) != 0){
		fprintf(stderr, "Couldnt generate symmetric key");
		disconnect();
		return 1;
	}
	
	unsigned char* cipher_symmetric_key;
	int cipher_symmetric_key_length;
	int session_key_length = 32*sizeof(unsigned char);
	if (asymmetric_encrypt(their_public_key, session_key, session_key_length, &cipher_symmetric_key, &cipher_symmetric_key_length) != 0){
		fprintf(stderr, "problem in assymetricly encrypting the session key");
		disconnect();
		return 1;
	}
	write(cfd, &cipher_symmetric_key_length, sizeof(cipher_symmetric_key_length));
	write(cfd, cipher_symmetric_key, cipher_symmetric_key_length);
	free(cipher_symmetric_key);
	
	char dot_notation[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(&ca)->sin_addr, dot_notation, INET_ADDRSTRLEN);

	printf("Success in connecting to client with IP address: %s and with port number: %d\nIf you would like to disconnect type: \"DISCONNECT\"\n", dot_notation, ntohs(ca.sin_port));
	
	return 0;
}

int connect_as_client(char* ip_address,int port_number){
	cfd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in ca;
    memset(&ca, 0, sizeof(struct sockaddr_in));      
    ca.sin_family = AF_INET;   
	ca.sin_port = htons(port_number);

	if (inet_pton(AF_INET, ip_address, &ca.sin_addr) == 0){
		fprintf(stderr, "Not an IPv4 address");
		disconnect();
		return 1;
	}
	if (connect(cfd, (struct sockaddr *)&ca, sizeof(struct sockaddr_in)) == -1){
		fprintf(stderr, "Error in connecting to server with IP address: %s and with port number: %d\n", ip_address, port_number);
		disconnect();
		return 1;
	}
	
	unsigned char message[6] = "hello";
	unsigned char *pub_buf = NULL;
	int public_key_length = i2d_PUBKEY(your_public_key, &pub_buf); // DER encode

	if (public_key_length <= 0) {
		disconnect();
		fprintf(stderr, "Failed to encode public key");
		return 1;
	}

	uint32_t total_length = htonl(sizeof(message) + public_key_length);		//handshake algo
	write(cfd, &total_length, sizeof(total_length));
	write(cfd, message, sizeof(message));
	write(cfd, pub_buf, public_key_length);
	OPENSSL_free(pub_buf);
	
	uint32_t length_of_data;
	unsigned char data_sent[4096];
	unsigned char first_5_characters_and_null[6];
	read(cfd, &length_of_data, sizeof(length_of_data));
	read(cfd, first_5_characters_and_null, sizeof(first_5_characters_and_null));
	if (strcmp(first_5_characters_and_null, "hello") != 0){
		fprintf(stderr, "handshake algo went bad");
		disconnect();
		return 1;
	}
	
	int client_pub_len = length_of_data - sizeof(first_5_characters_and_null);
    unsigned char *client_pub_buf = malloc(client_pub_len);
    if (!client_pub_buf) {
        fprintf(stderr, "malloc failed");
        disconnect();
        return 1;
    }

    read(cfd, client_pub_buf, client_pub_len);

    const unsigned char *p = client_pub_buf;
    their_public_key = d2i_PUBKEY(NULL, &p, client_pub_len);
    free(client_pub_buf);
    if (!their_public_key) {
        fprintf(stderr, "Failed to decode client public key");
        disconnect();
        return 1;
    }
	
	uint32_t length_encrypted_symmetric_key;
	read(cfd, &length_encrypted_symmetric_key, sizeof(length_encrypted_symmetric_key));
	unsigned char encrypted_symmetric_key[length_encrypted_symmetric_key];
	read(cfd, encrypted_symmetric_key, length_encrypted_symmetric_key);
	int temp;
	asymmetric_decrypt(your_private_key, encrypted_symmetric_key, length_encrypted_symmetric_key, &session_key, &temp);
	printf("Success in connecting to server with IP address: %s and with port number: %d,\nIf you would like to disconnect type: \"DISCONNECT\"\n", ip_address, port_number);
	FD_SET(cfd, &all_sockets);
	return 0;
}

void write_to_client(){           //helper function to write to our client  
    unsigned char message[message_size_limit];
	unsigned char encrypted_message[2048];
	int encrypted_message_length;
    if (fgets(message, sizeof(message), stdin) == NULL){     	//read message from standard input
		return;
    }
	if (strlen(message) == message_size_limit - 1){			// we also have null character at the end due to how fgets work
		fprintf(stderr, "Sending message longer than %d characters", message_size_limit - 1);
		return;
	}
	if (strcmp(message, "DISCONNECT\n") == 0){
		disconnect();
		return;
	}
	if (generate_iv(iv, sizeof(iv)) != 0){
		fprintf(stderr, " Error generating IV for encryption, message not sent\n");
		return;
	}
	
	if (symmetric_encrypt(message, strlen(message) + 1, encrypted_message, &encrypted_message_length, iv, session_key) != 0){		// also include null terminator
		fprintf(stderr, " Error symmetricaly encryting message, message not sent\n");
		return;
	}
	uint32_t total_length_message = encrypted_message_length;
    if (write(cfd, &encrypted_message_length, sizeof(encrypted_message_length)) <= 0 || (write(cfd, iv, sizeof(iv))) <= 0 || (write(cfd, encrypted_message, total_length_message)) <= 0){			//client has stopped reading
		disconnect();
		return;
	}
	
}

void handle_input(){
	char message[1024];
	char ip_address[32];
	char port_number[32];
    if (fgets(message, sizeof(message), stdin) == NULL){     	//read message from standard input
		return;
    }
	if (sscanf(message, "CONNECT:%s %s", ip_address, port_number) == 2){
		connect_as_client(ip_address, atoi(port_number));
		return;
	}
}

void handle_client_data(){
	unsigned char message[1028];
	int message_length;
	unsigned char encrypted_message[2048];
	int encrypted_message_length;
	
	if (read(cfd, &encrypted_message_length, sizeof(encrypted_message_length)) <=0 || read(cfd, iv, sizeof(iv)) <=0 || read(cfd, encrypted_message, encrypted_message_length) <= 0){
		disconnect();
		return;
	}
	if (symmetric_decrypt(message, &message_length, encrypted_message, encrypted_message_length, iv, session_key) != 0){
		fprintf(stderr," Error symmetricaly decrypting message, ask peer to resend message\n");
		return;
	}
	printf("PEER: %s", message);
	
}

  
int main(int argc, char **argv){
	OPENSSL_init_ssl(0, NULL);
	if (generate_key_pair(&your_public_key, &your_private_key) !=0){
		return 1;
	}
	
	cfd = -1;

	if (argc < 2){  
        fprintf(stderr, "Need port number for you to host on\n");  
        return -1;  
    }
	if (argc == 3){  
        fprintf(stderr, "Need port number of peer\n");  
        return -1;  
    }

    sfd = socket(AF_INET, SOCK_STREAM, 0);				//initializing ourselves as a server
    FD_ZERO(&all_sockets);
	FD_SET(STDIN_FILENO, &all_sockets);
    FD_SET(sfd, &all_sockets);  
  
    struct sigaction myaction;      //so that writing to disconnected peer doesnt end server  
    myaction.sa_handler = SIG_IGN;  
    sigaction(SIGPIPE, &myaction, NULL);  
  
	struct sockaddr_in a;
    memset(&a, 0, sizeof(struct sockaddr_in));      //preamble for setting up server down below  
    a.sin_family = AF_INET;  
    a.sin_port = htons(atoi(argv[1])); // first argument is your port number  
    a.sin_addr.s_addr = htonl(INADDR_ANY);  
  
    if (bind(sfd, (struct sockaddr *)&a, sizeof(struct sockaddr_in)) == -1){  
        fprintf(stderr, "bind failed");  
        return -1;  
    }  
  
    if (listen(sfd, max_client_queue) == -1){
        fprintf(stderr, "listen failed");  
        return -1;  
    }
	
	if (argc >= 4){
		connect_as_client(argv[2] , atoi(argv[3]));		//second argument is peer ip, third argument is peers port number
	}
	
	if (cfd == -1){
		printf("Waiting for connection as a server now, if you would like to connect type: \"CONNECT:IP_ADDRESS PORT_NUMBER\"\nIf you would like to disconnect type: \"DISCONNECT\"\n");
	}
	
    for(;;){		//loop
	
		ready_read_sockets = all_sockets;
		ready_write_sockets = all_sockets;
		
		if (select(FD_SETSIZE, &ready_read_sockets, NULL, NULL, NULL) == -1){  
            fprintf(stderr, "select failed for reading and writing");  
            return -1;  
        }
		
		if (FD_ISSET(sfd, &ready_read_sockets) && cfd == -1){
			connect_as_server();
		}
		
		if (FD_ISSET(cfd, &ready_read_sockets)){				//peer has sent data
			handle_client_data();
		}
		
		if (FD_ISSET(STDIN_FILENO,  &ready_read_sockets) && cfd == -1){		//we have some input for user
			handle_input();
		}
		
		if (FD_ISSET(STDIN_FILENO,  &ready_read_sockets) && cfd != -1){		//we have data ready to send to peer
			write_to_client();
		}
	}
}