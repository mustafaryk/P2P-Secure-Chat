#include <arpa/inet.h>  
#include <netinet/in.h>  
#include <stdio.h>  
#include <string.h>  
#include <sys/socket.h>  
#include <unistd.h>  
#include <signal.h>   
#include <stdlib.h>

fd_set all_sockets;				//these variables are global to help with helper functions
fd_set ready_read_sockets; 
int sfd;
int cfd = -1;
int client_request_limit = 100;
int max_client_queue = 5;

void connect_as_server(){		//we as a peer are connecting as a server (waiting for a client)
	struct sockaddr_in ca;
	socklen_t sinlen = sizeof(struct sockaddr_in);
	printf("Now waiting for connnection as a server.\n");
	cfd = accept(sfd, (struct sockaddr *)&ca, &sinlen);				//this is blocking, will wait untill a client comes to connect
	FD_SET(cfd, &all_sockets);
	char dot_notation[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(&ca)->sin_addr, dot_notation, INET_ADDRSTRLEN);
	printf("Success in connecting to client with IP address: %s | Port Number: %d\n", dot_notation, ntohs(ca.sin_port));
	return;
}

void connect_as_client(char* ip_address,int port_number){
	cfd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in ca;
    memset(&ca, 0, sizeof(struct sockaddr_in));      
    ca.sin_family = AF_INET;   
	ca.sin_port = htons(port_number);
	ca.sin_addr.s_addr = htonl(INADDR_ANY);

	if (inet_pton(AF_INET, ip_address, &ca.sin_addr) == 0){
		perror("That's not an IPv4 address");
		disconnect();
		return;
	}
	if (connect(cfd, (struct sockaddr *)&ca, sizeof(struct sockaddr_in)) == -1){
		printf("Error in trying to connect to server with IP address: %s and with port number: %d\n", ip_address, port_number);
		disconnect();
		return;
	}
	printf("Success in connecting to server with IP address: %s and with port number: %d\n", ip_address, port_number);
	FD_SET(cfd, &all_sockets);
	
}

int encrypt(char* buffer){
	return 0;
}
int decrypt(char* buffer){
	printf("Client: %s", buffer);
}

void disconnect(){
	printf("Client has disconnected.\n");
	FD_CLR(cfd, &all_sockets);
	close(cfd);
	cfd = -1;
}

void write_to_client(){           //helper function to write to our client  
    char message[1024];  
    if (fgets(message, sizeof(message), stdin) == NULL){     	//read message from standard input
		return;
    }  
	encrypt(message);
    if (write(cfd, message, strlen(message)) <= 0){			//client has stopped reading
		disconnect();
	}
}

void handle_client_data(){
	char buffer[128];   
	int condition = 0;  
	ssize_t total_bytes = 0;  
  
	while(condition == 0){  
		ssize_t bytes = read(cfd, &buffer[total_bytes], sizeof(buffer) - total_bytes);    //read whatever client wants to send  
		if (bytes <= 0 || bytes > client_request_limit || total_bytes > client_request_limit){       //naughty client trying to send more than 100 bytes or has closed on their end  
			disconnect();		//disconnect
			return;
		}  
		total_bytes = total_bytes + bytes;  
		buffer[total_bytes] = 0;                //null terminate our buffer as we will use string methods later on it  
		if (buffer[total_bytes - 1] == '\n'){           //last byte read has to be newline for us to know they have finished their request  
			condition = 1;  
		}  
	}
	
	//decrypt whatever request client sent  
	decrypt(buffer);	
	
}

  
int main(int argc, char **argv){
	if (argc < 2){  
        printf("Need port number for host\n");  
        return -1;  
    }
	if (argc == 3){  
        printf("Need port number for client\n");  
        return -1;  
    }

    sfd = socket(AF_INET, SOCK_STREAM, 0);
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
        perror("bind failed");  
        return -1;  
    }  
  
    if (listen(sfd, max_client_queue) == -1) {  
        perror("listen failed");  
        return -1;  
    }  
	
	if (argc >= 4){
		connect_as_client(argv[2] ,atoi(argv[3]));		//second argument is peer ip, third argument is peers port number
	}
  
    for(;;){		//loop
	
		ready_read_sockets = all_sockets;
		
		if (select(FD_SETSIZE, &ready_read_sockets, NULL, NULL, NULL) == -1){  
            perror("select failed for reading and writing");  
            return -1;  
        }
		
		if (cfd == -1){				//we dont have a peer
			connect_as_server();
		}
		
		if (FD_ISSET(cfd, &ready_read_sockets) && cfd != -1){				//peer has sent data
			handle_client_data();
		}
		
		if (FD_ISSET(STDIN_FILENO,  &ready_read_sockets) && cfd != -1){		//we have data ready to send to peer
			write_to_client();
		}
		
	}
}