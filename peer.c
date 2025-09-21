#include <arpa/inet.h>  
#include <netinet/in.h>  
#include <stdio.h>  
#include <string.h>  
#include <sys/socket.h>  
#include <unistd.h>  
#include <signal.h>   
#include <stdlib.h>

fd_set all_sockets;
fd_set ready_read_sockets; 
fd_set ready_write_sockets;
int sfd;
int cfd = -1;
int client_request_limit = 100;

int encrypt(char* buffer){
	return 0;
}
int decrypt(char* buffer){
	printf("Client:%s", buffer);
}

void disconnect(){
	printf("Client has disconnected.\n");
	FD_CLR(cfd, &all_sockets);
	cfd = -1;
}

void write_to_client(){           //helper function to write to our client  
    char message[1024];  
    if (fgets(message, sizeof(message), stdin) == 0){     
		return;
    }  
	encrypt(message);
    if (write(cfd, message, strlen(message)) <= 0){
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
			break;
		}  
		total_bytes = total_bytes + bytes;  
		buffer[total_bytes] = 0;                //null terminate our buffer as we will use string methods later on it  
		if (buffer[total_bytes - 1] == '\n'){           //last byte read has to be newline for us to know they have finished their request  
			condition = 1;  
		}  
	}	  
	//handle whatever request client sent  
	if (condition == 1){
		decrypt(buffer);	
	}
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
	cfd = socket(AF_INET, SOCK_STREAM, 0);
    FD_ZERO(&all_sockets);
	FD_SET(STDIN_FILENO, &all_sockets);
    FD_SET(sfd, &all_sockets);
    
    struct sockaddr_in a;  
  
    struct sigaction myaction;      //so that writing to disconnected client doesnt end server  
    myaction.sa_handler = SIG_IGN;  
    sigaction(SIGPIPE, &myaction, NULL);  
  
    memset(&a, 0, sizeof(struct sockaddr_in));      //preamble for setting up server down below  
    a.sin_family = AF_INET;  
    a.sin_port = htons(atoi(argv[1])); // first argument is port number  
    a.sin_addr.s_addr = htonl(INADDR_ANY);  
  
    if (bind(sfd, (struct sockaddr *)&a, sizeof(struct sockaddr_in)) == -1) {  
        perror("bind failed");  
        return -1;  
    }  
  
    if (listen(sfd, FD_SETSIZE) == -1) {  
        perror("listen failed");  
            return -1;  
    }  
 
    struct sockaddr_in ca;  
    socklen_t sinlen = sizeof(struct sockaddr_in);
	
	if (argc >= 4){

		a.sin_port = htons(atoi(argv[3])); // first argument is port number  

		if (inet_pton(AF_INET, argv[2], &a.sin_addr) == 0){
			perror("That's not an IPv4 address");
			return -1;
		}
		if (connect(cfd, (struct sockaddr *)&a, sizeof(struct sockaddr_in)) == -1){
			printf("Error in trying to connect to IP address with the specified port");
		}
		FD_SET(cfd, &all_sockets);
	}
	else{
		cfd = -1;
	}
  
    for(;;){		//waiting for peer to connect
	
		ready_read_sockets = all_sockets;
		ready_write_sockets = all_sockets;
		
		if (select(FD_SETSIZE, &ready_read_sockets, &ready_write_sockets, NULL, NULL) == -1){  
            perror("select in read");  
             return -1;  
        }
		
		if (cfd == -1){
			printf("Waiting for connnection.\n");
			cfd = accept(sfd, (struct sockaddr *)&ca, &sinlen);
			FD_SET(cfd, &all_sockets);
		}
		
		if (FD_ISSET(cfd, &ready_read_sockets) && cfd != -1){
			handle_client_data();
		}
		
		if (FD_ISSET(STDIN_FILENO,  &ready_read_sockets) && cfd != -1){
			write_to_client();
		}
		
	}
}