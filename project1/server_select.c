#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <endian.h>
#include <unistd.h>
#include <signal.h>
 
#define MXL 10000000 //Max length of message : 10MB
# define BACKLOG 5 //backlog. Is 5 too small/dated value?

void error_handling(int sock,char *message){
    close(sock);
	fputs(message,stderr);
    exit(1);
}
void rejection(int sock,fd_set *fds,char *message){
    close(sock);
    FD_CLR(sock,fds); //remove client from fds
    fputs(message,stderr);
}
uint16_t calc_checksum(char *msg,uint64_t l){
    int i;
    uint32_t sum=0;
    for(i=0;i<l;i+=2)if(i!=2){
        sum+=(((unsigned char)msg[i])<<8)+(i<l-1?(unsigned char)msg[i+1]:0);
        sum=(sum&65535)+(sum>65535);
    }
    uint16_t checksum=sum;
    return ~checksum;
}
uint64_t get_length(char *msg){
    int i;
    uint64_t l=0;
    for(i=7;++i<16;)l=(l<<8)+((unsigned char)msg[i]&255);
    return l;
}
uint64_t msg_proc(int sockfd,char *msg,uint64_t l,int sw){ //sw: 0->send 1->recv
    uint64_t r,t;
    for(r=t=0;r<l;){
        if(sw){
            if((t=recv(sockfd,msg+r,l-r,0))<=0)return 0;
        }
        else{
            if((t=send(sockfd,msg+r,l-r,MSG_NOSIGNAL))<0)return 0; //avoid instant process termination
        }
        r+=t;
        t=0;
        if(msg[r-1]==EOF)break;
    }
    return r;
}
void hexadecimal(char *msg,uint64_t l){ //only for endian checking
    int i;
    for(i=0;i<l;++i)printf("%x%x ",(msg[i]>>4)&15,msg[i]&15);
}
 
int main(int argc,char *argv[]){

    if(argc!=3)error_handling(0,"usage: ./server_select -p <port>\n"); //ex: ./server_select -p 1234

    uint16_t port=htons((uint64_t)(atoi(argv[2])));

    int listenfd = socket(AF_INET,SOCK_STREAM,0),connfd;
    if(listenfd==-1)error_handling(0,"socket() error: listenfd\n");
    
    struct sockaddr_in addr;
    addr.sin_addr.s_addr=htonl(INADDR_ANY);
    addr.sin_family=AF_INET;
    addr.sin_port=port;
 
    if(bind(listenfd,(struct sockaddr *)&addr,sizeof(addr))==-1){
        close(listenfd);
        error_handling(listenfd,"bind() error\n");
    }
    if(listen(listenfd,BACKLOG)==-1){
        close(listenfd);
        error_handling(listenfd,"listen() error\n");
    }

    fd_set fds,tmpfds;
    FD_ZERO(&fds); //clear the fd set
	FD_SET(listenfd,&fds);
	int n=listenfd+1;
	while(1){
        tmpfds=fds;
		int rv=select(n,&tmpfds,NULL,NULL,NULL); //select() changes the values in fds. hmm...
		if(FD_ISSET(listenfd,&tmpfds)){ //check if fd is in fds
            struct sockaddr_in client;
            socklen_t len=sizeof(client);
            int connfd=accept(listenfd,(struct sockaddr *)&client,&len);
            if(connfd==-1){
                fputs("accept() error\n",stderr);
                continue;
            }
			FD_SET(connfd,&fds); //add client to fds
            if(n<=connfd)n=connfd+1;
            continue;
		}

        int fd;
        for(fd=0;fd<n&&rv;++fd)if(FD_ISSET(fd,&tmpfds)){
            --rv;
            connfd=fd;
            char *msg=(char *)malloc(MXL*sizeof(char)); //memory allocation for message
            uint64_t l=msg_proc(connfd,msg,MXL,1);
            if(l==0){
                rejection(connfd,&fds,"");
                free(msg);
                continue;
            }
            else if(l!=get_length(msg)){
                rejection(connfd,&fds,"wrong length\n");
                free(msg);
                continue;
            }
            /*hexadecimal(msg,l);*/
            uint16_t checksum=calc_checksum(msg,l);
            if(msg[2]!=(char)(checksum>>8)||msg[3]!=(char)(checksum&255)){
                rejection(connfd,&fds,"wrong checksum\n");
                free(msg);
                continue;
            }
            
            char keyword[4]={msg[4],msg[5],msg[6],msg[7]};
            int i,j;
            for(i=0;i<4;++i)keyword[i]=tolower(keyword[i]);
            uint16_t op=((unsigned char)msg[0]<<8)+(unsigned char)msg[1]; //op: 0->encryption 1->decryption
            if(op!=0&&op!=1){
                rejection(connfd,&fds,"wrong op\n");
                free(msg);
                continue;
            }
            for(i=16,j=0;i<l;++i)if(isalpha(msg[i])){
                msg[i]='a'+(msg[i]-'a'+(op?-1:1)*(keyword[j]-'a')+26)%26;
                j=(j+1)%4;
            }
            
            checksum=calc_checksum(msg,l);
            msg[2]=checksum>>8;
            msg[3]=checksum&255;
            
            if(!msg_proc(connfd,msg,l,0))rejection(connfd,&fds,"connection closed\n");
            free(msg);
        }
	}
    close(listenfd);
    return 0;
}