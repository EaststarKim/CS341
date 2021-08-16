#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>
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
uint64_t msg_proc(struct pollfd *polls,int sockfd,char *msg,uint64_t l,int sw){ //sw: 0->send 1->recv
    uint64_t r,t;
    for(r=t=0;r<l;){
        //wait for events on client
        int pr=poll(polls,1,1000);
        if(pr<0)error_handling(sockfd,"poll() error\n");
        if(pr==0)error_handling(sockfd,"timeout\n");
        if(pr>0){
            if(sw){
                if((t=recv(sockfd,msg+r,l-r,0))<=0)return 0;
            }
            else{
                if(polls[0].revents&POLLOUT)
                    if((t=send(sockfd,msg+r,l-r,MSG_NOSIGNAL))<0)return 0; //avoid instant process termination
            }
            r+=t;
            t=0;
            if(msg[r-1]==EOF)break;
        }
    }
    return r;
}
void hexadecimal(char *msg,uint64_t l){ //only for endian checking
    int i;
    for(i=0;i<l;++i)printf("%x%x ",(msg[i]>>4)&15,msg[i]&15);
}
void sigchld_handler(int signal){
    int st;
    while(waitpid(-1,&st,WNOHANG)>0); //-1: any child / WNOHANG: return immediately if no child has exited
}
 
int main(int argc,char *argv[]){
    signal(SIGCHLD,(void *)sigchld_handler);

    if(argc!=3)error_handling(0,"usage: ./server -p <port>\n"); //ex: ./server -p 1234

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

    while(1){
        struct sockaddr_in client;
        socklen_t len=sizeof(client);
        while((connfd=accept(listenfd,(struct sockaddr *)&client,(socklen_t *)&len))!=-1){
            /*fputs("======Client connected======\n",stderr);*/
            /*fcntl(connfd,F_SETFL,O_NONBLOCK); //nonblocking socket*/

            pid_t pid;
            if((pid=fork())==0){ //new client connection->fork a new child server
                close(listenfd);

                struct pollfd polls[2]; //use IO Multiplexing instead of nonblocking socket
                polls[0].fd=connfd;
                polls[0].events=POLLOUT;
                
                while(1){
                    char *msg=(char *)malloc(MXL*sizeof(char)); //memory allocation for message
                    uint64_t l=msg_proc(polls,connfd,msg,MXL,1);
                    if(l==0){
                        free(msg);
                        break;
                    }
                    if(l!=get_length(msg)){
                        free(msg);
                        error_handling(connfd,"wrong length\n");
                    }
                    /*hexadecimal(msg,l);*/
                    uint16_t checksum=calc_checksum(msg,l);
                    if(msg[2]!=(char)(checksum>>8)||msg[3]!=(char)(checksum&255)){
                        free(msg);
                        error_handling(connfd,"wrong checksum\n");
                    }
                    
                    char keyword[4]={msg[4],msg[5],msg[6],msg[7]};
                    int i,j;
                    for(i=0;i<4;++i)keyword[i]=tolower(keyword[i]);
                    uint16_t op=((unsigned char)msg[0]<<8)+(unsigned char)msg[1]; //op: 0->encryption 1->decryption
                    if(op!=0&&op!=1){
                        free(msg);
                        error_handling(connfd,"wrong op\n");
                    }
                    for(i=16,j=0;i<l;++i)if(isalpha(msg[i])){
                        msg[i]='a'+(msg[i]-'a'+(op?-1:1)*(keyword[j]-'a')+26)%26;
                        j=(j+1)%4;
                    }
                    
                    checksum=calc_checksum(msg,l);
                    msg[2]=checksum>>8;
                    msg[3]=checksum&255;
                    
                    if(!msg_proc(polls,connfd,msg,l,0))error_handling(connfd,"connection closed\n");
                    free(msg);
                }
                close(connfd);
                exit(0);
            }
            else close(connfd);
        }
    }
    close(listenfd);
    return 0;
}