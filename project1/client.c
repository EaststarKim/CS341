#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <endian.h>
#include <unistd.h>

#define MXL 10000000 //Max length of message : 10MB

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
void rotate_keyword(char *keyword){
    int i;
    char tmp=keyword[0];
    for(i=1;i<4;++i)keyword[i-1]=keyword[i];
    keyword[3]=tmp;
}
int msg_proc(struct pollfd *polls,int sockfd,char *msg,uint64_t l,int sw){ //sw: 0->send 1->recv
    uint64_t r,t;
    for(r=t=0;r<l;){
        //wait for events on server
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
        }
    }
    return 1;
}
void hexadecimal(char *msg,uint64_t l){ //only for endian checking
    int i;
    for(i=0;i<l;++i)printf("%x%x ",(msg[i]>>4)&15,msg[i]&15);
}

int main(int argc,char *argv[]){
    if(argc!=9)error_handling(0,"usage: ./client -h <host> -p <port> -o <operation> -k <keyword>\n"); //"ex: ./client h 143.248.111.222 p 1234 o 0 k cake"
    
    char *host,keyword[4];
    uint16_t port,op;
    int i;
    for(i=1;i<argc-1;++i){ //prepare for not 'hpok' ordering cases
        if(!strcmp(argv[i],"-h")){
            host=(char *)malloc(strlen(argv[i+1])*sizeof(char));
            strcpy(host,argv[i+1]); //how can I use 'getaddrinfo()'?
        }
        if(!strcmp(argv[i],"-p"))port=htons((uint16_t)(atoi(argv[i+1])));
        if(!strcmp(argv[i],"-o"))op=htons((uint16_t)(atoi(argv[i+1])));
        if(!strcmp(argv[i],"-k"))strcpy(keyword,argv[i+1]);
    }
    
    int sockfd=socket(AF_INET,SOCK_STREAM,0);
    if(sockfd==-1)error_handling(0,"socket() error\n");
    /*fcntl(sockfd,F_SETFL,O_NONBLOCK); //nonblocking socket*/
    
    struct sockaddr_in addr;
    addr.sin_addr.s_addr=inet_addr(host);
    addr.sin_family=AF_INET;
    addr.sin_port=port;
    
    if(connect(sockfd,(struct sockaddr *)&addr,sizeof(addr))==-1)error_handling(sockfd,"connect() error\n");

    /*fprintf(stderr,"======Connected to %s======\n",host);*/

    struct pollfd polls[2]; //use IO Multiplexing instead of nonblocking socket
    polls[0].fd=sockfd;
    polls[0].events=POLLOUT;
    
    int eof_flag=0;
    while(!eof_flag){
        char *msg; //op(2) + checksum(2) + keyword(4) + length(8) + data(<= MXL-16)
        msg=(char *)malloc(MXL*sizeof(char)); //memory allocation for message

        msg[0]=(char)(op&255);
        msg[1]=(char)(op>>8);

        for(i=4;i<8;++i)msg[i]=keyword[i-4];

        uint64_t l=16;
        for(;l<MXL-1;){
            int c=tolower(getchar());
            if(isalpha(c))rotate_keyword(keyword);
            if(c==EOF){
                eof_flag=1;
                break;
            }
            msg[l++]=c;
        }
        msg[l++]=EOF;
        uint64_t tmp=htobe64(l);
        for(i=7;++i<16;tmp>>=8)msg[i]=tmp&255;
        
        uint16_t checksum=calc_checksum(msg,l);
        msg[2]=checksum>>8;
        msg[3]=checksum&255;
        /*hexadecimal(msg,l);*/

        char *res=(char *)malloc(MXL*sizeof(char));
        for(i=0;;++i){ //wrong checksum->request for resending
            if(i>0)fputs("resending\n",stderr);
            if(!msg_proc(polls,sockfd,msg,l,0))error_handling(sockfd,"connection closed\n");
            if(!msg_proc(polls,sockfd,res,l,1))error_handling(sockfd,"connection closed\n");
            /*hexadecimal(res,l);*/
            checksum=calc_checksum(res,l);
            if(res[2]!=(char)(checksum>>8)||res[3]!=(char)(checksum&255))fputs("wrong checksum\n",stderr);
            else break;
        }
        free(msg);
        for(i=16;i<l-1;++i)printf("%c",res[i]);
        free(res);
    }
    close(sockfd);
    return 0;
}