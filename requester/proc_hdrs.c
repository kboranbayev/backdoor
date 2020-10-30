/*---------------------------------------------------------------------------------------------
--	SOURCE FILE:	proc_hdrs.c -   program to process the packet headers
--
--	FUNCTIONS:		libpcap - packet filtering library based on the BSD packet
--					filter (BPF)
--
--	DATE:			November 1, 2020
--
--	REVISIONS:		(Date and nic_description)
--
--  				April 10, 2014
--  				Added the handle_TCP() function which parses the TCP header and
--  				prints out fields of interest.
--
--                  October 26, 2020
--                  Modified the handle_TCP() function to decrypt the payload and then 
--                  print out the results.
--
--
--	DESIGNERS:		Based on the code by Aman Abdulla
--					Modified & redesigned: Kuanysh Boranbayev, Parm Dhaliwal 2020
--
--	PROGRAMMERS:	Kuanysh Boranbayev, Parm Dhaliwal
--
--	NOTES:
--	These fucntions are designed to process and parse the individual headers and 
--	print out selected fields of interest. For TCP the payload is also printed out. 
--	Currently the only the IP and TCP header processing functionality has been implemented.
--  For TCP, the payload is decrypted and parsed to print out the output from sent command. 
-------------------------------------------------------------------------------------------------*/

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
    handle_TCP (args, pkthdr, packet);
}

// This function will parse the IP header and print out selected fields of interest
void handle_TCP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    const struct sniff_tcp *tcp=0;          // The TCP header 
    const struct my_ip *ip;              	// The IP header 
    const char *payload;                  // Packet payload 

    int size_ip;
    int size_tcp;
    int size_payload;

    char *ptr, *ptr2;
    char command[MAX_SIZE];

    ip = (struct my_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL (ip)*4;
    
    // define/compute tcp header offset
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    

    //printf ("   Src port: %d\n", ntohs(tcp->th_sport));
    //printf ("   Dst port: %d\n", ntohs(tcp->th_dport));
    
    // define/compute tcp payload (segment) offset
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    
    // compute tcp payload (segment) size
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
        
        
    // Print payload data, including binary translation 
        
    if (size_payload > 0) 
    {
        //printf("   Payload (%d bytes):\n", size_payload);
        //print_payload (payload, size_payload);
        //printf("%s", payload);
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
        char* decrypted = aes_decrypt(de, (unsigned char *)payload, &len);
        if (strstr(decrypted, "EOT") != NULL) {
            memcpy(args, "EOT", sizeof("EOT"));
            printf("EOT exiting ........................... cid %d\n", getpid());
            exit(1);
        }
        printf("%s", decrypted);
    }    
}


