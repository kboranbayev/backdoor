/*---------------------------------------------------------------------------------------------
--	SOURCE FILE:	proc_payload.c - Set of function to process and print the packet payload
--
--	FUNCTIONS:		libpcap - packet filtering library based on the BSD packet
--					filter (BPF)
--
--	DATE:			May 4, 2016
--
--	REVISIONS:		(Date and nic_description)
--
--				
--	DESIGNERS:		Based on the code by Martin Casado 
--				Modified & redesigned: Aman Abdulla: May 4, 2016
--
--	PROGRAMMER:		Aman Abdulla
--
--	NOTES:
--	This file contain thw functions to process and print out the payload data in captured
--      datagrams. The payload content is printed out as ASCII and hex. 
-------------------------------------------------------------------------------------------------*/

#include "pkt_sniffer.h"


// This function will print payload data
void print_payload (const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;		// number of bytes per line
	int line_len;
	int offset = 0;			// offset counter 
	const u_char *ch = payload;

	if (len <= 0)
		return;

	// does data fits on one line?
	if (len <= line_width) 
        {
		print_hex_ascii_line (ch, len, offset);
		return;
	}

	// data spans multiple lines 
	for ( ;; ) 
        {
		// determine the line length and print
		line_len = line_width % len_rem;
		print_hex_ascii_line (ch, line_len, offset);
		
                // Process the remainder of the line 
		len_rem -= line_len;
		ch += line_len;
		offset += line_width;
		
                // Ensure we have line width chars or less
		if (len_rem <= line_width) 
                {
			//print last line
			print_hex_ascii_line (ch, len_rem, offset);
			break;
		}
	}
 }

// Print data in hex & ASCII
void print_hex_ascii_line (const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	// the offset
	printf("%05d   ", offset);
	
	// print in hex 
	ch = payload;
	for (i = 0; i < len; i++) 
        {
		printf("%02x ", *ch);
		ch++;
		if (i == 7)
                    printf(" ");
	}
	
	// print spaces to handle a line size of less than 8 bytes 
	if (len < 8)
		printf(" ");
	
	// Pad the line with whitespace if necessary  
	if (len < 16) 
        {
		gap = 16 - len;
		for (i = 0; i < gap; i++) 
                    printf("   ");
        }
	printf("   ");
	
	// Print ASCII
	ch = payload;
	for (i = 0; i < len; i++) 
        {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf ("\n");

 }
