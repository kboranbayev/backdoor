# backdoor
Linux Backdoor application in C.

The application has two separate modules: requester and responder.

requester - a client application that sends console commands to responder machine. The sending command will be encrypted to avoid any watchers.

responder - a server application that listens and camouflages itself within the system processes. Once, the command is received, the responder will execute the command as the "root" and returns the output result to the requester. The output results will also be encrypted in the same way.

The application uses libpcap.h for sniffing the packets.
The application uses openssl/aes.h and openssl/evp.h for encryption parts.

