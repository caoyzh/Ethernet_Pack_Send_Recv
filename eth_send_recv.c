/********************************
Programmer	Last Modified		Description
---------	-------------		---------------
Cody Sigvartson	9_20_18			Initial development
Cody Sigvartson 9_27_18			Fixed IPv4 Packet type bug

Program description:
This program builds and sends an ethernet frames over sockets. This is a simple ethernet frame
with no error detection (ie. CRC)
********************************/

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>

#define BUFFER_MAX		65535
#define SEND 0
#define RECV 1

void send_message(char if_name[], char hw_addr[], char payload[]){
	// create socket
	int sockfd = -1;
	if((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))<0){
		perror("socket() failed!");
	}

	printf("Sending with sockfd: %d\n",sockfd);

	// connect to interface name
	struct ifreq if_hwaddr;
	memset(&if_hwaddr,0,sizeof(struct ifreq));
	strncpy(if_hwaddr.ifr_name, if_name, IFNAMSIZ-1);
	if(ioctl(sockfd, SIOCGIFHWADDR, &if_hwaddr) < 0){
		perror("SIOCGIFHWADDR");
	}

	// build ethernet frame
	struct ether_header frame;
	memset(&frame,0,sizeof(struct ether_header));
	memcpy(frame.ether_dhost, hw_addr, 6);
	memcpy(frame.ether_shost, if_hwaddr.ifr_hwaddr.sa_data, 6);
	frame.ether_type = htons(ETH_P_IP);


	struct ifreq if_idx;
	memset(&if_idx,0,sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, if_name, IFNAMSIZ-1);
	if(ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0){
		perror("SIOCGIFINDEX");
	}

	// pack frame header
	unsigned char buff[BUFFER_MAX + 1];
	char *eth_header = (char *)&frame;
	memset(buff, 0, sizeof(buff));
	strncpy(buff,eth_header,strlen(eth_header)+1);
	strncat(&buff[14],payload,strlen(payload)+1);

	struct sockaddr_ll sk_addr;
	memset(&sk_addr, 0, sizeof(struct sockaddr_ll));

	sk_addr.sll_ifindex = if_idx.ifr_ifindex;
	sk_addr.sll_halen = ETH_ALEN;
	int byteSent = sendto(sockfd, buff, strlen(payload)+strlen(eth_header)+1, 0, (struct sockaddr*)&sk_addr, sizeof(struct sockaddr_ll));
	printf("%d bytes sent!\n", byteSent);
}

void recv_message(char if_name[]){
    int sockfd;
    char buff[BUFFER_MAX];
    struct sockaddr_ll sk_addr;
    struct ifreq ifstruct;

    printf("[Date:%s] Time:%s \n", __DATE__, __TIME__);

    if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        fprintf(stdout, "create socket error\n");
        return;
    }

    memset(&sk_addr, 0, sizeof(sk_addr));
    sk_addr.sll_family = PF_PACKET;
    sk_addr.sll_protocol = htons(ETH_P_ALL);
    strcpy(ifstruct.ifr_name, if_name);
    if(ioctl(sockfd, SIOCGIFINDEX, &ifstruct) < 0){
		perror("SIOCGIFINDEX");
	}
    sk_addr.sll_ifindex = ifstruct.ifr_ifindex;

    strcpy(ifstruct.ifr_name, if_name);
    if(ioctl(sockfd, SIOCGIFHWADDR, &ifstruct) < 0){
		perror("SIOCGIFHWADDR");
	}
    memcpy(sk_addr.sll_addr, ifstruct.ifr_ifru.ifru_hwaddr.sa_data, ETH_ALEN);

    sk_addr.sll_halen = ETH_ALEN;

    if (bind(sockfd, (struct sockaddr *)&sk_addr, sizeof(sk_addr)) == -1)
    {
        printf("bind:   ERROR\n");
        return;
    }

    int byteRead = 0;
    while (byteRead <= 0)
    {
        byteRead = recvfrom(sockfd, buff, BUFFER_MAX, 0, NULL, NULL);
        if (byteRead <= 0)
        {
            continue;
        }

		unsigned char src_mac[6];
		// unsigned char dst_mac[6];
		memcpy(src_mac, &buff[6], 6);
		// memcpy(dst_mac, &buff[0], 6);
        printf("Source MAC: [%X][%X][%X][%X][%X][%X]\n",src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);
		// printf("Dest MAC  : [%X][%X][%X][%X][%X][%X]\n",dst_mac[0],dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);
        printf("Message: %s\n", &buff[14]);
    }
}

int main(int argc, char *argv[])
{
	int mode;
	char buff[BUFFER_MAX];
	char hw_addr[6];
	char interfaceName[IFNAMSIZ];
	memset(buff, 0, BUFFER_MAX);
	
	int correct=0;
	if (argc > 1){
		if(strncmp(argv[1],"Send", 4)==0){
			if (argc == 5){
				mode=SEND; 
				sscanf(argv[3], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &hw_addr[0], &hw_addr[1], &hw_addr[2], &hw_addr[3], &hw_addr[4], &hw_addr[5]);
				strncpy(buff, argv[4], BUFFER_MAX);
				printf("Sending payload: %s\n", buff);
				correct=1;
			}
		}
		else if(strncmp(argv[1],"Recv", 4)==0){
			if (argc == 3){
				mode=RECV;
				correct=1;
			}
		}
		strncpy(interfaceName, argv[2], IFNAMSIZ);
	 }
	 if(!correct){
		fprintf(stderr, "Send <InterfaceName> <DestHWAddr> <Message>\n");
		fprintf(stderr, "Recv <InterfaceName>\n");
		exit(1);
	 }

	if(mode == SEND){
		send_message(interfaceName, hw_addr, buff);
	}
	else if (mode == RECV){
		recv_message(interfaceName);
	}

	return 0;
}
