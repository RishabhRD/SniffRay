/*
*
* SNIFFRAY: An implementation of netwok sniffer for linux.
*           It puts your computer in promiscuous mode.
*           So, that it listens to all packet coming through it
*           (Basically all in ethernet and can be all in wifi using spoofing)
*           For putting your computer in promiscuous mode root mode is nedeed.
*
* VERSION:  1.0
*
* AUTHORS:  RISHABH DWIVEDI <rishabhdwivedi17@gmail.com>
*           PRABHDEEP SINGH <prabhisthir4u@gmail.com>

*           This is a free software open sources with MIT License;
*           You have the freedom to use, redistribute, modify, sub-license, sell it
*           under MIT License.
*           You can contact us regarding any doubt or contribution.
*          
*
*           Feel free to reach us for contribution.
*/





#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/ioctl.h>
#include <iostream>
#include <unistd.h>
#include <linux/ipv6.h>
#include <string>




using namespace std;



/*
* ARP Header
*/
#pragma pack(1)
struct arp_header //Structure defining ARP Header
{
    uint16_t    arp_hd;     //Hardware type (Ehternet or Frame)
    uint16_t    arp_pr;     //Protocol ID
    uint8_t     arp_hdl;    //Header length
    uint8_t     arp_prl;    //Protocol Length
    uint16_t    arp_opr;    //Operation code
    uint8_t     arp_sha[6]; //Sender Hardware Address
    uint32_t    arp_spa;    //Sender IP Address
    uint8_t     arp_dha[6]; //Target Hardware Address
    uint32_t    arp_dpa;    //Target IP Address
};
#pragma pack()





#pragma pack(1)
struct icmphdr
{
    uint8_t     type;        //Message Type
    uint8_t     code;        //ICMP Code
    uint16_t    checksum;    //Checksum
};
#pragma pack()






//For Printing data of any layer packet
void printData(unsigned char *str, int data)
{
    for (int i = 0; i < data; i++)
    {
        printf("%c", str[i]);
    }
    cout << "\n--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------";
}







int main(int argc, char **argv)
{

    /*
    * Give command like: sniffray <interface name>
    *                    sniffray wlan0
    */
    if (argc < 2)
    {
        cout << "Give Interface name on which you want to listen." << endl;
        return 0;
    }





    //For binding socket with device
    int sockopt;
    struct ifreq ifopts;
    struct ifreq if_ip;





    //Code works in root mode only
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0)
    {
        cout << "Enable root mode" << endl;
        return 0;
    }





    /*
    * Next block belongs to binding the socket to specified interface
    * It uses ioctl() function for that
    * So, it is Linux based only
    */
    strncpy(ifopts.ifr_name, argv[1], IFNAMSIZ - 1);
    ioctl(fd, SIOCGIFFLAGS, &ifopts);
    ifopts.ifr_flags |= IFF_PROMISC;
    ioctl(fd, SIOCSIFFLAGS, &ifopts);
    /* Allow the socket to be reused - incase connection is closed prematurely */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1)
    {
        perror("setsockopt");
        close(fd);
        exit(EXIT_FAILURE);
    }
    /* Bind to device */
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, argv[1], IFNAMSIZ - 1) == -1)
    {
        perror("SO_BINDTODEVICE");
        close(fd);
        exit(EXIT_FAILURE);
    }





    /*
    * recieve data in the buffer
    * setting buffer to empty 
    */
    unsigned char *buffer = (unsigned char *)malloc(65536);
    memset(buffer, 0, 65536);
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);
    while (1)
    {
        int bufferlen = recvfrom(fd, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_len); //Recieving data from buffer

        if (bufferlen < 0)
        {
            cout << "Error in recieving packets.\n"; //If data not recieved----> ERROR
            continue;
        }





        //Packet Processing started
        cout << "\n\n\n\n\n\n--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n";

        //Processing Ethernet frame
        struct ethhdr *eth = (struct ethhdr *)(buffer);
        cout << "Source MAC Address: ";
        printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
        cout << "Destination MAC Address: ";
        printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
        cout << "Network Layer protocol code: ";
        printf("%p\n", eth->h_proto);





        /*
        * Processing Network Layer Datagram
        */
        if (eth->h_proto == 0x8) //If it is an IPv4 packet
        {
            cout << "IPV4" << endl;
            struct in_addr inet;
            memset(&inet, 0, sizeof(struct in_addr));
            struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
            inet.s_addr = ip->saddr;
            cout << "Source IP Address: ";
            printf("%s\n", inet_ntoa(inet));
            cout << "Destination IP Address: ";
            memset(&inet, 0, sizeof(struct in_addr));
            inet.s_addr = ip->daddr;
            printf("%s\n", inet_ntoa(inet));
            cout << "TTL of IP packet: ";
            printf("%d\n", (unsigned int)ip->ttl);
            cout << "Upper Layer Protocol: ";
            printf("%p\n", ip->protocol);
            unsigned short iphdrlen = (ip->ihl * 4);
            unsigned char *ptr = buffer + iphdrlen + sizeof(struct ethhdr);







            /*
            * Transport Layer Processing
            */
            if (ip->protocol == 0x06) //If it is TCP packet
            {
                cout << "TCP:" << endl;
                struct tcphdr *tcp = (struct tcphdr *)ptr;
                cout << "Destination Port Number: ";
                printf("%hu\n", ntohs(tcp->dest));
                cout << "Source Port Number: ";
                printf("%hu\n", ntohs(tcp->source));
                unsigned char *data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
                int remaining_data = bufferlen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
                printData(data, remaining_data);
            }

            else if (ip->protocol == 0x11) //If it is is UDP Datagram
            {
                cout << "UDP:" << endl;
                struct udphdr *udp = (struct udphdr *)ptr;
                cout << "Destination Port Number: ";
                printf("%hu\n", ntohs(udp->dest));
                cout << "Source Port Number: ";
                printf("%hu\n", ntohs(udp->source));
                unsigned char *data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
                int remaining_data = bufferlen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
                printData(data, remaining_data);
            }


            else if (ip->protocol == 0x1) //IF it is an ICMP packet
            { 
                struct icmphdr *icmp;
                icmp = (struct icmphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));
                cout << "ICMP Message type: ";
                printf("%02d\n", icmp->type);
                cout << "ICMP Code: ";
                printf("%02d\n", icmp->code);
                int remaining_data = bufferlen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct icmphdr));
                printData((unsigned char *)icmp + sizeof(icmp), remaining_data);
            }

            else
            {
                cout << "Not a TCP UDP or ICMP protocol.\n"
                     << endl;
                continue;
            }
        }




        else if (eth->h_proto == 0xdd86) //If it is a IPv6 Packet
        {
            cout << "IPV6:" << endl;
            char strip[100];
            struct ipv6hdr *ip = (struct ipv6hdr *)(buffer + sizeof(struct ethhdr));
            cout << "Source IP Address: ";
            inet_ntop(AF_INET6, &(ip->saddr), strip, INET6_ADDRSTRLEN);
            printf("%s\n", strip);
            cout << "Destination IP Address: ";
            inet_ntop(AF_INET6, &(ip->daddr), strip, INET6_ADDRSTRLEN);
            printf("%s\n", strip);
            cout << "TTL of IP packet: ";
            printf("%d\n", (unsigned int)ip->hop_limit);
            unsigned short iphdrlen = 40;
            unsigned char *ptr = buffer + iphdrlen + sizeof(struct ethhdr);





            /*
            * Transport Layer Processing
            */
            if (ip->nexthdr == 0x06) //If it is a TCP Packet
            {
                cout << "TCP:" << endl;
                struct tcphdr *tcp = (struct tcphdr *)ptr;
                cout << "Destination Port Number: ";
                printf("%hu\n", ntohs(tcp->dest));
                cout << "Source Port Number: ";
                printf("%hu\n", ntohs(tcp->source));
                unsigned char *data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
                int remaining_data = bufferlen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
                printData(data, remaining_data);
            }


            else if (ip->nexthdr == 0x11) //If it is an UDP Datagram
            {
                cout << "UDP:" << endl;
                struct udphdr *udp = (struct udphdr *)ptr;
                cout << "Destination Port Number: ";
                printf("%hu\n", ntohs(udp->dest));
                cout << "Source Port Number: ";
                printf("%hu\n", ntohs(udp->source));
                unsigned char *data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
                int remaining_data = bufferlen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
                printData(data, remaining_data);
            }





            else if (ip->nexthdr == 0x1) //If it is an ICMP Packet
            {
                struct icmphdr *icmp;
                icmp = (struct icmphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));
                cout << "ICMP Message type: ";
                printf("%02d\n", icmp->type);
                cout << "ICMP Code: ";
                printf("%02d\n", icmp->code);
                int remaining_data = bufferlen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct icmphdr));
                printData((unsigned char *)icmp + sizeof(icmp), remaining_data);
            }


            else
            {
                cout << "Not a TCP UDP or ICMP protocol.\n"
                     << endl;
                continue;
            }
        }




        else if (eth->h_proto == 0x608) //If it is an ARP Packet
        {
            cout << "Size: " << sizeof(struct arp_header) << endl;
            cout << "\nARP" << endl;
            struct arp_header *arp = (struct arp_header *)(buffer + sizeof(struct ethhdr));
            cout << "ARP operation: ";
            printf("%x\n", arp->arp_opr);
            cout << "ARP Protocol: ";
            printf("%p\n", arp->arp_pr);
            cout << "Sender MAC Address: ";
            printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2], arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);
            cout << "Destination MAC Address: ";
            printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", arp->arp_dha[0], arp->arp_dha[1], arp->arp_dha[2], arp->arp_dha[3], arp->arp_dha[4], arp->arp_dha[5]);
            cout << "Sender IP Address: ";
            struct in_addr inet;
            memset(&inet, 0, sizeof(struct in_addr));
            inet.s_addr = arp->arp_spa;
            printf("%s\n", inet_ntoa(inet));
            //printf("%u.%u.%u.%u\n", arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2], arp->arp_sha[3]);
            cout << "Destination IP Address: ";
            memset(&inet, 0, sizeof(struct in_addr));
            inet.s_addr = arp->arp_dpa;
            printf("%s\n", inet_ntoa(inet));
            //printf("%02d.%02d.%02d.%02d\n", arp->arp_dha[0], arp->arp_dha[1], arp->arp_dha[2], arp->arp_dha[3]);
        }




        else
        {
            cout << "Not an IPv4 or IPv6 and ARP protocol.    " << endl;
            continue;
        }
    }
}