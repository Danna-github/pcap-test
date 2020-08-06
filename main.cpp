#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include "header.h"

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

void show_pckt_info(pcap_t* handle){
	/* ethernet headers are always exactly 14 bytes */
        #define SIZE_ETHERNET 14

        const struct sniff_ethernet *ethernet; /* The ethernet header */
        const struct sniff_ip *ip; /* The IP header */
        const struct sniff_tcp *tcp; /* The TCP header */
        const char *payload; /* Packet payload */

        u_int size_ip;
        u_int size_tcp;

        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        printf("%u bytes captured\n", header->caplen);

        ethernet = (struct sniff_ethernet*)(packet);
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        //ethertype check add!!
        if(ntohs(ethernet->ether_type)!=0x0800)
        	return;
        size_ip = IP_HL(ip)*4;
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;

	if(ip->ip_p!=IPPROTO_TCP) //if pckt is not tcp
		return;

	//print mac address
        printf("Ethernet Header: %x:%x:%x:%x:%x:%x -> ", ethernet->ether_shost[0], ethernet->ether_shost[1], ethernet->ether_shost[2], ethernet->ether_shost[3], ethernet->ether_shost[4], ethernet->ether_shost[5]);
        printf("%x:%x:%x:%x:%x:%x\n", ethernet->ether_dhost[0], ethernet->ether_dhost[1], ethernet->ether_dhost[2], ethernet->ether_dhost[3], ethernet->ether_dhost[4], ethernet->ether_dhost[5]);

	//print ip address
        printf("IP Header: %s -> ", inet_ntoa(ip->ip_src));
        printf("%s\n", inet_ntoa(ip->ip_dst));

	//print port
        printf("TCP Header: %x -> ", ntohs(tcp->th_sport));
        printf("%x\n", ntohs(tcp->th_dport));

	//print payload & 16 bytes of payload in hexadecimal(if exists)
        payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        size_payload=ntohs(ip->ip_len) - size_ip - size_tcp;
        printf("Payload len: %dn", size_payload);
        int printlen = min(16, size_payload);
        for(int i=0; i<pirntlen; i++)
        	printf("%02X", payload[i]);

        printf("=================================================================\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        show_pckt_info(handle);
    }

    pcap_close(handle);
}
