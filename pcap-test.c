#include <stdio.h>
#include <stdbool.h>
#include <pcap.h>
#include <netinet/in.h>

#include "protocol-headers.h"


typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test eth0\n");
}

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
		
		struct libnet_ethernet_hdr* ether;
		struct libnet_ipv4_hdr* ip;
		struct libnet_tcp_hdr* tcp;
		
		ether = (struct libnet_ethernet_hdr*)packet;
		if(ether->ether_type != 0x8) continue;
		ip = (struct libnet_ipv4_hdr*)(packet + ETHER_HDR_LEN);
		if(ip->ip_p != 0x6) continue;
		tcp = (struct libnet_tcp_hdr*)(packet + ETHER_HDR_LEN + IP_HDR_LEN);
		char* payload = (char*)(packet + ETHER_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
		
		printf("src mac: ");
		for(int i=0; i<6; i++) printf("%02x:", ether->ether_shost[i]);
		printf("\b \n");
		printf("dst mac: ");
		for(int i=0; i<6; i++) printf("%02x:", ether->ether_dhost[i]);
		printf("\b \n");
		
		printf("src ip: ");
		for(int i=0; i<4; i++) printf("%d.", *((u_int8_t*)&(ip->ip_src)+i));
		printf("\b \n");
		printf("dst ip: ");
		for(int i=0; i<4; i++) printf("%d.", *((u_int8_t*)&(ip->ip_dst)+i));
		printf("\b \n");
		
		printf("src port: %d\n", ntohs(tcp->th_sport));
		printf("dst port: %d\n", ntohs(tcp->th_dport));
		
		u_int16_t payload_len = ntohs(ip->ip_len) - IP_HDR_LEN - TCP_HDR_LEN;
		printf("payload size: %d bytes", payload_len);
		if(payload_len>0){
			printf("\npayload data: ");
			for(int i=0; i<(payload_len<8?payload_len:8); i++) printf("%02x ", *((u_int8_t*)payload+i));
			if(payload_len>9) printf("...");
		}
		printf("\n\n");
	}

	pcap_close(pcap);
}
