#include <stdint.h>
#include <pcap.h>
#include <iostream>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <stdlib.h>
#include <libnet.h>
#include <stdint.h>
#include <utility>
#include <string>
#include <vector>
#include <set>

using namespace std;
vector <pair<string,int>> frame_list;
set <pair<string,int>> frame;

struct Radiohdr{
    uint8_t hdr_rev;
    uint8_t hdr_pad;
    uint8_t hdr_len;
    uint64_t present_flag;
    uint64_t MAC_timestamp;
    uint8_t flag;
    uint8_t data_rate;
    uint16_t chnl_freq;
    uint16_t chnl_flag;
    uint8_t ant_sig0;
    uint16_t RX_flag;
    uint8_t ant_sig1;
    uint8_t ant;
};

struct Beacon{
    uint8_t FCF[2];
    uint16_t Dur;
    uint8_t Rec_MAC[6];
    uint8_t Dst_MAC[6];
    uint8_t Trans_MAC[6];
    uint8_t Src_MAC[6];
    uint8_t BSSID[6];
    uint16_t frag_num;
    uint16_t seq_num;
};


struct Tag{
    uint8_t tag1_num;
    uint8_t tag1_len;
    char* SSID;

};
struct Management{
    uint16_t fixed;
    struct Tag* tag;    
};

void analysisframe(uint8_t* packet){

    struct Radiohdr* radiohdr = (struct Radiohdr*)packet;
    struct Beacon* beacon = (struct Beacon*)(packet+radiohdr->hdr_len);
    struct Management* mgmt = (struct Management*)(packet+sizeof(struct Beacon));

    if(beacon->FCF[0] != 0x80){
        printf("This frame is not beacon frame\n");
        return;
    }
    
    printf("BSSID : ");
    for(int i=0;i<6;i++){
        printf("%02x:",beacon->BSSID[i]);
    }
    
    printf("\nSSID : %s\n",mgmt->tag->SSID);

    int num =1;
    for(int i=0;i<frame_list.size();i++){
        if(!strncmp(mgmt->tag->SSID,frame_list[i].first.c_str(),sizeof(frame_list[i].first.c_str()))){
            frame_list[i].second ++;
            printf("BEACON : %d\n",frame_list[i].second);
            num =0;
            break;
        }
    }

    if(num){
        pair<string,int> p = make_pair(mgmt->tag->SSID,0);
        frame_list.push_back(p);
        printf("BEACON : 1\n");
    } 
    return;
}

int main(int argc, char* argv[]){
    if(argc !=2){ 
        printf("syntax : airodump <interface>\n");
        printf("sample : airodump mon0\n");
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (1) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        uint8_t* packet2 = (uint8_t*)packet;

        struct Radiohdr* radiohdr = (struct Radiohdr*)packet2;
        struct Beacon* beacon = (struct Beacon*)(packet2+radiohdr->hdr_len);
        struct Management* mgmt = (struct Management*)(packet2+sizeof(struct Beacon));

        if(beacon->FCF[0] != 0x80){
            printf("This frame is not beacon frame\n");
            return 0;
        }
    
        printf("BSSID : ");
        for(int i=0;i<6;i++){
            printf("%02x:",beacon->BSSID[i]);
        }
    
        printf("\nSSID : %s\n",mgmt->tag->SSID);

        int num =1;
        for(int i=0;i<frame_list.size();i++){
            if(!strncmp(mgmt->tag->SSID,frame_list[i].first.c_str(),sizeof(frame_list[i].first.c_str()))){
                frame_list[i].second ++;
                printf("BEACON : %d\n",frame_list[i].second);
                num =0;
                break;
            }
        }

        if(num){
            pair<string,int> p = make_pair(mgmt->tag->SSID,0);
            frame_list.push_back(p);
            printf("BEACON : 1\n");
        } 
    }
    
    pcap_close(handle);
}