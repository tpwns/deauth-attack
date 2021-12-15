#pragma once
#include <cstdio>
#include "mac.h" 
#pragma pack(push,1)

struct DeauthHeader {
    uint16_t frame_control_;
    uint16_t duration_;
    Mac DA;
    Mac SA;
    Mac BSSID;
    uint16_t Seq_ctl;

    enum: uint16_t{
        type_beacon_frame = 0x8000,
        type_deauth_frame = 0xc000
    };
};

struct IEEEWM {
    uint16_t fixed = 7;
};

void make_deauth_hdr(Mac DA, Mac SA, struct DeauthHeader *deauthhdr);

#pragma pack(pop)