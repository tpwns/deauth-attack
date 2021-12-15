#include "deauth.h"
#include "arpa/inet.h"

void make_deauth_hdr(Mac DA, Mac SA, struct DeauthHeader *deauthhdr){

    deauthhdr->frame_control_ = htons(deauthhdr->type_deauth_frame);
    deauthhdr->duration_ = 314; //기존 deauth packet과 일치하도록 하드코딩
    deauthhdr->DA = DA;
    deauthhdr->SA = SA;
    deauthhdr->BSSID = SA;
    deauthhdr->Seq_ctl = 0;

}