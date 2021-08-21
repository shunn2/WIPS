#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <stdint.h>
#include "ieee80211/ieee80211.h"
#include <netinet/in.h>

#define MAC_len 6

void gotoxy(int x, int y) {
    printf("\033[%d;%df",y,x);
    fflush(stdout);
}

typedef struct radiotap_header_deauth
{
    uint8_t HR;
    uint8_t HP;
    uint16_t H_length;
    uint32_t Present;
    uint8_t DR;
    uint8_t RX[3];
}radiotap_deauth;

typedef struct radiotap_header
{
    uint8_t HR;
    uint8_t HP;
    uint16_t H_length;
    uint32_t Present[2];
    uint8_t Flags;
    uint8_t DR;
    uint16_t Channel;
    uint16_t CF;
    uint8_t Antenna;
    uint16_t RX;
    uint8_t Antenna2;
    uint8_t Antenna3;
}radiotap;

typedef struct Deauthentication
{
    uint16_t subtype;
    uint16_t duration;
    uint8_t dmac[MAC_len];
    uint8_t smac[MAC_len];
    uint8_t bssid[MAC_len];
    uint16_t seq;
    uint16_t reson_code;
}deauth;

typedef struct ssid_param
{
    uint8_t tag_num;
    uint8_t tag_len;
}ssid_tag;

typedef struct RSN_tag
{
    uint8_t tag_num;
    uint8_t tag_len;
    
    uint16_t version;
    uint8_t G_oui[3];
    uint8_t G_enc;

    uint16_t P_count;
    uint8_t P_oui[3];
    uint8_t P_enc;

    uint16_t A_count;
    uint8_t A_oui[3];
    uint8_t auth;
}RSN;

typedef enum Info{
    rouge_AP = 1,
    Authorized_AP,
    ad_hoc,
    honeypot_AP
}info;

typedef struct AP_INFO{
    uint8_t mac[6]; // AP mac
    char ssid[50]; // AP SSID
    info state; // AP state
}AP_info;