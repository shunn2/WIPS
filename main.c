#include "main.h"

void send_deauth(uint8_t *src_mac, uint8_t *dst_mac, uint8_t *bssid, pcap_t *handle_)
{
    radiotap_deauth *rah = (radiotap_deauth *)malloc(sizeof(radiotap_deauth *));
    rah->HR = 0x00;
    rah->HP = 0x00;
    rah->H_length = htons(0x0c00);
    rah->Present = htonl(0x04800000);
    rah->DR = 0x02;
    rah->RX[0] = 0x00;
    rah->RX[1] = 0x18;
    rah->RX[2] = 0x00;

    deauth *deauth_packet = (deauth *)malloc(sizeof(deauth *));
    deauth_packet->subtype = IEEE80211_FC0_SUBTYPE_DEAUTH;
    deauth_packet->duration = 0x013a;

    memcpy(deauth_packet->dmac, dst_mac, MAC_len);
    memcpy(deauth_packet->smac, src_mac, MAC_len);
    memcpy(deauth_packet->bssid, bssid, MAC_len);

    deauth_packet->seq = 0x0000;
    deauth_packet->reson_code = IEEE80211_REASON_NOT_ASSOCED;

    uint8_t Packet[40];
    uint8_t Packet2[40];

    int datalen = 0;
    memcpy(Packet, rah, sizeof(*rah));
    datalen += sizeof(*rah);
    memcpy(Packet + datalen, deauth_packet, sizeof(*deauth_packet));
    memcpy(Packet2, Packet, 40);
    memcpy(Packet2 + datalen + 4, src_mac, MAC_len);
    memcpy(Packet2 + datalen + 4 + MAC_len, dst_mac, MAC_len);
    datalen += sizeof(*deauth_packet);

    free(deauth_packet);
    free(rah);

    pcap_sendpacket(handle_, Packet, datalen);
    pcap_sendpacket(handle_, Packet2, datalen);
}

int is_equal(uint8_t *a, uint8_t *b, int len)
{
    for (int i = 0; i < len; i++)
    {
        if (a[i] != b[i])
            return 0; // different
    }
    return 1; // is_equal
}

void str_tok(char *line, char *Arr[6])
{
    int i = 0;
    char *ptr = strtok(line, ":");
    while (i < 6)
    {
        Arr[i] = ptr;
        ptr = strtok(NULL, ":");
        i++;
    }
}

int mac_comp(uint8_t *mac, char *file_name)
{
    FILE *f;
    char *arr[MAC_len];
    uint8_t t[MAC_len];
    char buffer[100], *line;

    f = fopen(file_name, "r");
    while (!feof(f))
    {
        line = fgets(buffer, 100, f);
        if(line == NULL) break;
        str_tok(buffer, arr);
        for (int i = 0; i < MAC_len; i++)
        {
            t[i] = strtol(arr[i], NULL, 16);
        }
        if (is_equal(t, mac, MAC_len))
        {
            fclose(f);
            return 1; // equal
        }
    }
    fclose(f);
    return 0; // different
}

int SSID_comp(char *SSID, char *file_name)
{
    FILE *f;
    char buffer[100], *line;

    f = fopen(file_name, "r");
    while (!feof(f))
    {
        line = fgets(buffer, 100, f);
        if(line == NULL) break;
        if (!strcmp(line, SSID))
        {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

int WPA_mode(const unsigned char *pkt_data, int *datalen, struct pcap_pkthdr *header, uint8_t RSN_tag) // WPA2 check
{
    ssid_tag *ssid_p = (ssid_tag *)(pkt_data + *datalen);
    *datalen = *datalen + sizeof(*ssid_p) + ssid_p->tag_len;
    uint8_t tag_num[2]; // tag_num[0] = tag num , tag_num[1] = tag len
    while (*datalen <= header->caplen) // first tag -> last tag
    {
        memcpy(tag_num, pkt_data + *datalen, 2);
        if (tag_num[0] == RSN_tag) // RSN tag = 0x30
            return 1;
        *datalen = *datalen + tag_num[1] + 2; // next tag
    }
    return 0;
}

int P2P_param(const unsigned char *pkt_data, int *datalen, struct pcap_pkthdr *header, uint8_t vender_tag) // P2P check
{
    uint8_t tag_num[2];                // tag_num[0] = tag num , tag_num[1] = tag len
    while (*datalen <= header->caplen) // first tag -> last tag
    {
        memcpy(tag_num, pkt_data + *datalen, 2);
        if (tag_num[0] == vender_tag) // vender specific tag = 0xdd
        {
            *datalen += 2;                        //tag_num, tag_len jump
            uint8_t wifi[3] = {0x50, 0x6f, 0x9a}; //wifi_alliance(OUI)
            uint8_t OUI[3];
            memcpy(OUI, pkt_data + *datalen, 3);
            if (is_equal(wifi, OUI, 3)) //OUI = wifi_alliance
            {
                *datalen += 3; //OUI jump
                uint8_t P2P[1];
                memcpy(P2P, pkt_data + *datalen, 1);
                if (P2P[0] == 0x09) //P2P
                {
                    return 1;
                }
                *datalen -= 3;
            }
            *datalen -= 2;
        }
        *datalen = *datalen + tag_num[1] + 2; // next tag
    }
    return 0;
}

void print_mac(uint8_t *mac, int rouge)
{
    if (rouge == 1)
        printf("\033[31m");
    for (int i = 0; i < MAC_len; i++)
    {
        if (i == MAC_len - 1)
            printf("%02x", mac[i]);
        else
            printf("%02x:", mac[i]);
    }
    printf("\033[0m");
}

int packet_scan(pcap_t *_handle, AP_info **ap_info, int *info_size) // WIPS Start
{
    char *Device_whitelist = "/home/shunn2/wips1/bob-WIPS/Device_whitelist.txt"; // Device_whitelist file
    char *AP_whitelist = "/home/shunn2/wips1/bob-WIPS/AP_whitelist.txt"; // AP_whitelist file
    char *SSID_whitelist = "/home/shunn2/wips1/bob-WIPS/SSID_whitelist.txt"; // SSID_whitelist file
    int Device, AP, SSID;

    struct pcap_pkthdr *header;
    const unsigned char *pkt_data;

    int datalen = 0;
    pcap_next_ex(_handle, &header, &pkt_data);

    struct radiotap_header *rah;
    rah = (struct radiotap_header *)(pkt_data);
    datalen += sizeof(*rah);

    struct ieee80211_frame *fc;
    fc = (struct ieee80211_frame *)(pkt_data + datalen);
    datalen += sizeof(*fc);

    uint8_t MGT = fc->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    uint8_t subtype = fc->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
    uint8_t DS = fc->i_fc[1] & IEEE80211_FC0_SUBTYPE_MASK;

    if (MGT == IEEE80211_FC0_TYPE_MGT)
    {
        if (subtype == IEEE80211_FC0_SUBTYPE_BEACON) //Beacon frame
        {
            datalen += 12; //fixed param jump;
            ssid_tag *ssid_p = (ssid_tag *)(pkt_data + datalen);
            datalen = datalen + sizeof(*ssid_p); // +2Bytes(tag_num, tag_len)
            for (int i = 0; i < *info_size; i++) // ap_info array size
            {
                if (is_equal(ap_info[i]->mac, fc->i_addr2, MAC_len))
                {
                    datalen += ssid_p->tag_len;                      // +ssid length
                    if (P2P_param(pkt_data, &datalen, header, 0xdd)) // tag_num = 0xdd
                    { 
                        ap_info[i]->state = ad_hoc;
                    }
                return 0;
                }
                
            }
            ap_info[*info_size] = (AP_info *)calloc(1, sizeof(AP_info)); // AP_info list memory allocation
            memcpy(ap_info[*info_size]->mac, fc->i_addr2, MAC_len);                           // AP mac copy
            memcpy(ap_info[*info_size]->ssid, ((char *)pkt_data + datalen), ssid_p->tag_len); // AP SSID copy
            datalen += ssid_p->tag_len;
            if (P2P_param(pkt_data, &datalen, header, 0xdd)) // P2P check
                ap_info[*info_size]->state = ad_hoc; // P2P AP
            else if (SSID_comp(ap_info[*info_size]->ssid, SSID_whitelist))// SSID compare
            { 
                if (mac_comp(fc->i_addr2, AP_whitelist)) // Mac compare
                    ap_info[*info_size]->state = Authorized_AP; // == SSID, == Mac
                else
                    ap_info[*info_size]->state = honeypot_AP; // == SSID, != Mac
            }
            else
                ap_info[*info_size]->state = rouge_AP; // !=SSID, != Mac
            (*info_size)++;
        }
        else if ((subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ) || (subtype == IEEE80211_FC0_SUBTYPE_REASSOC_REQ)) // re/association request frame
        {
            for (int i = 0; i < *info_size; i++)
            {
                if (ap_info[i]->state == ad_hoc && is_equal(ap_info[i]->mac, fc->i_addr1, MAC_len)) // ad-hoc AP
                {
                    printf("Re/Association\t\t\t");
                    print_mac(fc->i_addr2, 0); // Device_Mac
                    printf("\t\t");
                    print_mac(fc->i_addr1, 1); // AP_Mac
                    printf("\t\t");
                    printf("Ad-Hoc Device\t\t\t");
                    printf("send deauth");
                    send_deauth(fc->i_addr1, fc->i_addr2, fc->i_addr1, _handle);
                    return 1;
                }
            }
            if (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ)
                datalen += 4; // association: fixed param = 4
            else
                datalen += 10; // reassociation: fixed param = 10
            AP = mac_comp(fc->i_addr1, AP_whitelist); // Authorized AP = 1, Rouge AP = 0
            Device = mac_comp(fc->i_addr2, Device_whitelist); // Authorized Device = 1, Rouge Device = 0
            if (AP + Device == 1)                           // Rouge AP or Rouge Device
            {
                printf("Re/Association\t\t\t");
                if (AP == 1) // Rouge Device
                {
                    print_mac(fc->i_addr2, 1); // Device_Mac
                    printf("\t\t");
                    print_mac(fc->i_addr1, 0); // AP_Mac
                    printf("\t\t");
                    printf("Rouge Device\t\t\t");
                }
                else // Rouge AP
                {
                    print_mac(fc->i_addr2, 0); // Device_Mac
                    printf("\t\t");
                    print_mac(fc->i_addr1, 1); // AP_Mac
                    printf("\t\t");
                    ssid_tag *ssid_p = (ssid_tag *)(pkt_data + datalen);
                    datalen = datalen + sizeof(*ssid_p);

                    char SSID[30];
                    memcpy(SSID, pkt_data + datalen, ssid_p->tag_len); // SSID copy
                    datalen = datalen + sizeof(ssid_p->tag_len);

                    if (SSID_comp(SSID, SSID_whitelist)) // SSID compare
                        printf("Honeypot AP\t\t\t"); // == SSID, != Mac
                    else
                        printf("Rouge AP\t\t\t"); // != SSID, != Mac
                }
                printf("send deauth");
                send_deauth(fc->i_addr1, fc->i_addr2, fc->i_addr1, _handle);
                return 1;
            }
            else if (AP + Device == 2) // Authorization AP, Device
            {
                if (WPA_mode(pkt_data, &datalen, header, 0x30)) // WPA2 check => 0x30(RSN tag)
                {
                    RSN *rsn = (RSN *)(pkt_data + datalen);
                    if ((rsn->G_enc != RSN_CSE_CCMP) || (rsn->P_enc != RSN_CSE_CCMP) || (rsn->auth != RSN_ASE_8021X_PSK)) // encryption and authentication check
                    {
                        printf("Re/Association\t\t\t");
                        print_mac(fc->i_addr2, 0); // Device
                        printf("\t\t");
                        print_mac(fc->i_addr1, 1); // AP
                        printf("\t\t");
                        printf("Mis_configure AP(Enc/Auth)\t");
                        send_deauth(fc->i_addr1, fc->i_addr2, fc->i_addr1, _handle);
                        printf("send deauth");
                        return 1;
                    }
                }
                else
                {
                    printf("Re/Association\t\t\t");
                    print_mac(fc->i_addr2, 0); // Device
                    printf("\t\t");
                    print_mac(fc->i_addr1, 1); // AP
                    printf("\t\t");
                    printf("Mis_configure AP(WPA mode)\t");
                    send_deauth(fc->i_addr1, fc->i_addr2, fc->i_addr1, _handle);
                    printf("send deauth");
                    return 1;
                }
            }
        }
    }
    else if (MGT == IEEE80211_FC0_TYPE_DATA) // Data
    {
        if (subtype == IEEE80211_FC0_SUBTYPE_QOS) // QoS Frame
        {
            if (DS = 0x01) // Device to AP
            {
                for (int i = 0; i < *info_size; i++) // ad-hoc AP check
                {
                    if (ap_info[i]->state == ad_hoc && is_equal(ap_info[i]->mac, fc->i_addr1, MAC_len))
                    {
                        printf("QoS Data\t\t\t");
                        print_mac(fc->i_addr2, 0); // Device
                        printf("\t\t");
                        print_mac(fc->i_addr1, 1); // AP
                        printf("\t\t");
                        printf("Ad-Hoc Device\t\t\t");
                        printf("send deauth");
                        send_deauth(fc->i_addr1, fc->i_addr2, fc->i_addr1, _handle);
                        return 1;
                    }
                }
                AP = mac_comp(fc->i_addr1, AP_whitelist);
                Device = mac_comp(fc->i_addr2, Device_whitelist);
                if (AP + Device == 1)
                {
                    printf("QoS Data\t\t\t");
                    if (AP == 1)
                    {
                        print_mac(fc->i_addr2, 1); // Device
                        printf("\t\t");
                        print_mac(fc->i_addr1, 0); // AP
                        printf("\t\t");
                        printf("Rouge Device\t\t\t");
                    }
                    else
                    {
                        print_mac(fc->i_addr2, 0); // Device
                        printf("\t\t");
                        print_mac(fc->i_addr1, 1); // AP
                        printf("\t\t");
                        printf("Rouge AP\t\t\t");
                    }
                    send_deauth(fc->i_addr1, fc->i_addr2, fc->i_addr1, _handle);
                    printf("send deauth");
                    return 1;
                }
            }
            else // AP to Device
            {
                for (int i = 0; i < *info_size; i++) // ad-hoc AP check
                {
                    if (ap_info[i]->state == ad_hoc && is_equal(ap_info[i]->mac, fc->i_addr2, MAC_len))
                    {
                        printf("QoS Data\t\t\t");
                        print_mac(fc->i_addr1, 0); // Device
                        printf("\t");
                        print_mac(fc->i_addr2, 1); // AP
                        printf("\t");
                        printf("Ad-Hoc Device\t\t\t");
                        printf("send deauth");
                        send_deauth(fc->i_addr1, fc->i_addr2, fc->i_addr2, _handle);
                        return 1;
                    }
                }
                AP = mac_comp(fc->i_addr2, AP_whitelist);
                Device = mac_comp(fc->i_addr1, Device_whitelist);
                if (AP + Device == 1)
                {
                    printf("QoS Data\t\t\t");
                    if (AP == 1)
                    {
                        print_mac(fc->i_addr1, 1); // Device
                        printf("\t\t");
                        print_mac(fc->i_addr2, 0); // AP
                        printf("\t\t\t");
                        printf("Rouge Device\t\t\t");
                    }
                    else
                    {
                        print_mac(fc->i_addr1, 0); // Device
                        printf("\t\t");
                        print_mac(fc->i_addr2, 1); // AP
                        printf("\t\t\t");
                        printf("Rouge AP\t\t\t");
                    }
                    send_deauth(fc->i_addr1, fc->i_addr2, fc->i_addr2, _handle);
                    printf("send deauth");
                    return 1;
                }
            }
        }
        else if (subtype == IEEE80211_FC0_SUBTYPE_DATA)
        {
            uint8_t broad[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
            AP = mac_comp(fc->i_addr2, AP_whitelist);
            Device = mac_comp(fc->i_addr3, Device_whitelist);
            if (!is_equal(fc->i_addr1, broad, MAC_len) && (AP + Device == 1))
            {
                // printf("Data\t\t\t\t");
                // if (AP == 1)
                // {
                //     print_mac(fc->i_addr3, 1); //Device
                //     printf("\t\t");
                //     print_mac(fc->i_addr2, 0); //AP
                //     printf("\t\t");
                //     printf("Rouge Device\t\t\t");
                // }
                // else
                // {
                //     print_mac(fc->i_addr3, 0); //Device
                //     printf("\t\t");
                //     print_mac(fc->i_addr2, 1); //AP
                //     printf("\t\t");
                //     printf("Rouge AP\t\t\t");
                // }
                send_deauth(fc->i_addr2, fc->i_addr3, fc->i_addr2, _handle);
                //printf("send deauth");
                return 1;
            }
        }
    }
    return 0;
}

void file_open(char *file_name)
{
    FILE *f;
    char buffer[100], *line;
    int count = 1;

    f = fopen(file_name, "r");
    while (!feof(f))
    {
        line = fgets(buffer, 100, f);
        if(line == NULL) break;
        printf("- %s", line);
        count++;
    }
    printf("\n\n");
    fclose(f);
}

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    if (!(handle = pcap_open_live("wlan0mon", BUFSIZ, 1, 1, errbuf)))
    {
        fprintf(stderr, "Not interface\n");
        return -1;
    }

    //WIPS log
    printf("\n**WIPS**\n\n");
    printf("\033[1;36m< White_list >\033[0m\n\n");
    printf("[Device]\n");
    file_open("/home/shunn2/wips1/bob-WIPS/Device_whitelist.txt");
    printf("[AP]\n");
    file_open("/home/shunn2/wips1/bob-WIPS/AP_whitelist.txt");
    printf("\n\033[1;36m< Policy >\033[0m\n\n");
    printf(" - Rouge AP/Device\n");
    printf(" - Honey Pot\n");
    printf(" - Mis Configure\n");
    printf(" - Ad-Hoc\n\n\n\n");

    printf("\033[35m[Packet]\t\t\t[Device]\t\t\t[AP]\t\t\t\t[Info]\t\t\t\t[Event]\n\033[0m");

    // log Coordinates
    int x = 40, y = 5;
    int init_x = 0, init_y = 24;

    gotoxy(x, y);
    printf("\033[1;36m< < < Scan AP Info > > > \033[0m");
    y += 2;

    AP_info **ap_info = (AP_info **)malloc(sizeof(AP_info *) * 20); // AP_info memory allocation
    int info_size = 0;
    int temp = 0;
    while (1)
    {
        gotoxy(init_x, init_y);
        init_y += packet_scan(handle, ap_info, &info_size); // WIPS
        if (info_size > temp)
        {
            gotoxy(x, y);
            print_mac(ap_info[temp]->mac, 0);
            printf("[%s] = ", ap_info[temp]->ssid);
            switch (ap_info[temp]->state)
            {
            case Authorized_AP:
                printf("\033[36mAuthorized AP\033[0m\n");
                break;
            case rouge_AP:
                printf("\033[31mRouge AP\033[0m\n");
                break;
            case ad_hoc:
                printf("\033[31mAd-Hoc AP\033[0m\n");
                break;
            case honeypot_AP:
                printf("\033[31mHoneypot AP\033[0m\n");
                break;
            }
            y++;
            temp++;
        }
    }

    free(ap_info);
    printf("Exit\n");

    return 0;
}
