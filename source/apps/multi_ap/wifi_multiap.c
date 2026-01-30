/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2025 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 **************************************************************************/

#include <arpa/inet.h>
#include <errno.h>
#include <linux/filter.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include <poll.h>
#include <sys/prctl.h>

#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_multiap.h"
#include "wifi_stubs.h"
#include "wifi_util.h"
#include "scheduler.h"

#define FAILOVER_ENABLE "Device.X_RDK_GatewayManagement.Failover.Enable"
#define MULTIAP_RESP_TIMEOUT (1000)
#define MULTIAP_CONNECT_TIMEOUT (60000 * 2)

static int create_autoconfig_search(unsigned char *buff, char *ifname);
static int send_frame(unsigned char *buff, unsigned int len, bool multicast, char *ifname);
static void send_multiap_broadcast_message(char *ifname);
static int receive_multiap_message();
static int create_autoconfig_resp_msg(unsigned char *buff, unsigned char *dst, char *interface_name);
static int parse_multiap_tlv(unsigned char *buff, unsigned int len, multiap_tlv_type_t type,
    void *out_buff, size_t out_len);

static int sockets[MAX_IFACES] = { -1 };
static int socket_count = 0;
static int send_sock = -1;
pthread_t tid;

static volatile multiap_state_t state = multiap_state_none;

static int get_service_type()
{
    wifi_ctrl_t *ctrl = NULL;
    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    if (ctrl->network_mode == rdk_dev_mode_type_gw) {
        wifi_util_info_print(WIFI_APPS, "Gateway mode  %s:%d\n", __func__, __LINE__);
        return multiap_service_type_gateway;
    }
    else if (ctrl->network_mode == rdk_dev_mode_type_ext) {
        wifi_util_info_print(WIFI_APPS, "Extender mode  %s:%d\n", __func__, __LINE__);
        return multiap_service_type_extender;
    }
    else {
        wifi_util_error_print(WIFI_APPS, "UnSupported type %s:%d\n", __func__, __LINE__);
        return multi_service_type_none;
    }
}


static int parse_multiap_tlv(unsigned char *buff, unsigned int len, multiap_tlv_type_t type,
    void *out_buff, size_t out_len)
{
    unsigned int start = sizeof(multiap_raw_hdr_t) + sizeof(multiap_cmdu_t);
    unsigned int remaining;
    int rlen = -1;

    if (!buff || !out_buff || len < sizeof(multiap_raw_hdr_t) + sizeof(multiap_cmdu_t)) {
        wifi_util_error_print(WIFI_APPS, "Invalid input parameters to parse_multiap_tlvs\n");
        return -1;
    }

    wifi_util_info_print(WIFI_APPS, "In parse_multiap_tlvs function.\n");

    remaining = len - start;
    multiap_tlv_t *tlv = (multiap_tlv_t *)&buff[start];

    while (remaining > (int)sizeof(multiap_tlv_t) && tlv->type != multiap_tlv_type_eom) {
        unsigned short tlv_len = ntohs(tlv->len);

        // Safety: ensure we don’t read beyond buffer
        if (tlv_len > remaining - (int)sizeof(multiap_tlv_t)) {
            wifi_util_error_print(WIFI_APPS, "TLV length exceeds remaining buffer\n");
            return -1;
        }

        if (tlv->type == type) {
            // found requested tlv break from while
            break;
        }
        // Move to next TLV
        remaining -= sizeof(multiap_tlv_t) + tlv_len;
        tlv = (multiap_tlv_t *)((unsigned char *)tlv + sizeof(multiap_tlv_t) + tlv_len);
    }
    if (tlv->type != type) {
        wifi_util_error_print(WIFI_APPS, "Requested TLV type not found\n");
        return -1;
    }

    rlen = ntohs(tlv->len);
    if (out_len < (size_t)rlen) {
        wifi_util_error_print(WIFI_APPS, "Not enough memory\n");
        return -1;
    }

    switch (type) {
    case multiap_tlv_type_al_mac_address: {
        wifi_util_info_print(WIFI_APPS, "Found AL MAC Address TLV\n");
        memcpy(out_buff, tlv->value, rlen);
        wifi_util_info_print(WIFI_APPS, "%s:%d len=%d\n", __func__, __LINE__, ntohs(tlv->len));
    } break;

    case multiap_tlv_type_supported_service: {
        multiap_supported_srv_t *stlv = (multiap_supported_srv_t *)out_buff;

        wifi_util_info_print(WIFI_APPS, "Found Supported Service TLV\n");
        stlv->num_service = tlv->value[0];
        wifi_util_info_print(WIFI_APPS, "%s:%d: stlv->num_service=0x%x\n", __func__, __LINE__,
            stlv->num_service);
        memcpy(&stlv->supported_service, &tlv->value[1], tlv->value[0]);
        wifi_util_info_print(WIFI_APPS, "%s:%d stlv->supported_service=0x%x  len=%d\n", __func__, __LINE__,
            stlv->supported_service, ntohs(tlv->len));
    } break;

    case multiap_tlv_type_sta_mac_addr: {
        wifi_util_info_print(WIFI_APPS, "Found STA MAC Address TLV\n");
        memcpy(out_buff, tlv->value, rlen);
        wifi_util_info_print(WIFI_APPS, "%s:%d rlen=%d\n", __func__, __LINE__, rlen);
    } break;

    default:
        wifi_util_error_print(WIFI_APPS, "Unknown TLV type requested. ******* \n");
        rlen = -1;
        break;
    }

    return rlen;
}

static int handle_autoconf_search(unsigned char *data, unsigned int len)
{
    unsigned char msg[MAX_BUFF_SZ];
    mac_address_t dst;
    wifi_ctrl_t *ctrl = NULL;
    char st[64];
    char *ifaces[MAX_IFACES] = { "brlan0", "wl1", "wl0.1", "wl0", "wl0.7", "wl1.7", "wl2.1", "wl1.1" };
    unsigned char buff[128] = { 0 };
    multiap_supported_srv_t *srv = (multiap_supported_srv_t *)buff;
    int device_supporting_service = get_service_type();
    wifi_util_info_print(WIFI_APPS, "%s:%d device_supporting_service = %d\n", __func__, __LINE__, device_supporting_service);
    //Extract Supported Service TLV
    if (parse_multiap_tlv(data, len, multiap_tlv_type_supported_service, srv, sizeof(buff)) < 0) {
        wifi_util_error_print(WIFI_APPS, "%s:%d Service type TLV not found\n", __func__, __LINE__);
        return -1;
    }
    
    if (device_supporting_service == multiap_service_type_extender ||
        srv->supported_service[0] == multiap_service_type_extender) {
        wifi_util_error_print(WIFI_APPS,
            "%s:%d Either supporting service or supported service is extender so not replying\n",
            __func__, __LINE__);
        return -1;
    }
    wifi_util_info_print(WIFI_APPS, "%s:%d Split brain is detected in the network\n",__func__, __LINE__);

    state = multiap_state_completed;
    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    // Extract AL MAC address
    if (parse_multiap_tlv(data, len, multiap_tlv_type_al_mac_address,&dst, sizeof(mac_address_t)) <
        0) {
        wifi_util_error_print(WIFI_APPS, "%s:%d AL MAC address TLV not found\n",__func__, __LINE__);
        return -1;
    }

    uint8_mac_to_string_mac(dst, st);
    wifi_util_info_print(WIFI_APPS, "%s:%d Sender mac=%s\n",__func__, __LINE__, st);
    for (int i = 0; i < MAX_IFACES; ++i) {
        len = create_autoconfig_resp_msg(msg, (unsigned char *)dst, ifaces[i]);
        wifi_util_error_print(WIFI_APPS, "%s:%d After create_autoconfig_resp_msg got len=%d\n",
        __func__, __LINE__, len);
        send_frame(msg, len, false, ifaces[i]);
    }
    wifi_util_info_print(WIFI_APPS, "%s:%d Autoconfig response is sent to Gateway\n",__func__, __LINE__);

    set_to_extender_mode(&ctrl->handle, FAILOVER_ENABLE, 0, 0);

    set_to_extender_mode(&ctrl->handle, WIFI_DEVICE_MODE, 1, 1);

    wifi_util_info_print(WIFI_APPS,"%s:%d Switching the device to Extender mode, Split brain Recovered\n",__func__, __LINE__);
    return 0;
}

static int handle_autoconf_search_resp(unsigned char *data, unsigned int len)
{
    int tlv_len, total_macs;
    unsigned int itr = 0, itrj = 0;
    mac_address_t mac;
    int vap_index = 0;
    rdk_wifi_vap_info_t *rdk_vap_info = NULL;
    mac_address_t zero_mac = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    acl_entry_t *acl_entry = NULL;
    acl_entry_t *temp_acl_entry = NULL;
    mac_addr_str_t new_mac_str;
    char macfilterkey[128];
    unsigned char buffer[100] = { 0 };
    int rc = 0;
    wifi_vap_info_map_t *wifi_vap_map = NULL;

    wifi_util_info_print(WIFI_APPS, "%s:%d Enter\n",__func__, __LINE__);
    memset(macfilterkey, 0, sizeof(macfilterkey));
    //  Extract STA MAC addresses
    tlv_len = parse_multiap_tlv(data, len, multiap_tlv_type_sta_mac_addr, buffer, sizeof(buffer));
    if (tlv_len < 0) {
        wifi_util_error_print(WIFI_APPS, "%s:%d STA MAC address TLV not found\n",__func__, __LINE__);
        return -1;
    }
    // This is the retriving mechanism from the TLV
    total_macs = tlv_len / MAC_ADDR_LEN;

    for (int i = 0; i < total_macs; ++i) {
        memcpy(mac, &buffer[i * MAC_ADDR_LEN], MAC_ADDR_LEN);
        to_mac_str(mac, new_mac_str);
        str_tolower(new_mac_str);
        wifi_util_info_print(WIFI_APPS, "STA mac_str[%d]=%s\n", i, new_mac_str);
        for (itr = 0; itr < getNumberRadios(); itr++) {
            wifi_vap_map = get_wifidb_vap_map(itr);
            for (itrj = 0; itrj < getMaxNumberVAPsPerRadio(itr); itrj++) {
                vap_index = wifi_vap_map->vap_array[itrj].vap_index;
                wifi_util_info_print(WIFI_APPS, "%s:%d vap_index=%d\n",__func__, __LINE__,vap_index);
                rdk_vap_info = get_wifidb_rdk_vap_info(vap_index);

                if (rdk_vap_info == NULL) {
                    wifi_util_error_print(WIFI_APPS, "rdk_vap_info is NULL\n");
                    return rc;
                }

                if ((strstr(rdk_vap_info->vap_name, "mesh_backhaul") == NULL)) {
                    continue;
                }

                if (rdk_vap_info->acl_map == NULL) {
                    wifi_util_error_print(WIFI_APPS, "GreyList acl_map is NULL\n");
                    rdk_vap_info->acl_map = hash_map_create();
                }

                if (memcmp(mac, zero_mac, sizeof(mac_address_t)) == 0) {
                    wifi_util_error_print(WIFI_APPS, "GreyList new_mac is zero mac \n");
                    return rc;
                }

                to_mac_str(mac, new_mac_str);
                str_tolower(new_mac_str);
                wifi_util_info_print(WIFI_APPS, "%s:%d new_mac_str %s\n",__func__, __LINE__, new_mac_str);
                temp_acl_entry = hash_map_get(rdk_vap_info->acl_map, new_mac_str);

                if (temp_acl_entry != NULL) {
                    wifi_util_info_print(WIFI_APPS, "Mac is already present in macfilter \n");
                    continue;
                }
                acl_entry = (acl_entry_t *)malloc(sizeof(acl_entry_t));
                memcpy(acl_entry->mac, mac, sizeof(mac_address_t));
                to_mac_str(acl_entry->mac, new_mac_str);
                str_tolower(new_mac_str);

#ifdef NL80211_ACL
                wifi_util_info_print(WIFI_APPS, "%s : %d rdk_vap_info->vap_index =%d.\n",__func__, __LINE__,rdk_vap_info->vap_index);
                if (wifi_hal_addApAclDevice(rdk_vap_info->vap_index, new_mac_str) != RETURN_OK) {
#else
                if (wifi_addApAclDevice(rdk_vap_info->vap_index, new_mac_str) != RETURN_OK) {
#endif
                    wifi_util_info_print(WIFI_APPS, "%s:%d wifi_addApAclDevice failed. vap_index %d, MAC %s \n",
                        __func__,__LINE__, rdk_vap_info->vap_index, new_mac_str);
                    continue;
                }

                hash_map_put(rdk_vap_info->acl_map, strdup(new_mac_str), acl_entry);
                snprintf(macfilterkey, sizeof(macfilterkey), "%s-%s", rdk_vap_info->vap_name, new_mac_str);
            }
        }
    }
    return 0;
}
static int create_autoconfig_search(unsigned char *buff, char *interface_name)
{
    unsigned short msg_id = multiap_msg_type_autoconf_search;
    static unsigned msg_num = 0;
    int len = 0;
    multiap_cmdu_t *cmdu;
    multiap_tlv_t *tlv;
    multiap_enum_type_t searched, profile;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    char st[64] = { 0 };
    mac_address_t multi_addr = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    mac_address_t src_addr;
    multiap_service_type_t service_type = multiap_service_type_gateway;
    unsigned char registrar = 0;
    multiap_freq_band_t freq_band;
    mac_address_from_name(interface_name, src_addr);

    uint8_mac_to_string_mac(src_addr, st);
    wifi_util_info_print(WIFI_APPS, "st from mac_address_from_name =%s\n", st);

    memcpy(tmp, (unsigned char *)multi_addr, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += (int)(sizeof(mac_address_t));

    memcpy(tmp, (unsigned char *)src_addr, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += (int)(sizeof(mac_address_t));

    memcpy(tmp, (unsigned char *)&type, sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += (int)(sizeof(unsigned short));
    cmdu = (multiap_cmdu_t *)tmp;

    memset(tmp, 0, sizeof(multiap_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = msg_num;
    msg_num++;
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 1;

    tmp += sizeof(multiap_cmdu_t);
    len += (int)(sizeof(multiap_cmdu_t));

    // AL MAC Address type TLV
    tlv = (multiap_tlv_t *)tmp;
    tlv->type = multiap_tlv_type_al_mac_address;
    tlv->len = htons(sizeof(mac_address_t));
    memcpy(tlv->value, (unsigned char *)src_addr, sizeof(mac_address_t));

    tmp += (sizeof(multiap_tlv_t) + sizeof(mac_address_t));
    len += (int)(sizeof(multiap_tlv_t) + sizeof(mac_address_t));

    // 6-22—SearchedRole TLV
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_searched_role;
    tlv->len = htons(sizeof(unsigned char));
    memcpy(&tlv->value, &registrar, sizeof(unsigned char));

    tmp += (sizeof(multiap_tlv_t) + 1);
    len += (int)(sizeof(multiap_tlv_t) + 1);

    // 6-23—autoconf_freq_band TLV
    freq_band = multiap_freq_band_5;
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_autoconf_freq_band;
    tlv->len = htons(sizeof(unsigned char));
    memcpy(&tlv->value, &freq_band, sizeof(unsigned char));

    tmp += (sizeof(multiap_tlv_t) + 1);
    len += (int)(sizeof(multiap_tlv_t) + 1);

    // supported service 17.2.1
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_supported_service;
    tlv->len = htons(sizeof(multiap_enum_type_t) + 1);
    // Number of services
    tlv->value[0] = 1;
    memcpy(&tlv->value[1], &service_type, sizeof(multiap_enum_type_t));

    tmp += (sizeof(multiap_tlv_t) + sizeof(multiap_enum_type_t) + 1);
    len += (int)(sizeof(multiap_tlv_t) + sizeof(multiap_enum_type_t) + 1);

    // searched service 17.2.2
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_searched_service;
    tlv->len = htons(sizeof(multiap_enum_type_t) + 1);
    tlv->value[0] = 1;
    searched = multiap_service_type_gateway;
    memcpy(&tlv->value[1], &searched, sizeof(multiap_enum_type_t));

    tmp += (sizeof(multiap_tlv_t) + sizeof(multiap_enum_type_t) + 1);
    len += (int)(sizeof(multiap_tlv_t) + sizeof(multiap_enum_type_t) + 1);

    // One multiAP profile tlv 17.2.47
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_profile;
    tlv->len = htons(sizeof(multiap_enum_type_t));
    profile = 3;
    memcpy(tlv->value, &profile, sizeof(multiap_enum_type_t));

    tmp += (sizeof(multiap_tlv_t) + sizeof(multiap_enum_type_t));
    len += (int)(sizeof(multiap_tlv_t) + sizeof(multiap_enum_type_t));

    // End of message
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof(multiap_tlv_t));
    len += (int)(sizeof(multiap_tlv_t));

    return len;
}

static int send_frame(unsigned char *buff, unsigned int len, bool multicast, char *ifname)
{
    int ret = 0;
    multiap_raw_hdr_t *hdr = (multiap_raw_hdr_t *)(buff);

    struct sockaddr_ll sadr_ll;
    mac_address_t multi_addr = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    sadr_ll.sll_ifindex = (int)(if_nametoindex(ifname));
    // length of destination mac address
    sadr_ll.sll_halen = ETH_ALEN;
    sadr_ll.sll_protocol = htons(ETH_P_ALL);
    memcpy(sadr_ll.sll_addr, (multicast == true) ? multi_addr : hdr->dst, sizeof(mac_address_t));

    ret = (int)(sendto(send_sock, buff, len, 0, (const struct sockaddr *)&sadr_ll,
        sizeof(struct sockaddr_ll)));
    wifi_util_info_print(WIFI_APPS, "Sent frame on %s len:%d ret val =%d\n", ifname, len, ret);
    return ret;
}

static void send_multiap_broadcast_message(char *ifname)
{
    unsigned char buff[MAX_BUFF_SZ];
    unsigned int sz;
    wifi_util_info_print(WIFI_APPS, "%s:%d ifname = %s\n", __func__, __LINE__, ifname);

    //wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_util_info_print(WIFI_APPS, "%s:%d: ifname = %s\n", __func__, __LINE__, ifname);
    if (multiap_service_type_extender == get_service_type() ) {
        wifi_util_info_print(WIFI_APPS,
            "%s:%d:service type is extender or broadcast message is sent so returning \n", 
            __func__, __LINE__);
        return;
    }

    sz = create_autoconfig_search(buff, ifname);
    wifi_util_info_print(WIFI_APPS, "%s:%d IEEE1905: Autoconfig search message created, size=%u\n",
        __func__, __LINE__, sz);

    if (send_frame(buff, sz, true, ifname) < 0) {
        wifi_util_info_print(WIFI_APPS, "%s:%d: failed, err:%d\n", __func__, __LINE__);
        return;
    }

    wifi_util_info_print(WIFI_APPS, "IEEE1905: autoconfig_search send successful and state =%d \n", state);
    /* After sending for Autofconfig search for 50 times if no reply is
        seen then the other device s in extender mode*/
}

static int set_bp_filter(int sockfd, const char *iface_name)
{
    struct packet_mreq mreq;
    #define OP_LDH (BPF_LD  | BPF_H   | BPF_ABS)
    #define OP_LDB (BPF_LD  | BPF_B   | BPF_ABS)
    #define OP_JEQ (BPF_JMP | BPF_JEQ | BPF_K)
    #define OP_RET (BPF_RET | BPF_K)
    static struct sock_filter bpfcode[4] = {
           { OP_LDH, 0, 0, 12          },  // ldh [12]
           { OP_JEQ, 0, 1, ETH_P_1905  },  // jeq #0x893a, L2, L3
           { OP_RET, 0, 0, 0xffffffff,         },  // ret #0xffffffff
           { OP_RET, 0, 0, 0           },  // ret #0x0
    };
    struct sock_fprog bpf = { 4, bpfcode };

    if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf))) {
        wifi_util_info_print(WIFI_CTRL,"%s:%d: IEEE1905: Error in attaching filter, err:%d\n", __func__, __LINE__, errno);
        close(sockfd);
        return -1;
    }
    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_type = PACKET_MR_PROMISC;
    mreq.mr_ifindex = (int)(if_nametoindex(iface_name));

    if (setsockopt(sockfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq))) {
        wifi_util_info_print(WIFI_CTRL,"%s:%d: IEEE1905: Error setting promisuous for interface:%s, err:%d\n", __func__, __LINE__,iface_name, errno);
        close(sockfd);
        return -1;
    }
    return 0;
}

static int create_raw_socket(const char *iface_name)
{
    int sockfd;
    struct sockaddr_ll sll;
    // Create raw socket
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        wifi_util_info_print(WIFI_APPS, "socket\n");
        return -1;
    }

    // Bind to interface
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = (int)(if_nametoindex(iface_name));
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
        wifi_util_info_print(WIFI_APPS, "bind error\n");
        close(sockfd);
        return -1;
    }
    set_bp_filter(sockfd, iface_name);

    return sockfd;
}

static int create_autoconfig_resp_msg(unsigned char *buff, unsigned char *dst, char *interface_name)
{
    unsigned short msg_id = multiap_msg_type_autoconf_resp;
    int len = 0;
    multiap_cmdu_t *cmdu;
    multiap_tlv_t *tlv;
    multiap_enum_type_t profile;
    multiap_ctrl_cap_t ctrl_cap;
    multiap_ieee_1905_security_cap_t sec_info_cap;
    unsigned char *tmp = buff;
    unsigned char src_addr[64];
    unsigned char mac_buffer[100] = { 0 };
    char st[64] = { 0 };
    mac_address_t mac;
    unsigned int itr = 0, offset = 0;
    unsigned short type = htons(ETH_P_1905);
    unsigned char registrar = 0;
    multiap_freq_band_t band = multiap_freq_band_5;
    multiap_service_type_t service_type = get_service_type();
    mac_address_from_name(interface_name, src_addr);
    wifi_mgr_t *g_wifi_mgr = (wifi_mgr_t *)get_wifimgr_obj();

    uint8_mac_to_string_mac(src_addr, st);
    wifi_util_info_print(WIFI_APPS, "string from mac_address_from_name %s =%s\n", interface_name, st);
    uint8_mac_to_string_mac(dst, st);
    wifi_util_info_print(WIFI_APPS, "string from mac_address_from_name of dest==%s\n", st);

    memcpy(tmp, (unsigned char *)dst, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += (int)(sizeof(mac_address_t));

    memcpy(tmp, (unsigned char *)src_addr, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += (int)(sizeof(mac_address_t));

    memcpy(tmp, (unsigned char *)(&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += (int)(sizeof(unsigned short));
    cmdu = (multiap_cmdu_t *)(tmp);

    memset(tmp, 0, sizeof(multiap_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = msg_id;
    msg_id++;
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 1;

    tmp += sizeof(multiap_cmdu_t);
    len += (int)(sizeof(multiap_cmdu_t));

    // 6-24—SupportedRole TLV
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_supported_role;
    tlv->len = htons(sizeof(unsigned char));
    memcpy(&tlv->value, &registrar, sizeof(unsigned char));

    tmp += (sizeof(multiap_tlv_t) + 1);
    len += (int)(sizeof(multiap_tlv_t) + 1);

    // 6-25—supported freq_band TLV
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_supported_freq_band;
    tlv->len = htons(sizeof(unsigned char));
    memcpy(&tlv->value, &band, sizeof(unsigned char));

    tmp += (sizeof(multiap_tlv_t) + 1);
    len += (int)(sizeof(multiap_tlv_t) + 1);

    // supported service tlv 17.2.1
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_supported_service;
    tlv->len = htons(sizeof(multiap_enum_type_t) + 1);
    tlv->value[0] = 1;
    memcpy(&tlv->value[1], &service_type, sizeof(multiap_enum_type_t));

    tmp += (sizeof(multiap_tlv_t) + sizeof(multiap_enum_type_t) + 1);
    len += (int)(sizeof(multiap_tlv_t) + sizeof(multiap_enum_type_t) + 1);

    // 1905 layer security capability tlv 17.2.67
    sec_info_cap.onboarding_proto = 0;
    sec_info_cap.integrity_algo = 1;
    sec_info_cap.encryption_algo = 0;
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_1905_layer_security_cap;
    tlv->len = htons(sizeof(multiap_ieee_1905_security_cap_t));
    memcpy(tlv->value, &sec_info_cap, sizeof(multiap_ieee_1905_security_cap_t));

    tmp += (sizeof(multiap_tlv_t) + sizeof(multiap_ieee_1905_security_cap_t));
    len += (int)(sizeof(multiap_tlv_t) + sizeof(multiap_ieee_1905_security_cap_t));

    // One multiAP profile tlv 17.2.47
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_profile;
    tlv->len = htons(sizeof(multiap_enum_type_t));
    profile = multiap_profile_type_3;
    memcpy(tlv->value, &profile, sizeof(multiap_enum_type_t));

    tmp += (sizeof(multiap_tlv_t) + sizeof(multiap_enum_type_t));
    len += (int)(sizeof(multiap_tlv_t) + sizeof(multiap_enum_type_t));

    // One controller capability tlv 17.2.94
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_ctrl_cap;
    tlv->len = htons(sizeof(multiap_ctrl_cap_t));
    memset(&ctrl_cap, 0, sizeof(multiap_ctrl_cap_t));

    memcpy(tlv->value, &ctrl_cap, sizeof(multiap_ctrl_cap_t));

    tmp += (sizeof(multiap_tlv_t) + sizeof(multiap_ctrl_cap_t));
    len += (int)(sizeof(multiap_tlv_t) + sizeof(multiap_ctrl_cap_t));

    // STA MAC Address type TLV
    tlv = (multiap_tlv_t *)tmp;
    tlv->type = multiap_tlv_type_sta_mac_addr;
    for (itr = 0; itr < getNumberRadios(); itr++) {
        wifi_util_info_print(WIFI_APPS, "%s:%d index=%d and getNumberRadios()=%d\n", __func__,
            __LINE__, itr, getNumberRadios());
        get_sta_mac_address_for_radio(&g_wifi_mgr->hal_cap.wifi_prop, itr, mac);
        uint8_mac_to_string_mac(mac, st);
        wifi_util_info_print(WIFI_APPS, "%s:%d mac_adr= %s\n", __func__, __LINE__, st);
        memcpy(&mac_buffer[offset], mac, MAC_ADDR_LEN);
        offset += MAC_ADDR_LEN;
    }

    tlv->len = htons(offset);
    wifi_util_info_print(WIFI_APPS, "%s:%d offset=%d\n", __func__, __LINE__, offset);
    memcpy(tlv->value, (unsigned char *)mac_buffer, offset);

    tmp += (sizeof(multiap_tlv_t) + offset);
    len += (int)(sizeof(multiap_tlv_t) + offset);
    // End of message
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof(multiap_tlv_t));
    len += (int)(sizeof(multiap_tlv_t));
    wifi_util_info_print(WIFI_APPS, "%s:%d len = %d\n", __func__, __LINE__, len);
    return len;
}

static void proto_process(unsigned char *data, unsigned int len)
{
    wifi_ctrl_t *ctrl;
    multiap_cmdu_t *cmdu;
    int ret = -1;
    multiap_raw_hdr_t *hdr = (multiap_raw_hdr_t *)(data);
    cmdu = (multiap_cmdu_t *)(data + sizeof(multiap_raw_hdr_t));

    if (memcmp(hdr->src, hdr->dst, sizeof(mac_address_t)) == 0) {
        wifi_util_info_print(WIFI_APPS, "%s:%d :Failed to initialize socket on\n", __func__,
            __LINE__);
        // This is a message that was sent to the same address it was sent fro
        return;
    }
    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_util_info_print(WIFI_APPS, "%s:%d :Got a valid packet of type =%d\n", __func__, __LINE__,
        htons(cmdu->type));

    switch (htons(cmdu->type)) {
    case multiap_msg_type_autoconf_search:
        if (is_device_type_xle()) {
        wifi_util_info_print(WIFI_APPS, "%s:%d IEEE1905: XLE Extender - processing autoconfig search from gateway\n",
            __func__, __LINE__);
            if (state == multiap_state_none) {
                wifi_util_info_print(WIFI_APPS, "%s:%d Got a Packet of type = %d. Processing it\n",
                    __func__, __LINE__, htons(cmdu->type));
                ret = handle_autoconf_search(data, len);
                if (ret == -1) {
                    wifi_util_info_print(WIFI_APPS,
                        "%s:%d Autoconfig search response not sent hence setting the State to none\n",
                        __func__, __LINE__);
                    state = multiap_state_none;
                } else {
                    wifi_util_info_print(WIFI_APPS,
                        "%s:%d Autoconfig search response sent moving to extender mode\n",
                        __func__, __LINE__);
                }
            }
        } else if (ctrl->network_mode == rdk_dev_mode_type_gw) {
            wifi_util_info_print(WIFI_APPS, "%s:%d IEEE1905: XB Gateway - ignoring autoconfig search (gateway mode)\n",
                __func__, __LINE__);
            return;
        }
        break;
    case multiap_msg_type_autoconf_resp:
        if (state == multiap_state_search_rsp_pending && ctrl->network_mode == rdk_dev_mode_type_gw) {
            wifi_util_info_print(WIFI_APPS, "%s:%d Got a valid packet of type =%d.Processing it\n",
                __func__, __LINE__, htons(cmdu->type));
            state = multiap_state_completed;
            handle_autoconf_search_resp(data, len);
            wifi_util_info_print(WIFI_APPS, "%s:%d Bringing down the station\n", __func__, __LINE__);
            if (is_sta_enabled() == false) {
                wifi_util_info_print(WIFI_APPS, "%s:%d stop mesh sta\n", __func__, __LINE__);
                stop_extender_vaps();
                ctrl->webconfig_state |= ctrl_webconfig_state_vap_mesh_sta_cfg_rsp_pending;
            }
        }
        break;
    default:
        wifi_util_info_print(WIFI_APPS, "%s:%d Got different Packet\n", __func__, __LINE__);
        break;
    }
}

static void *receive_multicast_message(void *ctx)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    const char *ifaces[MAX_IFACES] = { "wl1", "wl1.1", "wl0", "wl0.1", "brlan0", "wl1.7", "wl0.7" , "brlan1" };
    char buffer[MAX_FRAME_SZ];

    struct pollfd poll_fds[MAX_IFACES];

    for (int i = 0; i < socket_count; i++) {
        if (sockets[i] >= 0) {
            wifi_util_info_print(WIFI_APPS,"%s:%d Closing old socket %d\n",__func__, __LINE__, sockets[i]);
            close(sockets[i]);
            sockets[i] = -1;
        }
    }
    socket_count = 0;
    wifi_util_info_print(WIFI_APPS, "%s:%d Initializing sockets on interfaces\n", __func__, __LINE__);
    for (int i = 0; i < MAX_IFACES; ++i) {
        sockets[i] = create_raw_socket(ifaces[i]);
        if (sockets[i] < 0) {
            wifi_util_info_print(WIFI_APPS, "Failed to initialize socket on %s\n", ifaces[i]);
            return NULL;
        }
        /* Initialize pollfd entry */
        poll_fds[i].fd = sockets[i];
        poll_fds[i].events = POLLIN;
        poll_fds[i].revents = 0;

        socket_count++;
        wifi_util_info_print(WIFI_APPS, "%s:%d sockets[i]= %d\n", __func__, __LINE__, sockets[i]);
    }
    wifi_util_info_print(WIFI_CTRL, "%s:%d multiap_sta_enabled=%d\n", __func__, __LINE__,ctrl->multiap_sta_enabled);
    while (ctrl->multiap_sta_enabled == true) {
        wifi_util_info_print(WIFI_APPS, "%s:%d Waiting for data on %d sockets\n", __func__, __LINE__, socket_count);
        int ret = poll(poll_fds, socket_count, -1); // -1 = infinite timeout
        if (ret < 0) {
            wifi_util_error_print(WIFI_APPS, "%s:%d Poll error: %d\n", __func__, __LINE__, errno);
            break;
        } else if (ret == 0) {
            wifi_util_info_print(WIFI_APPS, "%s:%d Poll timeout\n", __func__, __LINE__);
            continue; // Timeout, continue waiting
        }

        // Check which sockets have data
        for (int i = 0; i < socket_count; ++i) {
            if (poll_fds[i].revents & POLLIN) {
                ssize_t len = recvfrom(sockets[i], buffer, sizeof(buffer), 0, NULL, NULL);
                if (len < 0) {
                    wifi_util_error_print(WIFI_APPS, "%s:%d: recvfrom error: %d\n", __func__, __LINE__, errno);
                    continue;
                }
                wifi_util_info_print(WIFI_APPS, "%s:%d Received %zd bytes on socket:%d(%s)\n",
                    __func__, __LINE__, len, sockets[i], ifaces[i]);
                if (len > 0) {
                    proto_process((unsigned char *)buffer, len);
                }
            }
            // Check for socket errors
            if (poll_fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                wifi_util_info_print(WIFI_APPS, "%s:%d Socket error on fd %d, revents: 0x%x\n",
                    __func__, __LINE__, sockets[i], poll_fds[i].revents);
                close(sockets[i]);
                sockets[i] = -1;
                /* Remove from poll list */
                poll_fds[i].fd = -1;
                poll_fds[i].events = 0;
                poll_fds[i].revents = 0;
            }
        }
    }
    wifi_util_info_print(WIFI_APPS, "%s:%d IEEE1905: receive_multicast_message thread exiting\n", __func__, __LINE__);
    return NULL;
}

static int receive_multiap_message()
{
    int ret;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    ret = pthread_create(&tid, &attr, receive_multicast_message, NULL);
    pthread_attr_destroy(&attr);
    if (ret != 0) {
        wifi_util_error_print(WIFI_APPS, "Failed to create thread\n");
        return -1;
    } else {
        wifi_util_info_print(WIFI_APPS, "Recv thread created successfully\n");
    }
    return 0;
}

static int multiap_event_exec_timeout(wifi_app_t *apps, void *arg)
{
    // Hardcoded interface names for debugging
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    const char *interfaces[] = {"wl1","wl0","brlan0"};
    unsigned int num_interfaces = sizeof(interfaces) / sizeof(interfaces[0]);
    wifi_util_info_print(WIFI_CTRL, "%s:%d multiap_sta_enabled=%d\n", __func__, __LINE__,ctrl->multiap_sta_enabled);
    if (ctrl->multiap_sta_enabled == false) {
        wifi_util_error_print(WIFI_APPS, "%s:%d called when multiap disabled\n",
            __func__, __LINE__);
        return RETURN_OK;
    }
    // Send autoconfiguration search on each interface
    for (unsigned int i = 0; i < num_interfaces; i++) {
        send_multiap_broadcast_message((char *)interfaces[i]);
    }

    return RETURN_OK;
}

static int multiap_timeout_fun(void* arg)
{
    wifi_ctrl_t *ctrl = NULL;
    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    if (state == multiap_state_search_rsp_pending) {
        static int count = 16;
        wifi_util_info_print(WIFI_CTRL, "%s:%d IEEE1905: wifi_event_exec_timeout.\n",__func__, __LINE__);
        apps_mgr_multiap_event(&ctrl->apps_mgr, wifi_event_type_exec, wifi_event_exec_timeout, NULL, 0);
         // Stop the scheduler
        scheduler_cancel_timer_task(ctrl->sched, ctrl->multiap_timer_id);
        if (count <= 0){
            count = 16;
            wifi_util_info_print(WIFI_APPS, "%s:%d Max send count reached,Stopping Send.\n",__func__, __LINE__);
            return RETURN_OK;
        }
        count--;
		scheduler_add_timer_task(ctrl->sched, FALSE, &ctrl->multiap_timer_id, multiap_timeout_fun,
		NULL, MULTIAP_RESP_TIMEOUT, 0, FALSE);
    } else if (state == multiap_state_sta_create_and_connect) {
        wifi_util_info_print(WIFI_APPS, "%s:%d IEEE1905: Failed to connect/find GW device within timeout\n",
            __func__, __LINE__);
        // Stop the scheduler
        scheduler_cancel_timer_task(ctrl->sched, ctrl->multiap_timer_id);
        wifi_util_info_print(WIFI_APPS, "%s:%d IEEE1905 Stopping Multiap App.\n", __func__, __LINE__);
        apps_mgr_multiap_event(&ctrl->apps_mgr, wifi_event_type_exec, wifi_event_exec_stop, NULL, 0);
    } else {
        wifi_util_info_print(WIFI_APPS, "%s:%d IEEE1905:(UNHANDLED CASE)  Timeout on state : %d\n",
            __func__, __LINE__, state);
        // Stop the scheduler
        scheduler_cancel_timer_task(ctrl->sched, ctrl->multiap_timer_id);
    }

    return RETURN_OK;
}

static int multiap_event_exec_start(wifi_app_t *apps, void *arg)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    wifi_util_info_print(WIFI_APPS, "%s:%d IEEE1905: Starting multiap event execution\n", __func__, __LINE__);
    if (ctrl == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d Ctrl is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (ctrl->rf_status_down || (ctrl->network_mode == rdk_dev_mode_type_ext)) {
        wifi_util_error_print(WIFI_APPS, "%s:%d Station not started: rf_status_down=%d, network_mode=%d (ext_mode=%d)\n",
        __func__, __LINE__, ctrl->rf_status_down, ctrl->network_mode, rdk_dev_mode_type_ext);
        return RETURN_ERR;
    }

    send_sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (send_sock < 0) {
        wifi_util_error_print(WIFI_APPS, "%s:%d Failed to create a send socket\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    /*start the station vaps only if none of the station is connected to vaps because in XLE when
    its in GW mode(with WAN failover) stations are connected to the GW then we should not start the station vaps*/
    if (!is_device_type_xle() && (ctrl->network_mode == rdk_dev_mode_type_gw)) {
        start_station_vaps(true, true);
        state = multiap_state_sta_create_and_connect;
        scheduler_add_timer_task(ctrl->sched, FALSE, &ctrl->multiap_timer_id, multiap_timeout_fun,
		NULL, MULTIAP_CONNECT_TIMEOUT, 0, FALSE);
        wifi_util_info_print(WIFI_APPS, "%s:%d IEEE1905: Registered multiap timer task\n", __func__, __LINE__);
    }
    return RETURN_OK;
}

static int multiap_event_exec_stop(wifi_app_t *apps, void *arg)
{
    wifi_ctrl_t *ctrl = NULL;
    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_util_info_print(WIFI_APPS, "%s:%d Inside\n", __func__, __LINE__);
    //Close global sockets
    for (int i = 0; i < socket_count; i++) {
        if (sockets[i] >= 0) {
            wifi_util_info_print(WIFI_APPS, "%s:%d IEEE1905: Closing multicast socket\n", __func__, __LINE__);
            close(sockets[i]);
            sockets[i] = -1;
        } else {
            wifi_util_info_print(WIFI_APPS, "%s:%d IEEE1905: Socket already closed\n", __func__, __LINE__);
        }
    }
    socket_count = 0;
    wifi_util_info_print(WIFI_APPS, "%s:%d test1\n", __func__, __LINE__);
    state = multiap_state_none;
    wifi_util_info_print(WIFI_CTRL, "%s:%d multiap_sta_enabled=%d\n", __func__, __LINE__,ctrl->multiap_sta_enabled);
    //Stop station VAPs
    if (ctrl != NULL && ctrl->multiap_sta_enabled == true) {
        ctrl->multiap_sta_enabled = false;
        start_station_vaps(true, false);
    }
    close(send_sock);
    send_sock = -1;

    wifi_util_info_print(WIFI_CTRL, "%s:%d IEEE1905: Multiap application stopped\n", __func__, __LINE__);
    return RETURN_OK;
}

static int multiap_event_hal_sta_conn_status(wifi_app_t *apps, void *arg)
{
    rdk_sta_data_t *sta_data = (rdk_sta_data_t *)arg;
    char temp_str[128];

    if (sta_data == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: input arg is NULL\n",__func__, __LINE__);
        return RETURN_ERR;
    }

    memset(temp_str, 0, sizeof(temp_str));
    switch(sta_data->stats.connect_status) {
        case wifi_connection_status_connected:
            snprintf(temp_str, sizeof(temp_str), "connected : vap_index %d bssid %02x:%02x:%02x:%02x:%02x:%02x",
                    sta_data->stats.vap_index, sta_data->bss_info.bssid[0], sta_data->bss_info.bssid[1],
        sta_data->bss_info.bssid[2], sta_data->bss_info.bssid[3],
        sta_data->bss_info.bssid[4], sta_data->bss_info.bssid[5]);
            wifi_util_info_print(WIFI_APPS, analytics_format_hal_core, "sta status", temp_str);
        break;
        case wifi_connection_status_disconnected:
            snprintf(temp_str, sizeof(temp_str), "disconnected : vap_index %d bssid %02x:%02x:%02x:%02x:%02x:%02x",
                    sta_data->stats.vap_index, sta_data->bss_info.bssid[0], sta_data->bss_info.bssid[1],
                    sta_data->bss_info.bssid[2], sta_data->bss_info.bssid[3],
                    sta_data->bss_info.bssid[4], sta_data->bss_info.bssid[5]);
            wifi_util_info_print(WIFI_APPS, analytics_format_hal_core, "sta status", temp_str);
        break;
        case wifi_connection_status_ap_not_found:
            snprintf(temp_str, sizeof(temp_str), "disconnected AP not found : vap_index %d",
                    sta_data->stats.vap_index);
            wifi_util_info_print(WIFI_APPS, analytics_format_hal_core, "sta status", temp_str);
        break;
        default:
        break;
    }

    return RETURN_OK;
}

static int event_hal_ind_multiap(wifi_app_t *apps, wifi_event_subtype_t sub_type, void *arg)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_util_info_print(WIFI_CTRL, "%s:%d multiap_sta_enabled=%d\n", __func__, __LINE__,ctrl->multiap_sta_enabled);
    if (ctrl->multiap_sta_enabled == false) {
        wifi_util_error_print(WIFI_APPS, "%s:%d called when multiap disabled evt:%s\n",
            __func__, __LINE__, wifi_event_subtype_to_string(sub_type));
        return RETURN_OK;
    }

    switch (sub_type) {
    case wifi_event_hal_sta_conn_status:
        /* Need to check the status
            1. If connected on (expected interface),
               * schedule timer to send the required messages (auto config)
            2. If disconnected, stop sending any packets, update the states and free the resources
                 (If required we can try reconnecting)
         */
        multiap_event_hal_sta_conn_status(apps, arg);
        state = multiap_state_search_rsp_pending;
        wifi_util_error_print(WIFI_APPS, "%s:%d Creating Rx thread.\n",__func__, __LINE__);
        if (receive_multiap_message() != 0) {
        close(send_sock);
        wifi_util_error_print(WIFI_APPS, "%s:%d Failed to create a receive thread for Multip messages\n",
            __func__, __LINE__);
        return RETURN_ERR;
        }
        // Stop the scheduler
        scheduler_cancel_timer_task(ctrl->sched, ctrl->multiap_timer_id);
        scheduler_add_timer_task(ctrl->sched, FALSE, &ctrl->multiap_timer_id, multiap_timeout_fun,
        NULL, 1000, 0, FALSE);
		//scheduler_update_timer_task_interval(ctrl->sched, ctrl->multiap_timer_id, 1000);
        wifi_util_info_print(WIFI_CTRL, "%s:%d, Handling Evt: %s\n", __func__, __LINE__,
            wifi_event_subtype_to_string(sub_type));
        break;

    case wifi_event_scan_results:
        wifi_util_info_print(WIFI_APPS, "%s:%d, Handling Evt: %s\n", __func__, __LINE__,
            wifi_event_subtype_to_string(sub_type));
        break;

    default:
        wifi_util_error_print(WIFI_APPS, "%s:%d: event not handle %s\r\n", __func__, __LINE__,
            wifi_event_subtype_to_string(sub_type));
        break;
    }

    return RETURN_OK;
}

static int event_exec_multiap(wifi_app_t *apps, wifi_event_subtype_t sub_type, void *arg)
{
    switch (sub_type) {
    case wifi_event_exec_start:
        multiap_event_exec_start(apps, arg);
        break;

    case wifi_event_exec_stop:
        wifi_util_info_print(WIFI_APPS, "%s:%d wifi_event_exec_stop\n", __func__, __LINE__);
        multiap_event_exec_stop(apps, arg);
        break;

    case wifi_event_exec_timeout:
        multiap_event_exec_timeout(apps, arg);
        break;

    default:
        wifi_util_error_print(WIFI_APPS, "%s:%d: event not handle %s\r\n", __func__, __LINE__,
            wifi_event_subtype_to_string(sub_type));
        break;
    }
    return RETURN_OK;
}

int multiap_event(wifi_app_t *app, wifi_event_t *event)
{
    switch (event->event_type) {
    case wifi_event_type_webconfig:
        break;

    case wifi_event_type_exec:
        event_exec_multiap(app, event->sub_type, NULL);
        break;

    case wifi_event_type_hal_ind:
        event_hal_ind_multiap(app, event->sub_type,event->u.core_data.msg);
        break;

    default:
        break;
    }
    return RETURN_OK;
}

int multiap_deinit(wifi_app_t *app)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    wifi_util_info_print(WIFI_APPS, "%s:%d IEEE1905: Deinitializing multiap application\n", __func__, __LINE__);

    //Close all global sockets
    for (int i = 0; i < socket_count; i++) {
        if (sockets[i] >= 0) {
            wifi_util_info_print(WIFI_APPS, "%s:%d Closing socket %d\n", __func__, __LINE__, sockets[i]);
            close(sockets[i]);
            sockets[i] = -1;
        }
    }
    socket_count = 0;

    close(send_sock);
    send_sock = -1;

    state = multiap_state_none;
    wifi_util_info_print(WIFI_CTRL, "%s:%d multiap_sta_enabled=%d\n", __func__, __LINE__,ctrl->multiap_sta_enabled);
    //Stop station VAPs
    if (ctrl != NULL && ctrl->multiap_sta_enabled == true) {
        ctrl->multiap_sta_enabled = false;
        start_station_vaps(true, false);
    }
    wifi_util_info_print(WIFI_APPS, "%s:%d IEEE1905: Multiap application deinitialized\n",
                            __func__, __LINE__);
    return RETURN_OK;
}

int multiap_init(wifi_app_t *app, unsigned int create_flag)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (app_init(app, create_flag) != 0) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: Failed to register app!\n", __func__, __LINE__);
        return RETURN_ERR;
    }
#define MULTIAP_INIT_TIMEOUT 5000
    scheduler_add_timer_task(ctrl->sched, FALSE, &ctrl->multiap_timer_id, multiap_timeout_fun,
        NULL, MULTIAP_INIT_TIMEOUT, 0, FALSE);
    state = multiap_state_none;
    wifi_util_info_print(WIFI_APPS, "%s:%d: IEEE1905: Init multiap_app \n", __func__, __LINE__);

    return RETURN_OK;
}