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
#include "const.h"

/* MACROS */
#define FAILOVER_ENABLE "Device.X_RDK_GatewayManagement.Failover.Enable"
#define MAX_BUFF_SZ 1024
#define MAX_IFACES 8
#define ETH_P_1905 0x893a

/* Timeout Macros */
#define MULTIAP_RESP_TIMEOUT (1000)
#define MULTIAP_CONNECT_TIMEOUT (60000 * 2)

/* CNT Macros */
#define MAX_SEARCH_REQ_PKTS 100

/* Global variables */
static int rx_socks[MAX_IFACES] = { -1 };
static int rx_sock_count = 0;
static int send_sock = -1;
static pthread_t tid;
static int search_req_count = 0;

static volatile multiap_state_t state = multiap_state_none;
static char connected_interface[IFNAMSIZ] = {0};
static pthread_mutex_t multiap_mutex;

/* Function declarations/prototypes */
static int create_autoconfig_search(unsigned char *buff, char *ifname);
static int send_frame(unsigned char *buff, unsigned int len, bool multicast, char *ifname);
static void send_multiap_broadcast_message(char *ifname);
static int receive_multiap_message();
static int create_autoconfig_resp_msg(unsigned char *buff, unsigned char *dst, char *interface_name);
static int parse_multiap_tlv(unsigned char *buff, unsigned int len, multiap_tlv_type_t type,
    void *out_buff, size_t out_len);

static int get_service_type()
{
    wifi_ctrl_t *ctrl = NULL;

    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl && ctrl->network_mode == rdk_dev_mode_type_gw) {
        wifi_util_info_print(WIFI_APPS, "%s:%d Gateway mode\n", __func__, __LINE__);
        return multiap_service_type_gateway;
    }
    else if (ctrl->network_mode == rdk_dev_mode_type_ext) {
        wifi_util_info_print(WIFI_APPS, "%s:%d Extender mode\n", __func__, __LINE__);
        return multiap_service_type_extender;
    }
    else {
        wifi_util_error_print(WIFI_APPS, "%s:%d UnSupported type\n", __func__, __LINE__);
        return multi_service_type_none;
    }
}

static int parse_multiap_tlv(unsigned char *buff, unsigned int len, multiap_tlv_type_t type,
    void *out_buff, size_t out_len)
{
    unsigned int start = sizeof(multiap_raw_hdr_t) + sizeof(multiap_cmdu_t);
    unsigned int remaining;
    int rlen = RETURN_ERR;

    if (!buff || !out_buff || len < sizeof(multiap_raw_hdr_t) + sizeof(multiap_cmdu_t)) {
        wifi_util_error_print(WIFI_APPS, "%s:%d Invalid input parameters\n",  __func__, __LINE__);
        return RETURN_ERR;
    }

    remaining = len - start;
    multiap_tlv_t *tlv = (multiap_tlv_t *)&buff[start];

    while (remaining > (int)sizeof(multiap_tlv_t) && tlv->type != multiap_tlv_type_eom) {
        unsigned short tlv_len = ntohs(tlv->len);

        /* Safety: ensure we don’t read beyond buffer */
        if (tlv_len > remaining - (int)sizeof(multiap_tlv_t)) {
            wifi_util_error_print(WIFI_APPS, "%s:%d TLV length exceeds remaining buffer\n", __func__, __LINE__);
            return RETURN_ERR;
        }

        if (tlv->type == type) {
            /* Found requested tlv break from while */
            break;
        }
        /* Move to next TLV */
        remaining -= sizeof(multiap_tlv_t) + tlv_len;
        tlv = (multiap_tlv_t *)((unsigned char *)tlv + sizeof(multiap_tlv_t) + tlv_len);
    }
    if (tlv->type != type) {
        wifi_util_error_print(WIFI_APPS, "%s:%d Requested TLV type is not found\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    rlen = ntohs(tlv->len);
    if (out_len < (size_t)rlen) {
        wifi_util_error_print(WIFI_APPS, "%s:%d Not enough memory\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    switch (type) {
    case multiap_tlv_type_al_mac_address: {
        wifi_util_info_print(WIFI_APPS, "%s:%d Found AL MAC Address TLV, rlen=%d\n", __func__, __LINE__, rlen);
        memcpy(out_buff, tlv->value, rlen);
    } break;

    case multiap_tlv_type_supported_service: {
        multiap_supported_srv_t *stlv = (multiap_supported_srv_t *)out_buff;

        stlv->num_service = tlv->value[0];
        memcpy(&stlv->supported_service, &tlv->value[1], tlv->value[0]);
        wifi_util_info_print(WIFI_APPS, "%s:%d Found Supported Service TLV, num_service=0x%x, supported_service=0x%x, rlen=%d\n",
            __func__, __LINE__, stlv->num_service, stlv->supported_service, rlen);
    } break;

    case multiap_tlv_type_sta_mac_addr: {
        wifi_util_info_print(WIFI_APPS, "%s:%d Found STA MAC Address TLV, rlen=%d\n", __func__, __LINE__, rlen);
        memcpy(out_buff, tlv->value, rlen);
    } break;

    default:
        wifi_util_error_print(WIFI_APPS, "%s:%d Unknown TLV type requested***\n", __func__, __LINE__);
        rlen = RETURN_ERR;
        break;
    }

    return rlen;
}

static int handle_autoconf_search(unsigned char *data, unsigned int len, char *recv_interface)
{
    unsigned char msg[MAX_BUFF_SZ];
    mac_address_t dst;
    wifi_ctrl_t *ctrl = NULL;
    char st[64];
    unsigned char buff[128] = { 0 };
    multiap_supported_srv_t *srv = (multiap_supported_srv_t *)buff;
    int device_supporting_service = get_service_type();

    wifi_util_info_print(WIFI_APPS, "%s:%d device_supporting_service=%d\n",
	    __func__, __LINE__, device_supporting_service);

    if (parse_multiap_tlv(data, len, multiap_tlv_type_supported_service, srv, sizeof(buff)) < 0) {
        wifi_util_error_print(WIFI_APPS, "%s:%d Service type TLV not found\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    wifi_util_info_print(WIFI_APPS, "%s:%d supported_service=%d(0x%x)\n",
        __func__, __LINE__, srv->supported_service[0], srv->supported_service[0]);
    if (device_supporting_service == multiap_service_type_extender ||
        srv->supported_service[0] == multiap_service_type_extender) {
        wifi_util_info_print(WIFI_APPS,
            "%s:%d Either supporting service or supported service is extender so not replying\n",
            __func__, __LINE__);
        return RETURN_ERR;
    }

    state = multiap_state_completed;
    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    /* Extract AL MAC address */
    if (parse_multiap_tlv(data, len, multiap_tlv_type_al_mac_address, &dst, sizeof(mac_address_t)) < 0) {
        wifi_util_error_print(WIFI_APPS, "%s:%d AL MAC address TLV is not found\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    uint8_mac_to_string_mac(dst, st);
    wifi_util_info_print(WIFI_APPS, "%s:%d Sender mac=%s\n", __func__, __LINE__, st);

   /* Send response on the interface where packet was received */
    if (recv_interface != NULL && strlen(recv_interface) > 0) {
        len = create_autoconfig_resp_msg(msg, (unsigned char *)dst, recv_interface);
        wifi_util_info_print(WIFI_APPS, "%s:%d After create_autoconfig_resp_msg got len=%d\n",
            __func__, __LINE__, len);
        (void)send_frame(msg, len, false, recv_interface);
        wifi_util_info_print(WIFI_APPS, "%s:%d Autoconfig response sent on %s\n",
            __func__, __LINE__, recv_interface);
    }
    /* Set device to extender mode*/
    set_to_extender_mode(&ctrl->handle, FAILOVER_ENABLE, 0, 0);
    set_to_extender_mode(&ctrl->handle, WIFI_DEVICE_MODE, 1, 1);

    wifi_util_info_print(WIFI_APPS, "%s:%d Split brain detected - Device switched to extender mode\n",
        __func__, __LINE__);
    return RETURN_OK;
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
    unsigned char buffer[100] = { 0 };
    wifi_vap_info_map_t *wifi_vap_map = NULL;

    /* Extract STA MAC addresses */
    tlv_len = parse_multiap_tlv(data, len, multiap_tlv_type_sta_mac_addr, buffer, sizeof(buffer));
    if (tlv_len < 0) {
        wifi_util_error_print(WIFI_APPS, "%s:%d STA MAC address TLV not found\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    /* This is the retriving mechanism from the TLV for multiple MAC addresses */
    total_macs = tlv_len / MAC_ADDR_LEN;

    for (int i = 0; i < total_macs; ++i) {
        memcpy(mac, &buffer[i * MAC_ADDR_LEN], MAC_ADDR_LEN);
        to_mac_str(mac, new_mac_str);
        str_tolower(new_mac_str);
        wifi_util_info_print(WIFI_APPS, "%s:%d STA mac_str[%d]=%s\n", __func__, __LINE__, i, new_mac_str);

        if (memcmp(mac, zero_mac, sizeof(mac_address_t)) == 0) {
            wifi_util_info_print(WIFI_APPS, "%s:%d GreyList new_mac is zero mac - Continue\n", __func__, __LINE__);
            continue;
        }

        for (itr = 0; itr < getNumberRadios(); itr++) {
            wifi_vap_map = get_wifidb_vap_map(itr);

            for (itrj = 0; itrj < getMaxNumberVAPsPerRadio(itr); itrj++) {
                vap_index = wifi_vap_map->vap_array[itrj].vap_index;
                rdk_vap_info = get_wifidb_rdk_vap_info(vap_index);
                if (rdk_vap_info == NULL) {
                    wifi_util_error_print(WIFI_APPS, "%s:%d rdk_vap_info is NULL\n", __func__, __LINE__);
                    return RETURN_ERR;
                }

                if ((strstr(rdk_vap_info->vap_name, "mesh_backhaul") == NULL)) {
                    continue;
                }

                if (rdk_vap_info->acl_map == NULL) {
                    wifi_util_error_print(WIFI_APPS, "%s:%d GreyList acl_map is NULL\n", __func__, __LINE__);
                    rdk_vap_info->acl_map = hash_map_create();
                }

                wifi_util_info_print(WIFI_APPS, "%s:%d new_mac_str %s\n", __func__, __LINE__, new_mac_str);
                temp_acl_entry = hash_map_get(rdk_vap_info->acl_map, new_mac_str);
                if (temp_acl_entry != NULL) {
                    wifi_util_info_print(WIFI_APPS, "%s:%d Mac is already present in macfilter\n", __func__, __LINE__);
                    continue;
                }
                acl_entry = (acl_entry_t *)malloc(sizeof(acl_entry_t));
                memcpy(acl_entry->mac, mac, sizeof(mac_address_t));

#ifdef NL80211_ACL
                if (wifi_hal_addApAclDevice(rdk_vap_info->vap_index, new_mac_str) != RETURN_OK) {
#else
                if (wifi_addApAclDevice(rdk_vap_info->vap_index, new_mac_str) != RETURN_OK) {
#endif
                    wifi_util_info_print(WIFI_APPS, "%s:%d wifi_addApAclDevice failed. vap_index:%d, MAC:%s\n",
                        __func__,__LINE__, rdk_vap_info->vap_index, new_mac_str);
                    continue;
                }

                hash_map_put(rdk_vap_info->acl_map, strdup(new_mac_str), acl_entry);
            }
        }
    }
    return RETURN_OK;
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
    wifi_util_info_print(WIFI_APPS, "%s:%d Source MAC from interface %s = %s\n",
        __func__, __LINE__, interface_name, st);

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

    /* AL MAC Address type TLV 6-21 */
    tlv = (multiap_tlv_t *)tmp;
    tlv->type = multiap_tlv_type_al_mac_address;
    tlv->len = htons(sizeof(mac_address_t));
    memcpy(tlv->value, (unsigned char *)src_addr, sizeof(mac_address_t));

    tmp += (sizeof(multiap_tlv_t) + sizeof(mac_address_t));
    len += (int)(sizeof(multiap_tlv_t) + sizeof(mac_address_t));

    /* 6-22—SearchedRole TLV */
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_searched_role;
    tlv->len = htons(sizeof(unsigned char));
    memcpy(&tlv->value, &registrar, sizeof(unsigned char));

    tmp += (sizeof(multiap_tlv_t) + 1);
    len += (int)(sizeof(multiap_tlv_t) + 1);

    /* 6-23—autoconf_freq_band TLV */
    freq_band = multiap_freq_band_5;
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_autoconf_freq_band;
    tlv->len = htons(sizeof(unsigned char));
    memcpy(&tlv->value, &freq_band, sizeof(unsigned char));

    tmp += (sizeof(multiap_tlv_t) + 1);
    len += (int)(sizeof(multiap_tlv_t) + 1);

    /* Supported service 17.2.1 */
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_supported_service;
    tlv->len = htons(sizeof(multiap_enum_type_t) + 1);
    /* Number of services */
    tlv->value[0] = 1;
    memcpy(&tlv->value[1], &service_type, sizeof(multiap_enum_type_t));

    tmp += (sizeof(multiap_tlv_t) + sizeof(multiap_enum_type_t) + 1);
    len += (int)(sizeof(multiap_tlv_t) + sizeof(multiap_enum_type_t) + 1);

    /* One searched service 17.2.2 */
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_searched_service;
    tlv->len = htons(sizeof(multiap_enum_type_t) + 1);
    tlv->value[0] = 1;
    searched = multiap_service_type_gateway;
    memcpy(&tlv->value[1], &searched, sizeof(multiap_enum_type_t));

    tmp += (sizeof(multiap_tlv_t) + sizeof(multiap_enum_type_t) + 1);
    len += (int)(sizeof(multiap_tlv_t) + sizeof(multiap_enum_type_t) + 1);

    /* One multiAP profile tlv 17.2.47 */
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_profile;
    tlv->len = htons(sizeof(multiap_enum_type_t));
    profile = 3;
    memcpy(tlv->value, &profile, sizeof(multiap_enum_type_t));

    tmp += (sizeof(multiap_tlv_t) + sizeof(multiap_enum_type_t));
    len += (int)(sizeof(multiap_tlv_t) + sizeof(multiap_enum_type_t));

    /* End of message */
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
    /* Length of destination mac address */
    sadr_ll.sll_halen = ETH_ALEN;
    sadr_ll.sll_protocol = htons(ETH_P_ALL);
    memcpy(sadr_ll.sll_addr, (multicast == true) ? multi_addr : hdr->dst, sizeof(mac_address_t));

    ret = (int)(sendto(send_sock, buff, len, 0, (const struct sockaddr *)&sadr_ll,
        sizeof(struct sockaddr_ll)));
    if (ret < 0) {
        wifi_util_error_print(WIFI_APPS, "%s:%d Failed to send frame on %s, err:%d\n",
            __func__, __LINE__, ifname, errno);
        return RETURN_ERR;
    }
    wifi_util_info_print(WIFI_APPS, "%s:%d Sent frame on %s of len:%d\n", __func__, __LINE__, ifname, len);

    return ret;
}

static void send_multiap_broadcast_message(char *ifname)
{
    unsigned char buff[MAX_BUFF_SZ];
    unsigned int sz;

    wifi_util_info_print(WIFI_APPS, "%s:%d ifname = %s\n", __func__, __LINE__, ifname);
    if (multiap_service_type_extender == get_service_type()) {
        wifi_util_info_print(WIFI_APPS, "%s:%d Device is in extender mode, skipping broadcast message\n",
            __func__, __LINE__);
        return;
    }

    sz = create_autoconfig_search(buff, ifname);
    wifi_util_info_print(WIFI_APPS, "%s:%d Autoconfig search message created, size=%u\n",
        __func__, __LINE__, sz);

    if (send_frame(buff, sz, true, ifname) < 0) {
        wifi_util_info_print(WIFI_APPS, "%s:%d Failed to send frame\n", __func__, __LINE__);
        return;
    }

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
        wifi_util_info_print(WIFI_APPS, "%s:%d Error in attaching filter, err:%d\n",
            __func__, __LINE__, errno);
        close(sockfd);
        return RETURN_ERR;
    }
    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_type = PACKET_MR_PROMISC;
    mreq.mr_ifindex = (int)(if_nametoindex(iface_name));

    if (setsockopt(sockfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq))) {
        wifi_util_info_print(WIFI_APPS, "%s:%d Error setting promisuous for interface:%s, err:%d\n",
            __func__, __LINE__, iface_name, errno);
        close(sockfd);
        return RETURN_ERR;
    }
    return RETURN_OK;
}

static int create_raw_socket(const char *iface_name)
{
    int sockfd;
    struct sockaddr_ll sll;

    /* Create raw socket */
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        wifi_util_error_print(WIFI_APPS, "%s:%d Failed to create raw socket, err:%d\n",
            __func__, __LINE__, errno);
        return RETURN_ERR;
    }

    /* Bind to interface */
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = (int)(if_nametoindex(iface_name));
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
        wifi_util_error_print(WIFI_APPS, "%s:%d Failed to bind socket to interface %s, err:%d\n",
            __func__, __LINE__, iface_name, errno);
        close(sockfd);
        return RETURN_ERR;
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
    wifi_util_info_print(WIFI_APPS, "Source MAC from interface %s = %s\n", interface_name, st);

    uint8_mac_to_string_mac(dst, st);
    wifi_util_info_print(WIFI_APPS, "Destination MAC = %s\n", st);

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

    /* 6-24—SupportedRole TLV */
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_supported_role;
    tlv->len = htons(sizeof(unsigned char));
    memcpy(&tlv->value, &registrar, sizeof(unsigned char));

    tmp += (sizeof(multiap_tlv_t) + 1);
    len += (int)(sizeof(multiap_tlv_t) + 1);

    /* 6-25—supported freq_band TLV */
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_supported_freq_band;
    tlv->len = htons(sizeof(unsigned char));
    memcpy(&tlv->value, &band, sizeof(unsigned char));

    tmp += (sizeof(multiap_tlv_t) + 1);
    len += (int)(sizeof(multiap_tlv_t) + 1);

    /* supported service tlv 17.2.1 */
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_supported_service;
    tlv->len = htons(sizeof(multiap_enum_type_t) + 1);
    tlv->value[0] = 1;
    memcpy(&tlv->value[1], &service_type, sizeof(multiap_enum_type_t));

    tmp += (sizeof(multiap_tlv_t) + sizeof(multiap_enum_type_t) + 1);
    len += (int)(sizeof(multiap_tlv_t) + sizeof(multiap_enum_type_t) + 1);

    /* 1905 layer security capability tlv 17.2.67 */
    sec_info_cap.onboarding_proto = 0;
    sec_info_cap.integrity_algo = 1;
    sec_info_cap.encryption_algo = 0;
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_1905_layer_security_cap;
    tlv->len = htons(sizeof(multiap_ieee_1905_security_cap_t));
    memcpy(tlv->value, &sec_info_cap, sizeof(multiap_ieee_1905_security_cap_t));

    tmp += (sizeof(multiap_tlv_t) + sizeof(multiap_ieee_1905_security_cap_t));
    len += (int)(sizeof(multiap_tlv_t) + sizeof(multiap_ieee_1905_security_cap_t));

    /* One multiAP profile tlv 17.2.47 */
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_profile;
    tlv->len = htons(sizeof(multiap_enum_type_t));
    profile = multiap_profile_type_3;
    memcpy(tlv->value, &profile, sizeof(multiap_enum_type_t));

    tmp += (sizeof(multiap_tlv_t) + sizeof(multiap_enum_type_t));
    len += (int)(sizeof(multiap_tlv_t) + sizeof(multiap_enum_type_t));

    /* One controller capability tlv 17.2.94 */
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_ctrl_cap;
    tlv->len = htons(sizeof(multiap_ctrl_cap_t));
    memset(&ctrl_cap, 0, sizeof(multiap_ctrl_cap_t));
    memcpy(tlv->value, &ctrl_cap, sizeof(multiap_ctrl_cap_t));

    tmp += (sizeof(multiap_tlv_t) + sizeof(multiap_ctrl_cap_t));
    len += (int)(sizeof(multiap_tlv_t) + sizeof(multiap_ctrl_cap_t));

    /* STA MAC Address type TLV */
    tlv = (multiap_tlv_t *)tmp;
    tlv->type = multiap_tlv_type_sta_mac_addr;
    for (itr = 0; itr < getNumberRadios(); itr++) {
        wifi_util_info_print(WIFI_APPS, "%s:%d index=%d and  getNumberRadios()=%d\n", __func__,
            __LINE__, itr, getNumberRadios());
        get_mesh_sta_mac_address_for_radio(&g_wifi_mgr->hal_cap.wifi_prop, itr, mac);
        uint8_mac_to_string_mac(mac, st);
        wifi_util_info_print(WIFI_APPS, "%s:%d mac_adr=%s\n", __func__, __LINE__, st);
        memcpy(&mac_buffer[offset], mac, MAC_ADDR_LEN);
        offset += MAC_ADDR_LEN;
    }

    tlv->len = htons(offset);
    wifi_util_info_print(WIFI_APPS, "%s:%d offset=%d\n", __func__, __LINE__, offset);
    memcpy(tlv->value, (unsigned char *)mac_buffer, offset);

    tmp += (sizeof(multiap_tlv_t) + offset);
    len += (int)(sizeof(multiap_tlv_t) + offset);
    /* End of message */
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof(multiap_tlv_t));
    len += (int)(sizeof(multiap_tlv_t));
    wifi_util_info_print(WIFI_APPS, "%s:%d Autoconfig response message created successfully, total_length=%d bytes\n",
         __func__, __LINE__, len);

    return len;
}

static void proto_process(unsigned char *data, unsigned int len, char *recv_interface)
{
    wifi_ctrl_t *ctrl;
    multiap_cmdu_t *cmdu;
    int ret = -1;
    multiap_raw_hdr_t *hdr = (multiap_raw_hdr_t *)(data);
    cmdu = (multiap_cmdu_t *)(data + sizeof(multiap_raw_hdr_t));

    if (memcmp(hdr->src, hdr->dst, sizeof(mac_address_t)) == 0) {
        char src_mac_str[64], dst_mac_str[64];
        uint8_mac_to_string_mac(hdr->src, src_mac_str);
        uint8_mac_to_string_mac(hdr->dst, dst_mac_str);
        wifi_util_info_print(WIFI_APPS, "%s:%d Dropping loopback frame: src=%s dst=%s\n",
            __func__, __LINE__, src_mac_str, dst_mac_str);
        /* This is a message that was sent to the same address it was sent from; ignore it */
        return;
    }
    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    switch (htons(cmdu->type)) {
    case multiap_msg_type_autoconf_search:
        if (state == multiap_state_none) {
            wifi_util_info_print(WIFI_APPS, "%s:%d Got a packet of type =%d, processing it\n",
                __func__, __LINE__, htons(cmdu->type));
            ret = handle_autoconf_search(data, len, recv_interface);
            if (ret == -1) {
                wifi_util_info_print(WIFI_APPS, "%s:%d Autoconfig search response not sent, setting the state to None\n",
                    __func__, __LINE__);
                state = multiap_state_none;
            } else {
                wifi_util_info_print(WIFI_APPS, "%s:%d Autoconfig search response sent moving to extender mode\n",
                __func__, __LINE__);
            }
        }
        break;
    case multiap_msg_type_autoconf_resp:
        if (state == multiap_state_search_rsp_pending) {
            wifi_util_info_print(WIFI_APPS, "%s:%d Got a valid packet of type =%d, processing it\n",
                __func__, __LINE__, htons(cmdu->type));
            state = multiap_state_completed;
            if (handle_autoconf_search_resp(data, len) == RETURN_ERR) {
                wifi_util_error_print(WIFI_APPS, "%s:%d Error handling resp\n", __func__, __LINE__);
                break;
            }
            wifi_util_info_print(WIFI_APPS, "%s:%d Autoconfig response received, bringing down the station\n",
                __func__, __LINE__);
            apps_mgr_multiap_event(&ctrl->apps_mgr, wifi_event_type_exec, wifi_event_exec_stop, NULL, 0);
            ctrl->webconfig_state |= ctrl_webconfig_state_vap_mesh_sta_cfg_rsp_pending;
        }
        break;
    default:
        wifi_util_info_print(WIFI_APPS, "%s:%d Got unknown message type =%d\n",
            __func__, __LINE__, htons(cmdu->type));
        break;
    }
}

static void *receive_multicast_message(void *ctx)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    const char *ifaces[] = { "wl1", "wl1.1", "wl0", "wl0.1", "brlan0", "wl1.7", "wl0.7" , "brlan1" };
    char buffer[MAX_FRAME_SZ];

    struct pollfd poll_fds[ARRAY_SIZE(ifaces)];

    for (int i = 0; i < rx_sock_count; i++) {
        if (rx_socks[i] >= 0) {
            wifi_util_info_print(WIFI_APPS, "%s:%d Closing old socket %d\n", __func__, __LINE__, rx_socks[i]);
            close(rx_socks[i]);
            rx_socks[i] = -1;
        }
    }
    rx_sock_count = 0;
    wifi_util_info_print(WIFI_APPS, "%s:%d Initializing sockets on interfaces\n", __func__, __LINE__);
    for (unsigned int i = 0; i < ARRAY_SIZE(ifaces); ++i) {
        rx_socks[i] = create_raw_socket(ifaces[i]);
        if (rx_socks[i] < 0) {
            wifi_util_info_print(WIFI_APPS, "Failed to initialize socket on %s\n", ifaces[i]);
            return NULL;
        }
        /* Initialize pollfd entry */
        poll_fds[i].fd = rx_socks[i];
        poll_fds[i].events = POLLIN;
        poll_fds[i].revents = 0;

        rx_sock_count++;
        wifi_util_info_print(WIFI_APPS, "%s:%d rx_socks[%d]= %d (%s)\n", __func__, __LINE__, i, rx_socks[i], ifaces[i]);
    }

    while (ctrl->multiap_sta_enabled == true) {
        wifi_util_info_print(WIFI_APPS, "%s:%d Waiting for data on %d sockets\n", __func__, __LINE__, rx_sock_count);
        int ret = poll(poll_fds, rx_sock_count, -1); /* -1 = infinite timeout */
        if (ret < 0) {
            wifi_util_error_print(WIFI_APPS, "%s:%d Poll Error: %d\n", __func__, __LINE__, errno);
            break;
        } else if (ret == 0) {
            wifi_util_info_print(WIFI_APPS, "%s:%d Poll Timeout\n", __func__, __LINE__);
            continue; /* Timeout, continue waiting */
        }

        /* Check which sockets have data */
        for (int i = 0; i < rx_sock_count; ++i) {
            if (poll_fds[i].revents & POLLIN) {
                ssize_t len = recvfrom(rx_socks[i], buffer, sizeof(buffer), 0, NULL, NULL);
                if (len < 0) {
                    wifi_util_error_print(WIFI_APPS, "%s:%d recvfrom error: %d\n", __func__, __LINE__, errno);
                    continue;
                }
                wifi_util_info_print(WIFI_APPS, "%s:%d Received %zd bytes on socket: %d(%s)\n",
                    __func__, __LINE__, len, rx_socks[i], ifaces[i]);
                if (len > 0) {
                    pthread_mutex_lock(&multiap_mutex);
                    proto_process((unsigned char *)buffer, len, (char *)ifaces[i]);
                    pthread_mutex_unlock(&multiap_mutex);
                }
            }
            /* Check for socket errors */
            if (poll_fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                wifi_util_info_print(WIFI_APPS, "%s:%d Socket error on fd %d, revents: 0x%x\n",
                    __func__, __LINE__, rx_socks[i], poll_fds[i].revents);
                close(rx_socks[i]);
                rx_socks[i] = -1;
                /* Remove from poll list */
                poll_fds[i].fd = -1;
                poll_fds[i].events = 0;
                poll_fds[i].revents = 0;
            }
        }
    }

    wifi_util_info_print(WIFI_APPS, "%s:%d Exiting the thread\n", __func__, __LINE__);

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
        wifi_util_error_print(WIFI_APPS, "%s:%d Failed to create thread\n", __func__, __LINE__);
        return RETURN_ERR;
    } else {
        wifi_util_info_print(WIFI_APPS, "%s:%d Receive thread created successfully\n", __func__, __LINE__);
    }

    return RETURN_OK;
}

static int multiap_event_exec_timeout(wifi_app_t *apps, void *arg)
{
    if (strlen(connected_interface) > 0) {
        wifi_util_info_print(WIFI_APPS, "%s:%d Sending broadcast on connected interface: %s\n",
            __func__, __LINE__, connected_interface);
        send_multiap_broadcast_message(connected_interface);
    }

    return RETURN_OK;
}

static int multiap_timeout_fun(void* arg)
{
    wifi_ctrl_t *ctrl = NULL;
    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    pthread_mutex_lock(&multiap_mutex);

    if (state == multiap_state_search_rsp_pending) {
        apps_mgr_multiap_event(&ctrl->apps_mgr, wifi_event_type_exec, wifi_event_exec_timeout, NULL, 0);
        /* Stop the scheduler */
        scheduler_cancel_timer_task(ctrl->sched, ctrl->multiap_timer_id);
        if (search_req_count >= MAX_SEARCH_REQ_PKTS){
            wifi_util_info_print(WIFI_APPS, "%s:%d Max send count reached,Stopping Send\n", __func__, __LINE__);
            apps_mgr_multiap_event(&ctrl->apps_mgr, wifi_event_type_exec, wifi_event_exec_stop, NULL, 0);
            pthread_mutex_unlock(&multiap_mutex);
            return RETURN_OK;
        }
        search_req_count++;
		scheduler_add_timer_task(ctrl->sched, FALSE, &ctrl->multiap_timer_id, multiap_timeout_fun,
		    NULL, MULTIAP_RESP_TIMEOUT, 0, FALSE);
    } else if (state == multiap_state_sta_create_and_connect) {
        wifi_util_info_print(WIFI_APPS, "%s:%d Connection timeout: Failed to connect/find GW device\n",
            __func__, __LINE__);
        scheduler_cancel_timer_task(ctrl->sched, ctrl->multiap_timer_id);
        apps_mgr_multiap_event(&ctrl->apps_mgr, wifi_event_type_exec, wifi_event_exec_stop, NULL, 0);
    } else {
        wifi_util_info_print(WIFI_APPS, "%s:%d Unexpected timeout in state:%d, canceling timer\n",
            __func__, __LINE__, state);
        scheduler_cancel_timer_task(ctrl->sched, ctrl->multiap_timer_id);
    }

    pthread_mutex_unlock(&multiap_mutex);

    return RETURN_OK;
}

static int multiap_event_exec_start(wifi_app_t *apps, void *arg)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *)get_ctrl_rfc_parameters();

    wifi_util_info_print(WIFI_APPS, "%s:%d Starting multiap event execution\n", __func__, __LINE__);
    if (ctrl == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d Ctrl is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (ctrl->rf_status_down || (ctrl->network_mode == rdk_dev_mode_type_ext) || !(rfc_param->multiap_rfc)) {
        wifi_util_error_print(WIFI_APPS, "%s:%d Station not started: rf_status_down=%d, network_mode=%d, multiap_rfc=%d\n",
            __func__, __LINE__, ctrl->rf_status_down, ctrl->network_mode, rfc_param->multiap_rfc);
        return RETURN_ERR;
    }

    send_sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (send_sock < 0) {
        wifi_util_error_print(WIFI_APPS, "%s:%d Failed to create a send socket\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    ctrl->multiap_sta_enabled = true;

    /* Start the station vaps only if none of the station is connected to vaps because in XLE when
    its in GW mode(with WAN failover) stations are connected to the GW then we should not start the station vaps */
    if (!is_device_type_xle() && (ctrl->network_mode == rdk_dev_mode_type_gw)) {
        start_station_vaps(true, true);
        state = multiap_state_sta_create_and_connect;
        scheduler_add_timer_task(ctrl->sched, FALSE, &ctrl->multiap_timer_id, multiap_timeout_fun,
		NULL, MULTIAP_CONNECT_TIMEOUT, 0, FALSE);
        wifi_util_info_print(WIFI_APPS, "%s:%d Registered multiap timer task\n", __func__, __LINE__);
    } else if (is_device_type_xle() && (ctrl->network_mode == rdk_dev_mode_type_gw)) {
        wifi_util_info_print(WIFI_APPS, "%s:%d Creating Rx thread\n", __func__, __LINE__);
        if (receive_multiap_message() != 0) {
            close(send_sock);
            wifi_util_error_print(WIFI_APPS, "%s:%d Failed to create a receive thread for Multip messages\n",
                __func__, __LINE__);
            apps_mgr_multiap_event(&ctrl->apps_mgr, wifi_event_type_exec, wifi_event_exec_stop, NULL, 0);
            return RETURN_ERR;
        }
    } else {
        wifi_util_info_print(WIFI_APPS, "%s:%d XLE Device is in Extender Mode\n", __func__, __LINE__);
        ctrl->multiap_sta_enabled = false;
        return RETURN_ERR;
    }

    return RETURN_OK;
}

static int multiap_event_exec_stop(wifi_app_t *apps, void *arg)
{
    wifi_ctrl_t *ctrl = NULL;
    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    vap_svc_t *mesh_ext_svc;
    vap_svc_ext_t *ext;

    if (ctrl != NULL && ctrl->multiap_sta_enabled == false) {
        wifi_util_info_print(WIFI_APPS, "%s:%d Multi-AP already disabled, returning\n",
            __func__, __LINE__);
        return RETURN_OK;
    }

    mesh_ext_svc = get_svc_by_type(ctrl, vap_svc_type_mesh_ext);
    if (mesh_ext_svc != NULL) {
        ext = &mesh_ext_svc->u.ext;
        /* Cancel connection algorithm timer */
        if (ext->ext_connect_algo_processor_id != 0) {
            scheduler_cancel_timer_task(ctrl->sched, ext->ext_connect_algo_processor_id);
            ext->ext_connect_algo_processor_id = 0;
            wifi_util_info_print(WIFI_APPS, "%s:%d Canceled mesh extender connection timer\n", __func__, __LINE__);
        }
        cancel_scan_result_timer(ctrl, ext);
        wifi_util_info_print(WIFI_APPS, "%s:%d Setting connection state to disconnected_steady\n",
            __func__, __LINE__);
        ext->conn_state = connection_state_disconnected_steady;
    }

    if (ctrl != NULL && ctrl->multiap_timer_id != 0) {
        scheduler_cancel_timer_task(ctrl->sched, ctrl->multiap_timer_id);
        ctrl->multiap_timer_id = 0;
        wifi_util_info_print(WIFI_APPS, "%s:%d Canceled Multi-AP timer\n", __func__, __LINE__);
    }
    memset(connected_interface, 0, sizeof(connected_interface));
    /* Close global sockets */
    for (int i = 0; i < rx_sock_count; i++) {
        if (rx_socks[i] >= 0) {
            wifi_util_info_print(WIFI_APPS, "%s:%d Closing multicast socket\n", __func__, __LINE__);
            close(rx_socks[i]);
            rx_socks[i] = -1;
        } else {
            wifi_util_info_print(WIFI_APPS, "%s:%d Socket already closed\n", __func__, __LINE__);
        }
    }
    rx_sock_count = 0;

    search_req_count = 0;

    close(send_sock);
    send_sock = -1;

    state = multiap_state_none;

    //Stop station VAPs
    ctrl->multiap_sta_enabled = false;
    start_station_vaps(true, false);

    wifi_util_info_print(WIFI_APPS, "%s:%d Multiap application stopped\n", __func__, __LINE__);

    return RETURN_OK;
}

static int multiap_event_hal_sta_conn_status(wifi_app_t *apps, void *arg)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    rdk_sta_data_t *sta_data = (rdk_sta_data_t *)arg;
    char temp_str[128];

    if (sta_data == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d input arg is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    memset(temp_str, 0, sizeof(temp_str));
    switch(sta_data->stats.connect_status) {
        case wifi_connection_status_connected:
            snprintf(temp_str, sizeof(temp_str), "Connected: vap_index %d bssid %02x:%02x:%02x:%02x:%02x:%02x",
                    sta_data->stats.vap_index, sta_data->bss_info.bssid[0], sta_data->bss_info.bssid[1],
                    sta_data->bss_info.bssid[2], sta_data->bss_info.bssid[3],
                    sta_data->bss_info.bssid[4], sta_data->bss_info.bssid[5]);
            wifi_util_info_print(WIFI_APPS, analytics_format_hal_core, "Sta status", temp_str);
            state = multiap_state_search_rsp_pending;
            strncpy(connected_interface, sta_data->interface_name, sizeof(connected_interface) - 1);
            wifi_util_info_print(WIFI_APPS, "%s:%d Connected on interface: %s\n",
                __func__, __LINE__, connected_interface);
            if (receive_multiap_message() != 0) {
                close(send_sock);
                wifi_util_error_print(WIFI_APPS, "%s:%d Failed to create receive thread\n", __func__, __LINE__);
                apps_mgr_multiap_event(&ctrl->apps_mgr, wifi_event_type_exec, wifi_event_exec_stop, NULL, 0);
                return RETURN_ERR;
            }
            /* Stop the scheduler */
            scheduler_cancel_timer_task(ctrl->sched, ctrl->multiap_timer_id);
            scheduler_add_timer_task(ctrl->sched, FALSE, &ctrl->multiap_timer_id, multiap_timeout_fun,
                NULL, MULTIAP_RESP_TIMEOUT, 0, FALSE);
            break;
        case wifi_connection_status_disconnected:
            snprintf(temp_str, sizeof(temp_str), "Disconnected: vap_index %d bssid %02x:%02x:%02x:%02x:%02x:%02x",
                    sta_data->stats.vap_index, sta_data->bss_info.bssid[0], sta_data->bss_info.bssid[1],
                    sta_data->bss_info.bssid[2], sta_data->bss_info.bssid[3],
                    sta_data->bss_info.bssid[4], sta_data->bss_info.bssid[5]);
            wifi_util_info_print(WIFI_APPS, analytics_format_hal_core, "Sta status", temp_str);
            apps_mgr_multiap_event(&ctrl->apps_mgr, wifi_event_type_exec, wifi_event_exec_stop, NULL, 0);
            break;
        default:
            wifi_util_error_print(WIFI_APPS, "%s:%d Unknown status %d\n", __func__, __LINE__, sta_data->stats.connect_status);
            break;
    }

    return RETURN_OK;
}

static int event_hal_ind_multiap(wifi_app_t *apps, wifi_event_subtype_t sub_type, void *arg)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    if (ctrl->multiap_sta_enabled == false) {
        wifi_util_error_print(WIFI_APPS, "%s:%d Called when multiap disabled evt:%s\n",
            __func__, __LINE__, wifi_event_subtype_to_string(sub_type));
        return RETURN_OK;
    }

    pthread_mutex_lock(&multiap_mutex);
    switch (sub_type) {
    case wifi_event_hal_sta_conn_status:
        wifi_util_info_print(WIFI_APPS, "%s:%d Handling Evt: %s\n", __func__, __LINE__,
            wifi_event_subtype_to_string(sub_type));
        multiap_event_hal_sta_conn_status(apps, arg);
        break;

    default:
        wifi_util_error_print(WIFI_APPS, "%s:%d Event not handle %s\n", __func__, __LINE__,
            wifi_event_subtype_to_string(sub_type));
        break;
    }
    pthread_mutex_unlock(&multiap_mutex);

    return RETURN_OK;
}

static int event_exec_multiap(wifi_app_t *apps, wifi_event_subtype_t sub_type, void *arg)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    int ret = RETURN_OK;

    pthread_mutex_lock(&multiap_mutex);
    switch (sub_type) {
    case wifi_event_exec_start:
        if (ctrl->multiap_sta_enabled == true) {
            wifi_util_info_print(WIFI_APPS, "%s:%d Multiap already enabled\n", __func__, __LINE__);
            ret = RETURN_ERR;
            break;
        }
        multiap_event_exec_start(apps, arg);
        break;

    case wifi_event_exec_stop:
        if (ctrl->multiap_sta_enabled == false) {
            wifi_util_info_print(WIFI_APPS, "%s:%d Multiap already disabled\n", __func__, __LINE__);
            ret = RETURN_ERR;
            break;
        }
        multiap_event_exec_stop(apps, arg);
        break;

    case wifi_event_exec_timeout:
        if (ctrl->multiap_sta_enabled == true) {
            multiap_event_exec_timeout(apps, arg);
        }
        break;

    default:
        wifi_util_error_print(WIFI_APPS, "%s:%d Event not handle %s\r\n", __func__, __LINE__,
            wifi_event_subtype_to_string(sub_type));
        ret = RETURN_ERR;
        break;
    }
    pthread_mutex_unlock(&multiap_mutex);

    return ret;
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
        event_hal_ind_multiap(app, event->sub_type, event->u.core_data.msg);
        break;

    default:
        break;
    }

    return RETURN_OK;
}

int multiap_deinit(wifi_app_t *app)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    wifi_util_info_print(WIFI_APPS, "%s:%d Deinitializing multiap application\n", __func__, __LINE__);

    pthread_mutex_lock(&multiap_mutex);
    /* Close all global sockets */
    for (int i = 0; i < rx_sock_count; i++) {
        if (rx_socks[i] >= 0) {
            wifi_util_info_print(WIFI_APPS, "%s:%d Closing socket %d\n", __func__, __LINE__, rx_socks[i]);
            close(rx_socks[i]);
            rx_socks[i] = -1;
        }
    }
    rx_sock_count = 0;
    close(send_sock);
    send_sock = -1;
    state = multiap_state_none;
    pthread_mutex_unlock(&multiap_mutex);

    /* Stop station VAPs */
    if (ctrl != NULL) {
        ctrl->multiap_sta_enabled = false;
        start_station_vaps(true, false);
    }
    /* Destroy state mutex */
    pthread_mutex_destroy(&multiap_mutex);
    wifi_util_info_print(WIFI_APPS, "%s:%d Multiap app deinitialized\n", __func__, __LINE__);

    return RETURN_OK;
}

int multiap_init(wifi_app_t *app, unsigned int create_flag)
{
    int ret;
    pthread_mutexattr_t attr;

    if (pthread_mutexattr_init(&attr) != 0) {
        wifi_util_error_print(WIFI_APPS, "%s:%d Failed to initialize mutext attr\n",
           __func__, __LINE__);
        return RETURN_ERR;
    }

    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) != 0) {
        wifi_util_error_print(WIFI_APPS, "%s:%d Failed to set mutex recursive attr\n",
            __func__, __LINE__);
        pthread_mutexattr_destroy(&attr);
        return RETURN_ERR;
    }

    /* Initialize state mutex */
    ret = pthread_mutex_init(&multiap_mutex, &attr);
    pthread_mutexattr_destroy(&attr);
    if (ret != 0) {
        wifi_util_error_print(WIFI_APPS, "%s:%d Failed to initialize multiap mutex: %d\n",
            __func__, __LINE__, ret);
        return RETURN_ERR;
    }

    if (app_init(app, create_flag) != 0) {
        wifi_util_error_print(WIFI_APPS, "%s:%d Failed to register app!\n", __func__, __LINE__);
        pthread_mutex_destroy(&multiap_mutex);
        return RETURN_ERR;
    }

    pthread_mutex_lock(&multiap_mutex);
    state = multiap_state_none;
    pthread_mutex_unlock(&multiap_mutex);

    wifi_util_info_print(WIFI_APPS, "%s:%d Init multiap_app\n", __func__, __LINE__);

    return RETURN_OK;
}
