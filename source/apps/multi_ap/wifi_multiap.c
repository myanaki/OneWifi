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

#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_multiap.h"
#include "wifi_stubs.h"
#include "wifi_util.h"

#define FAILOVER_ENABLE "Device.X_RDK_GatewayManagement.Failover.Enable"

volatile multiap_state_t state = multiap_state_none;

int multiap_init(wifi_app_t *app, unsigned int create_flag)
{
    if (app_init(app, create_flag) != 0) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: Failed to register app!\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    wifi_util_info_print(WIFI_APPS, "%s:%d: IEEE1905: Init multiap_app \n", __func__, __LINE__);

    return RETURN_OK;
}

int multiap_deinit(wifi_app_t *app)
{
    return RETURN_OK;
}

int parse_multiap_tlv(unsigned char *buff, unsigned int len, multiap_tlv_type_t type,
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

int get_service_type()
{
    wifi_ctrl_t *ctrl = NULL;
    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    wifi_util_info_print(WIFI_APPS, "Enter %s:%d\n", __func__, __LINE__);

    if (ctrl->network_mode == rdk_dev_mode_type_gw) {
        wifi_util_info_print(WIFI_APPS, "Gateway mode  %s:%d\n", __func__, __LINE__);
        return multiap_service_type_gateway;
    }
    else if (ctrl->network_mode == rdk_dev_mode_type_gw) {
        wifi_util_info_print(WIFI_APPS, "Extender mode  %s:%d\n", __func__, __LINE__);
        return multiap_service_type_extender;
    }
    else {
        wifi_util_error_print(WIFI_APPS, "UnSupported type %s:%d\n", __func__, __LINE__);
        return multi_service_type_none;
    }
}

int multiap_event_exec_start(wifi_app_t *apps, void *arg)
{
    wifi_ctrl_t *ctrl = NULL;
    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    wifi_util_info_print(WIFI_APPS, "%s:%d Start Exec\n", __func__, __LINE__);
    if (ctrl->rf_status_down || (ctrl->network_mode == rdk_dev_mode_type_ext)) {
        wifi_util_error_print(WIFI_APPS,
            "%s:%d rf_status_down=%d or network_mode=%d is enabled hence not starting the "
            "station\n",
            __func__, __LINE__, ctrl->rf_status_down, ctrl->network_mode);
        return RETURN_OK;
    }

    ctrl->multiap_sta_enabled = true;
    receive_multiap_message();
    // start the station vaps only if none of the station is connected to vaps because in XLE when
    // its in GW mode(with WAN failover)
    //  stations are connected to the GW then we should not start the station vaps
    start_station_vaps(true, true);
    return RETURN_OK;
}

int multiap_event_exec_stop(wifi_app_t *apps, void *arg)
{
    wifi_ctrl_t *ctrl = NULL;
    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    wifi_util_info_print(WIFI_APPS, "%s:%d IEE1905: Stop.\n", __func__, __LINE__);
    ctrl->multiap_sta_enabled = false;
    start_station_vaps(true, false);
    return RETURN_OK;
}

int multiap_event_exec_timeout(wifi_app_t *apps, void *arg)
{
    //char *interface_name = (char *)arg;
    // Hardcoded interface names for debugging
    const char *test_interfaces[] = {"brlan0", "wl1", "wl0"};
    unsigned int num_interfaces = sizeof(test_interfaces) / sizeof(test_interfaces[0]);

    wifi_util_info_print(WIFI_APPS, "%s:%d IEEE1905: inside multiap_event_exec_timeout\n", __func__,
        __LINE__);
    // Send autoconfiguration search on each interface
    for (unsigned int i = 0; i < num_interfaces; i++) {
        send_multiap_broadcast_message((char *)test_interfaces[i]);
    }
    //send_multiap_broadcast_message(interface_name);
    return RETURN_OK;
}

int handle_autoconf_search(unsigned char *data, unsigned int len)
{
    unsigned char msg[MAX_BUFF_SZ];
    mac_address_t dst;
    wifi_ctrl_t *ctrl = NULL;
    char st[64];
    char *ifaces[MAX_IFACES] = { "brlan0", "wl1", "wl0.1", "wl0", "wl0.7", "wl1.7", "wl2.1",
        "wl1.1" };
    unsigned char buff[128] = { 0 };
    multiap_supported_srv_t *srv = (multiap_supported_srv_t *)buff;
    int device_supporting_service = get_service_type();

    wifi_util_info_print(WIFI_APPS, "Enter %s:%d\n", __func__, __LINE__);
    wifi_util_info_print(WIFI_APPS, "device_supporting_service = %d: %s:%d\n",
        device_supporting_service, __func__, __LINE__);

    if (parse_multiap_tlv(data, len, multiap_tlv_type_supported_service, srv, sizeof(buff)) < 0) {
        wifi_util_error_print(WIFI_APPS, "Service type TLV not found\n");
        return -1;
    }
    wifi_util_error_print(WIFI_APPS, "%s:%d IEEE1905: supported_service = %d: hex value = 0x%x\n",
        __func__, __LINE__, srv->supported_service[0], srv->supported_service[0]);
    if (device_supporting_service == multiap_service_type_extender ||
        srv->supported_service[0] == multiap_service_type_extender) {
        wifi_util_error_print(WIFI_APPS,
            "%s:%d either supporting service or supported service is extender so not replying\n",
             __func__, __LINE__);
        return -1;
    }
    wifi_util_info_print(WIFI_APPS, "split brain is detected in the network\n");

    state = multiap_state_completed;
    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    // Extract AL MAC address
    if (parse_multiap_tlv(data, len, multiap_tlv_type_al_mac_address, &dst, sizeof(mac_address_t)) <
        0) {
        wifi_util_error_print(WIFI_APPS, "AL MAC address TLV not found\n");
        return -1;
    }

    uint8_mac_to_string_mac(dst, st);
    wifi_util_info_print(WIFI_APPS, "%s:%d sender mac=%s\n", __func__, __LINE__, st);
    for (int i = 0; i < MAX_IFACES; ++i) {
        len = create_autoconfig_resp_msg(msg, (unsigned char *)dst, ifaces[i]);
        wifi_util_error_print(WIFI_APPS, "After create_autoconfig_resp_msg got len = %s:%d :%d\n",
            __func__, __LINE__, len);
        send_frame(msg, len, false, ifaces[i]);
    }

    wifi_util_info_print(WIFI_APPS, "autoconfig response is sent to Gateway\n");
    set_to_extender_mode(&ctrl->handle, FAILOVER_ENABLE, 0, 0);

    set_to_extender_mode(&ctrl->handle, WIFI_DEVICE_MODE, 1, 1);

    wifi_util_info_print(WIFI_APPS,
        "switching the device to extender mode split brain recovered\n");
    return 0;
}

int handle_autoconf_search_resp(unsigned char *data, unsigned int len)
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

    wifi_util_info_print(WIFI_APPS, "Enter %s:%d\n", __func__, __LINE__);
    memset(macfilterkey, 0, sizeof(macfilterkey));
    //  Extract STA MAC addresses
    tlv_len = parse_multiap_tlv(data, len, multiap_tlv_type_sta_mac_addr, buffer, sizeof(buffer));
    if (tlv_len < 0) {
        wifi_util_error_print(WIFI_APPS, "STA MAC address TLV not found\n");
        return -1;
    }
    // This is the retriving mechanism from the TLV
    total_macs = tlv_len / MAC_ADDR_LEN;

    for (int i = 0; i < total_macs; ++i) {
        memcpy(mac, &buffer[i * MAC_ADDR_LEN], MAC_ADDR_LEN);
        to_mac_str(mac, new_mac_str);
        str_tolower(new_mac_str);
        wifi_util_info_print(WIFI_APPS, "Pramod mac_str array i val=%d: %s \n", i, new_mac_str);
        for (itr = 0; itr < 2; itr++) {
            wifi_vap_map = get_wifidb_vap_map(itr);
            for (itrj = 0; itrj < getMaxNumberVAPsPerRadio(itr); itrj++) {
                vap_index = wifi_vap_map->vap_array[itrj].vap_index;
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
                wifi_util_dbg_print(WIFI_APPS, "new_mac_str %s\n", new_mac_str);
                temp_acl_entry = hash_map_get(rdk_vap_info->acl_map, new_mac_str);

                if (temp_acl_entry != NULL) {
                    wifi_util_info_print(WIFI_APPS, "Mac is already present in macfilter \n");
                    continue;
                }
                wifi_util_info_print(WIFI_APPS, "%s:%d\n", __func__, __LINE__);

                acl_entry = (acl_entry_t *)malloc(sizeof(acl_entry_t));
                memcpy(acl_entry->mac, mac, sizeof(mac_address_t));
                to_mac_str(acl_entry->mac, new_mac_str);
                str_tolower(new_mac_str);

#ifdef NL80211_ACL
                if (wifi_hal_addApAclDevice(rdk_vap_info->vap_index, new_mac_str) != RETURN_OK) {
#else
                if (wifi_addApAclDevice(rdk_vap_info->vap_index, new_mac_str) != RETURN_OK) {
#endif
                    wifi_util_dbg_print(WIFI_APPS,
                        "%s:%d: wifi_addApAclDevice failed. vap_index %d, MAC %s \n", __func__,
                        __LINE__, rdk_vap_info->vap_index, new_mac_str);
                    continue;
                }

                hash_map_put(rdk_vap_info->acl_map, strdup(new_mac_str), acl_entry);
                snprintf(macfilterkey, sizeof(macfilterkey), "%s-%s", rdk_vap_info->vap_name,
                    new_mac_str);
                // get_wifidb_obj()->desc.update_wifi_macfilter_config_fn(macfilterkey, acl_entry,
                // true);
                wifi_util_info_print(WIFI_APPS, "%s:%d\n", __func__, __LINE__);
            }
        }
    }
    return 0;
}
int create_autoconfig_search(unsigned char *buff, char *interface_name)
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
    wifi_util_info_print(WIFI_APPS, "st from mac_address_from_name =%s \n", st);

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
    tlv->value[0] = get_service_type();
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
int send_frame(unsigned char *buff, unsigned int len, bool multicast, char *ifname)
{
    int ret = 0;
    multiap_raw_hdr_t *hdr = (multiap_raw_hdr_t *)(buff);

    struct sockaddr_ll sadr_ll;
    int sock;
    mac_address_t multi_addr = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    wifi_util_info_print(WIFI_APPS, "Sending frame on %s\n", ifname);

    sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        return -1;
    }

    sadr_ll.sll_ifindex = (int)(if_nametoindex(ifname));
    sadr_ll.sll_halen = ETH_ALEN; // length of destination mac address
    sadr_ll.sll_protocol = htons(ETH_P_ALL);
    memcpy(sadr_ll.sll_addr, (multicast == true) ? multi_addr : hdr->dst, sizeof(mac_address_t));

    ret = (int)(sendto(sock, buff, len, 0, (const struct sockaddr *)&sadr_ll,
        sizeof(struct sockaddr_ll)));
    wifi_util_info_print(WIFI_APPS, "Sent frame on %s ret val =%d\n", ifname, ret);
    close(sock);
    return ret;
}

void send_multiap_broadcast_message(char *ifname)
{
    unsigned char buff[MAX_BUFF_SZ];
    unsigned int sz;
    int i = 0;
    int wait_ret;
    wifi_util_info_print(WIFI_APPS, "%s:%d IEEE1905: ===== STARTING BROADCAST MESSAGE =====\n", __func__, __LINE__);
    wifi_util_info_print(WIFI_APPS, "%s:%d IEEE1905: Interface: %s\n", __func__, __LINE__, ifname);

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_util_info_print(WIFI_APPS, "%s:%d: ifname = %s\n", __func__, __LINE__, ifname);
    // state = multiap_state_none;
    if (multiap_service_type_extender == get_service_type() || state != multiap_state_none) {
        wifi_util_info_print(WIFI_APPS,
            "%s:%d:service type is extender or broadcast message is sent so returning \n", __func__,
            __LINE__);
        return;
    }

    state = multiap_state_search_rsp_pending;
    sz = create_autoconfig_search(buff, ifname);
    wifi_util_info_print(WIFI_APPS, "%s:%d IEEE1905: Starting retry loop (max %d attempts)\n",__func__, __LINE__, MAX_AUTOCONFIG_RETRIES);
    while (state != multiap_state_completed && (i <= MAX_AUTOCONFIG_RETRIES)) {
        wifi_util_info_print(WIFI_APPS, "%s:%d IEEE1905: Attempt %d: Sending frame\n", __func__, __LINE__, i+1);
        if (send_frame(buff, sz, true, ifname) < 0) {
            wifi_util_info_print(WIFI_APPS, "%s:%d: failed, err:%d\n", __func__, __LINE__);
            return;
        }
        wifi_util_info_print(WIFI_APPS, "%s:%d IEEE1905: Frame sent successfully\n", __func__, __LINE__);
        i++;
        wifi_util_info_print(WIFI_APPS, "%s:%d: state in while loop = %d and iteration =%d\n",
            __func__, __LINE__, state, i);
        // Wait 1 second between retries
        wait_ret = WaitForTimeout(AUTO_CFG_RETRY_MS);
        if (wait_ret == 0) {
            // Shutdown signal received
            break;
        } else if (wait_ret != ETIMEDOUT) {
            wifi_util_error_print(WIFI_APPS, "%s:%d: WaitForTimeout failed with error: %d\n",
                __func__, __LINE__, wait_ret);
            break;
        }
        wifi_util_info_print(WIFI_APPS, "%s:%d IEEE1905: ===== BROADCAST MESSAGE COMPLETED =====\n", __func__, __LINE__);
    }
    // state = multiap_state_none;
    wifi_util_info_print(WIFI_APPS, "IEEE1905: autoconfig_search send successful and state =%d \n",
        state);
    // After sending for Autofconfig search for 50 times if no reply is seen then the other device
    // is in extender mode
    apps_mgr_multiap_event(&ctrl->apps_mgr, wifi_event_type_exec, wifi_event_exec_stop, NULL, 0);
}

int set_bp_filter(int sockfd, const char *iface_name)
{
    struct packet_mreq mreq;
#define OP_LDH (BPF_LD | BPF_H | BPF_ABS)
#define OP_LDB (BPF_LD | BPF_B | BPF_ABS)
#define OP_JEQ (BPF_JMP | BPF_JEQ | BPF_K)
#define OP_RET (BPF_RET | BPF_K)
    static struct sock_filter bpfcode[4] = {
        { OP_LDH, 0, 0, 12 }, // ldh [12]
        { OP_JEQ, 0, 1, ETH_P_1905 }, // jeq #0x893a, L2, L3
        {
         OP_RET, 0,
         0, 0xffffffff,
         }, // ret #0xffffffff
        { OP_RET, 0, 0, 0 }, // ret #0x0
    };
    struct sock_fprog bpf = { 4, bpfcode };
    if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf))) {
        wifi_util_info_print(WIFI_APPS, "%s:%d: Error in attaching filter, err:%d\n", __func__,
            __LINE__, errno);
        close(sockfd);
        return -1;
    }

    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = (int)(if_nametoindex(iface_name));
    if (setsockopt(sockfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq))) {
        wifi_util_info_print(WIFI_APPS,
            "%s:%d: Error setting promisuous for interface:%s, err:%d\n", __func__, __LINE__,
            iface_name, errno);
        close(sockfd);
        return -1;
    }

    return 0;
}

int create_raw_socket(const char *iface_name)
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

int create_autoconfig_resp_msg(unsigned char *buff, unsigned char *dst, char *interface_name)
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
    wifi_util_info_print(WIFI_APPS, "string from mac_address_from_name %s =%s \n", interface_name,
        st);

    uint8_mac_to_string_mac(dst, st);
    wifi_util_info_print(WIFI_APPS, "string from mac_address_from_name of dest==%s \n", st);
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
    ;
    memcpy(tlv->value, &ctrl_cap, sizeof(multiap_ctrl_cap_t));

    tmp += (sizeof(multiap_tlv_t) + sizeof(multiap_ctrl_cap_t));
    len += (int)(sizeof(multiap_tlv_t) + sizeof(multiap_ctrl_cap_t));

    // STA MAC Address type TLV
    tlv = (multiap_tlv_t *)tmp;
    tlv->type = multiap_tlv_type_sta_mac_addr;
    for (itr = 0; itr < getNumberRadios(); itr++) {
        wifi_util_info_print(WIFI_APPS, "%s:%d index=%d and  getNumberRadios()=%d", __func__,
            __LINE__, itr, getNumberRadios());
        get_sta_mac_address_for_radio(&g_wifi_mgr->hal_cap.wifi_prop, itr, mac);
        uint8_mac_to_string_mac(mac, st);
        wifi_util_info_print(WIFI_APPS, "%s:%d pramod mac_adr= %s\n", __func__, __LINE__, st);
        memcpy(&mac_buffer[offset], mac, MAC_ADDR_LEN);
        offset += MAC_ADDR_LEN;
    }

    tlv->len = htons(offset);
    wifi_util_info_print(WIFI_APPS, "%s:%d pramod offset=%d\n", __func__, __LINE__, offset);
    memcpy(tlv->value, (unsigned char *)mac_buffer, offset);

    tmp += (sizeof(multiap_tlv_t) + offset);
    len += (int)(sizeof(multiap_tlv_t) + offset);
    // End of message
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof(multiap_tlv_t));
    len += (int)(sizeof(multiap_tlv_t));
    wifi_util_info_print(WIFI_APPS, "len = %d in fun=%s\n", len, __func__);
    return len;
}

void proto_process(unsigned char *data, unsigned int len)
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
        if (state == multiap_state_none) {
            wifi_util_info_print(WIFI_APPS, "%s:%d :Got a  packet of type =%d\n processing it",
                __func__, __LINE__, htons(cmdu->type));
            ret = handle_autoconf_search(data, len);
            if (ret == -1) {
                wifi_util_info_print(WIFI_APPS,
                    "autoconfig search response not sent hence setting the sate to none\n");
                state = multiap_state_none;
            } else {
                wifi_util_info_print(WIFI_APPS,
                    "autoconfig search response sent moving to extender mode\n");
            }
        }
        break;
    case multiap_msg_type_autoconf_resp:
        if (state == multiap_state_search_rsp_pending) {
            wifi_util_info_print(WIFI_APPS, "%s:%d :Got a valid packet of type =%d\n processing it",
                __func__, __LINE__, htons(cmdu->type));
            state = multiap_state_completed;
            handle_autoconf_search_resp(data, len);
            wifi_util_info_print(WIFI_APPS, "%s:%d :Bringing down the station", __func__, __LINE__);
            if (is_sta_enabled() == false) {
                wifi_util_info_print(WIFI_APPS, "%s:%d stop mesh sta\n", __func__, __LINE__);
                stop_extender_vaps();
                ctrl->webconfig_state |= ctrl_webconfig_state_vap_mesh_sta_cfg_rsp_pending;
            }
        }
        break;
    default:
        wifi_util_info_print(WIFI_APPS, "Got different  package\n");
        break;
    }
}
static void *receive_multicast_message(void *ctx)
{
    const char *ifaces[MAX_IFACES] = { "wl1.1", "wl1", "wl0.1", "wl0", "brlan0", "wl1.7", "brlan1",
        "wl0.7" };
    int sockets[MAX_IFACES];
    char buffer[MAX_FRAME_SZ];
    state = multiap_state_none;

    for (int i = 0; i < MAX_IFACES; ++i) {
        sockets[i] = create_raw_socket(ifaces[i]);
        if (sockets[i] < 0) {
            wifi_util_info_print(WIFI_APPS, "Failed to initialize socket on %s\n", ifaces[i]);
            return NULL;
        }
        wifi_util_info_print(WIFI_APPS, "%s:%d sockets[i]= %d\n", __func__, __LINE__, sockets[i]);
    }

    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds);

        int maxfd = -1;
        for (int i = 0; i < MAX_IFACES; i++) {
            FD_SET(sockets[i], &readfds);
            if (sockets[i] > maxfd)
                maxfd = sockets[i];
        }

        wifi_util_info_print(WIFI_APPS, "%s:%d maxfd = %d\n", __func__, __LINE__, maxfd);
        int ret = select(maxfd + 1, &readfds, NULL, NULL, NULL);
        if (ret < 0) {
            wifi_util_info_print(WIFI_APPS, "select error");
            break;
        }

        for (int i = 0; i < MAX_IFACES; ++i) {
            if (FD_ISSET(sockets[i], &readfds)) {
                ssize_t len = recvfrom(sockets[i], buffer, MAX_FRAME_SZ, 0, NULL, NULL);
                if (len < 0) {
                    wifi_util_info_print(WIFI_APPS, "recvfrom \n");
                    continue;
                }
                proto_process((unsigned char *)buffer, len);
            }
        }
    }
    return NULL;
}

void receive_multiap_message()
{
    wifi_util_info_print(WIFI_APPS, "receive message \n");
    int ret;
    pthread_attr_t attr;
    pthread_t thread_id;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    ret = pthread_create(&thread_id, &attr, receive_multicast_message, NULL);
    if (ret != 0) {
        wifi_util_error_print(WIFI_APPS, "Failed to create thread\n");
    } else {
        wifi_util_info_print(WIFI_APPS, "thread created successfully\n");
    }
}
int exec_event_multiap(wifi_app_t *apps, wifi_event_subtype_t sub_type, void *arg)
{
    switch (sub_type) {
    case wifi_event_exec_start:
        multiap_event_exec_start(apps, arg);
        break;

    case wifi_event_exec_stop:
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
        exec_event_multiap(app, event->sub_type, NULL);
        break;
    default:
        break;
    }
    return RETURN_OK;
}