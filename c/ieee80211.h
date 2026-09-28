/*
 * ieee80211.h - 802.11 MAC header constants (IEEE Std 802.11-2020, clause 9).
 *
 *   Frame Control (2) | Duration/ID (2) | Addr1 (6) | Addr2 (6) | Addr3 (6) |
 *   Sequence Control (2) | [Addr4 (6)] | [QoS Control (2)] | [HT Control (4)]
 *
 * Multi-byte fields are little-endian.
 */
#ifndef WIFIPARSE_IEEE80211_H
#define WIFIPARSE_IEEE80211_H

#define WLAN_MAC_LEN 6u
#define WLAN_FCS_LEN 4u

/* Byte offsets inside the MAC header. */
#define WLAN_OFF_ADDR1 4u
#define WLAN_OFF_ADDR2 10u
#define WLAN_OFF_ADDR3 16u
#define WLAN_OFF_SEQCTL 22u
#define WLAN_OFF_ADDR4 24u

/* Frame types: Frame Control byte 0, bits 2-3. */
#define WLAN_TYPE_MGMT 0u
#define WLAN_TYPE_CTRL 1u
#define WLAN_TYPE_DATA 2u
#define WLAN_TYPE_EXT  3u

/* Frame Control byte 1: flag bits (9.2.4.1). */
#define WLAN_FC_TO_DS     0x01u
#define WLAN_FC_FROM_DS   0x02u
#define WLAN_FC_RETRY     0x08u
#define WLAN_FC_PROTECTED 0x40u
#define WLAN_FC_ORDER     0x80u /* +HTC: a 4-byte HT Control field is present */

/* Control subtypes that matter for header length / addresses (Table 9-1). */
#define WLAN_CTRL_TRIGGER       2u /* added by IEEE 802.11ax */
#define WLAN_CTRL_BF_REPORT_POLL 4u
#define WLAN_CTRL_NDP_ANNOUNCE  5u
#define WLAN_CTRL_BLOCK_ACK_REQ 8u
#define WLAN_CTRL_BLOCK_ACK     9u
#define WLAN_CTRL_PS_POLL       10u
#define WLAN_CTRL_RTS           11u
#define WLAN_CTRL_CF_END        14u
#define WLAN_CTRL_CF_END_ACK    15u

/* Data subtype bits: bit 3 = QoS, bit 2 = "no data" (Null, QoS Null). */
#define WLAN_DATA_QOS     0x8u
#define WLAN_DATA_NO_DATA 0x4u

/* First QoS Control byte, bit 7: A-MSDU present. */
#define WLAN_QOS_AMSDU 0x80u

#endif
