/*
 * wifiparse - read a capture with libpcap and print one JSON line per
 * 802.11 frame: type, subtype, flags, addresses, sequence number, FCS check.
 *
 *   usage: wifiparse [--limit N] [--quiet] CAPTURE
 *
 *   --limit N   stop after N packets
 *   --quiet     print only a summary line (frame count, errors, elapsed time)
 *
 * It's an independent second implementation of the Python analyzer's header
 * parsing (src/wifi_analyzer/frames.py), so the two can be cross-checked,
 * and both against Wireshark.
 *
 * Safety rules followed everywhere below:
 *   - Every read is preceded by an explicit length check against the number
 *     of bytes actually captured (caplen), never the original length on the wire.
 *   - Multi-byte fields are assembled byte by byte (le16/le32), never by
 *     casting a pointer, so unaligned data can't trigger undefined behaviour.
 *   - Malformed or truncated frames produce a JSON record with "error" set;
 *     they never stop the program.
 *   - The only heap allocation is libpcap's handle, closed on every exit path.
 */
#include <pcap.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ieee80211.h"
#include "radiotap.h"

/* pcap link types (https://www.tcpdump.org/linktypes.html) */
#define LINKTYPE_IEEE802_11       105
#define LINKTYPE_IEEE802_11_RADIO 127

#define ERR_LEN 128

/* Everything we learn about one frame. Address pointers point into the
 * packet buffer and are NULL when the frame type has no such address. */
struct frame {
    bool have_fc; /* Frame Control was readable: type/subtype/flags valid */
    unsigned type, subtype;
    bool to_ds, from_ds, retry, protected_frame;
    const uint8_t *addr1, *addr2, *addr3, *addr4;
    const uint8_t *sa, *da, *bssid;
    int seq;             /* -1 when the frame has no Sequence Control field */
    int fcs_ok;          /* -1 no FCS captured, 0 bad, 1 good */
    char error[ERR_LEN]; /* empty string = no error */
};

/* ---- little helpers ---------------------------------------------------- */

static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* CRC-32 as used by the 802.11 FCS (and Ethernet, zlib): reflected
 * polynomial 0xEDB88320, initial value and final XOR 0xFFFFFFFF. */
static uint32_t crc_table[256];

static void crc32_init(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++)
            c = (c & 1u) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
        crc_table[i] = c;
    }
}

static uint32_t crc32_ieee(const uint8_t *p, size_t n)
{
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++)
        c = crc_table[(c ^ p[i]) & 0xFFu] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

/* ---- radiotap ------------------------------------------------------------ */

/*
 * Validate the radiotap header and return its length (it_len) in *rt_len.
 * Also report whether the Flags field says an FCS is at the end of the frame.
 * Returns false (with f->error set) if the header is unusable.
 */
static bool parse_radiotap(const uint8_t *pkt, size_t caplen, size_t *rt_len, bool *has_fcs,
                           struct frame *f)
{
    *has_fcs = false;
    if (caplen < RADIOTAP_MIN_LEN) {
        snprintf(f->error, ERR_LEN, "radiotap header truncated: %zu of %u bytes", caplen, RADIOTAP_MIN_LEN);
        return false;
    }
    if (pkt[0] != 0) {
        /* Only version 0 has ever been defined. */
        snprintf(f->error, ERR_LEN, "unknown radiotap version %u", (unsigned)pkt[0]);
        return false;
    }
    size_t it_len = le16(pkt + 2);
    if (it_len < RADIOTAP_MIN_LEN) {
        snprintf(f->error, ERR_LEN, "radiotap it_len %zu is smaller than the fixed header", it_len);
        return false;
    }
    if (it_len > caplen) {
        snprintf(f->error, ERR_LEN, "radiotap it_len %zu exceeds captured length %zu", it_len, caplen);
        return false;
    }
    *rt_len = it_len;

    /*
     * Find the Flags field. The present bitmaps come first: keep reading u32
     * words while bit 31 (EXT) is set; the fields start right after the last
     * word. Only TSFT (bit 0) can come before Flags (bit 1). TSFT is a u64,
     * aligned to 8 bytes counted from the start of the radiotap header.
     * All reads stay inside it_len. If the bitmaps run off the end we just
     * treat the FCS as absent; the 802.11 frame itself may still be fine.
     */
    uint32_t present0 = le32(pkt + 4);
    size_t off = 4;
    uint32_t word = present0;
    while (word & RADIOTAP_PRESENT_EXT) {
        off += 4;
        if (off + 4 > it_len)
            return true;
        word = le32(pkt + off);
    }
    off += 4; /* first field */
    if (present0 & RADIOTAP_PRESENT_TSFT)
        off = ((off + 7u) & ~(size_t)7u) + RADIOTAP_TSFT_LEN;
    if ((present0 & RADIOTAP_PRESENT_FLAGS) && off < it_len)
        *has_fcs = (pkt[off] & RADIOTAP_FLAG_FCS_AT_END) != 0;
    return true;
}

/* ---- 802.11 header ------------------------------------------------------- */

/* Control frames with a transmitter address (Addr2): Trigger, Beamforming
 * Report Poll, VHT/HE NDP Announcement, BlockAckReq, BlockAck, PS-Poll, RTS,
 * CF-End, CF-End+CF-Ack. ACK and CTS only have Addr1. */
static bool ctrl_has_addr2(unsigned subtype)
{
    switch (subtype) {
    case WLAN_CTRL_TRIGGER:
    case WLAN_CTRL_BF_REPORT_POLL:
    case WLAN_CTRL_NDP_ANNOUNCE:
    case WLAN_CTRL_BLOCK_ACK_REQ:
    case WLAN_CTRL_BLOCK_ACK:
    case WLAN_CTRL_PS_POLL:
    case WLAN_CTRL_RTS:
    case WLAN_CTRL_CF_END:
    case WLAN_CTRL_CF_END_ACK:
        return true;
    default:
        return false;
    }
}

/*
 * Length of the MAC header for this frame type, so we can check the frame
 * is long enough before reading any field (IEEE 802.11-2020 clause 9.3):
 *   management: 24 (+4 HT Control if Order is set)
 *   data:       24 (+6 Addr4 if ToDS and FromDS) (+2 QoS Control for QoS
 *               subtypes) (+4 HT Control if a QoS frame has Order set)
 *   control:    16 if it carries Addr2 (see ctrl_has_addr2), else 10
 *   extension:  at least FC + Duration + Addr1 = 10
 */
static size_t header_len(unsigned type, unsigned subtype, unsigned flags)
{
    switch (type) {
    case WLAN_TYPE_MGMT:
        return 24u + ((flags & WLAN_FC_ORDER) ? 4u : 0u);
    case WLAN_TYPE_DATA: {
        size_t n = 24u;
        if ((flags & WLAN_FC_TO_DS) && (flags & WLAN_FC_FROM_DS))
            n += WLAN_MAC_LEN;
        if (subtype & WLAN_DATA_QOS) {
            n += 2u;
            if (flags & WLAN_FC_ORDER)
                n += 4u;
        }
        return n;
    }
    case WLAN_TYPE_CTRL:
        return ctrl_has_addr2(subtype) ? 16u : 10u;
    default:
        return 10u;
    }
}

/*
 * Work out source, destination and BSSID the way Wireshark fills
 * wlan.sa / wlan.da / wlan.bssid (IEEE 802.11-2020 9.3.2.1 for data frames):
 *
 *   ToDS FromDS   Addr1   Addr2   Addr3   Addr4
 *    0     0      DA      SA      BSSID   -
 *    1     0      BSSID   SA      DA      -      client -> AP
 *    0     1      DA      BSSID   SA      -      AP -> client
 *    1     1      RA      TA      DA      SA     mesh / WDS, no single BSSID
 *
 * In an A-MSDU, SA/DA belong to each packet inside the aggregate, so the
 * header's Addr3 (and Addr4) are not SA/DA.
 */
static void resolve_addresses(struct frame *f, bool amsdu)
{
    if (f->type == WLAN_TYPE_MGMT) {
        f->da = f->addr1;
        f->sa = f->addr2;
        f->bssid = f->addr3;
    } else if (f->type == WLAN_TYPE_DATA) {
        if (!f->to_ds && !f->from_ds) {
            f->da = f->addr1;
            f->sa = f->addr2;
            f->bssid = f->addr3;
        } else if (f->to_ds && !f->from_ds) {
            f->bssid = f->addr1;
            f->sa = f->addr2;
            f->da = amsdu ? NULL : f->addr3;
        } else if (!f->to_ds && f->from_ds) {
            f->da = f->addr1;
            f->bssid = f->addr2;
            f->sa = amsdu ? NULL : f->addr3;
        } else if (!amsdu) {
            f->da = f->addr3;
            f->sa = f->addr4;
        }
    } else if (f->type == WLAN_TYPE_CTRL) {
        if (f->subtype == WLAN_CTRL_PS_POLL)
            f->bssid = f->addr1; /* PS-Poll is addressed to the AP */
        else if (f->subtype == WLAN_CTRL_CF_END)
            f->bssid = f->addr2; /* CF-End is sent by the AP */
    }
}

/* Parse the 802.11 frame in p[0..len). len excludes any FCS. */
static void parse_80211(const uint8_t *p, size_t len, struct frame *f)
{
    if (len < 2) {
        snprintf(f->error, ERR_LEN, "truncated: %zu bytes, Frame Control needs 2", len);
        return;
    }
    /* Frame Control byte 0: bits 0-1 protocol version, 2-3 type, 4-7 subtype.
     * Byte 1: flags. */
    unsigned fc0 = p[0], flags = p[1];
    f->have_fc = true;
    f->type = (fc0 >> 2) & 0x3u;
    f->subtype = (fc0 >> 4) & 0xFu;
    f->to_ds = (flags & WLAN_FC_TO_DS) != 0;
    f->from_ds = (flags & WLAN_FC_FROM_DS) != 0;
    f->retry = (flags & WLAN_FC_RETRY) != 0;
    f->protected_frame = (flags & WLAN_FC_PROTECTED) != 0;

    if ((fc0 & 0x3u) != 0) {
        /* Version 1 is 802.11ah's short "PV1" header, a different layout;
         * 2 and 3 are undefined (usually a corrupted frame). */
        snprintf(f->error, ERR_LEN, "unsupported protocol version %u", fc0 & 0x3u);
        return;
    }

    size_t hlen = header_len(f->type, f->subtype, flags);
    if (len < hlen) {
        snprintf(f->error, ERR_LEN, "truncated: %zu bytes, header needs %zu", len, hlen);
        return;
    }

    /* From here on, every offset used is < hlen <= len. */
    f->addr1 = p + WLAN_OFF_ADDR1;
    if (f->type == WLAN_TYPE_MGMT || f->type == WLAN_TYPE_DATA) {
        f->addr2 = p + WLAN_OFF_ADDR2;
        f->addr3 = p + WLAN_OFF_ADDR3;
        /* Sequence Control: low 4 bits fragment number, high 12 bits sequence number. */
        f->seq = le16(p + WLAN_OFF_SEQCTL) >> 4;
    } else if (f->type == WLAN_TYPE_CTRL && ctrl_has_addr2(f->subtype)) {
        f->addr2 = p + WLAN_OFF_ADDR2;
    }
    /* Extension frames (e.g. DMG Beacon) have their own layout: Addr1 only. */

    bool amsdu = false;
    if (f->type == WLAN_TYPE_DATA) {
        size_t qos_off = WLAN_OFF_ADDR4;
        if (f->to_ds && f->from_ds) {
            f->addr4 = p + WLAN_OFF_ADDR4;
            qos_off += WLAN_MAC_LEN;
        }
        /* QoS Control is inside hlen for QoS subtypes; "no data" subtypes
         * (QoS Null) can't carry an A-MSDU. */
        if ((f->subtype & WLAN_DATA_QOS) && !(f->subtype & WLAN_DATA_NO_DATA))
            amsdu = (p[qos_off] & WLAN_QOS_AMSDU) != 0;
    }
    resolve_addresses(f, amsdu);
}

/* Parse one captured packet according to the link type. */
static void parse_packet(const uint8_t *pkt, size_t caplen, int linktype, struct frame *f)
{
    memset(f, 0, sizeof *f);
    f->seq = -1;
    f->fcs_ok = -1;

    const uint8_t *body = pkt;
    size_t len = caplen;
    bool has_fcs = false;

    if (linktype == LINKTYPE_IEEE802_11_RADIO) {
        size_t rt_len = 0;
        if (!parse_radiotap(pkt, caplen, &rt_len, &has_fcs, f))
            return;
        body = pkt + rt_len;
        len = caplen - rt_len;
    }

    if (has_fcs) {
        /* The FCS is a CRC-32 over the whole MAC frame, sent least-significant
         * byte first. Monitor mode passes up frames that failed it, so we check. */
        if (len < WLAN_FCS_LEN) {
            snprintf(f->error, ERR_LEN, "truncated: %zu bytes, FCS alone needs %u", len, WLAN_FCS_LEN);
            return;
        }
        len -= WLAN_FCS_LEN;
        f->fcs_ok = crc32_ieee(body, len) == le32(body + len);
    }
    parse_80211(body, len, f);
}

/* ---- output -------------------------------------------------------------- */

static void print_mac(const char *key, const uint8_t *mac)
{
    if (!mac) {
        printf(",\"%s\":null", key);
        return;
    }
    printf(",\"%s\":\"%02x:%02x:%02x:%02x:%02x:%02x\"", key, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static const char *json_bool(bool b) { return b ? "true" : "false"; }

static void print_frame(unsigned long idx, const struct pcap_pkthdr *hdr, const struct frame *f)
{
    printf("{\"idx\":%lu,\"ts\":%lld.%06ld,\"caplen\":%lu", idx, (long long)hdr->ts.tv_sec,
           (long)hdr->ts.tv_usec, (unsigned long)hdr->caplen);
    if (f->have_fc)
        printf(",\"type\":%u,\"subtype\":%u,\"to_ds\":%s,\"from_ds\":%s,\"retry\":%s,\"protected\":%s", f->type,
               f->subtype, json_bool(f->to_ds), json_bool(f->from_ds), json_bool(f->retry),
               json_bool(f->protected_frame));
    else
        printf(",\"type\":null,\"subtype\":null,\"to_ds\":null,\"from_ds\":null,\"retry\":null,\"protected\":null");
    print_mac("addr1", f->addr1);
    print_mac("addr2", f->addr2);
    print_mac("addr3", f->addr3);
    print_mac("addr4", f->addr4);
    print_mac("sa", f->sa);
    print_mac("da", f->da);
    print_mac("bssid", f->bssid);
    if (f->seq >= 0)
        printf(",\"seq\":%d", f->seq);
    else
        printf(",\"seq\":null");
    printf(",\"fcs_ok\":%s", f->fcs_ok < 0 ? "null" : json_bool(f->fcs_ok == 1));
    /* Error strings are our own snprintf output: printable ASCII with no
     * quotes or backslashes, so they need no JSON escaping. */
    if (f->error[0])
        printf(",\"error\":\"%s\"}\n", f->error);
    else
        printf(",\"error\":null}\n");
}

/* ---- main ---------------------------------------------------------------- */

static int usage(void)
{
    fprintf(stderr, "usage: wifiparse [--limit N] [--quiet] CAPTURE\n");
    return 2;
}

static double now_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
    const char *path = NULL;
    unsigned long limit = 0; /* 0 = no limit */
    bool quiet = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--limit") == 0 && i + 1 < argc) {
            char *end = NULL;
            limit = strtoul(argv[++i], &end, 10);
            if (!end || *end != '\0')
                return usage();
        } else if (strcmp(argv[i], "--quiet") == 0) {
            quiet = true;
        } else if (argv[i][0] == '-' || path) {
            return usage();
        } else {
            path = argv[i];
        }
    }
    if (!path)
        return usage();

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pc = pcap_open_offline(path, errbuf);
    if (!pc) {
        fprintf(stderr, "wifiparse: %s\n", errbuf);
        return 1;
    }
    int linktype = pcap_datalink(pc);
    if (linktype != LINKTYPE_IEEE802_11 && linktype != LINKTYPE_IEEE802_11_RADIO) {
        fprintf(stderr, "wifiparse: link type %d carries no 802.11 frames; nothing to do\n", linktype);
        pcap_close(pc);
        return 0;
    }

    crc32_init();
    double start = now_seconds();
    unsigned long idx = 0, errors = 0;
    struct pcap_pkthdr *hdr;
    const u_char *data;
    int rc;
    while ((rc = pcap_next_ex(pc, &hdr, &data)) == 1) {
        idx++; /* 1-based, the same numbering as Wireshark's frame.number */
        struct frame f;
        parse_packet(data, hdr->caplen, linktype, &f);
        if (f.error[0])
            errors++;
        if (!quiet)
            print_frame(idx, hdr, &f);
        if (limit && idx >= limit)
            break;
    }
    int status = 0;
    if (rc == PCAP_ERROR) {
        /* A read error mid-file (e.g. the file itself is truncated). */
        fprintf(stderr, "wifiparse: %s\n", pcap_geterr(pc));
        status = 1;
    }
    if (quiet)
        printf("{\"frames\":%lu,\"errors\":%lu,\"seconds\":%.6f}\n", idx, errors, now_seconds() - start);
    pcap_close(pc);
    return status;
}
