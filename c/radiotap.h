/*
 * radiotap.h - the few radiotap definitions wifiparse needs.
 *
 * Radiotap is a header the capturing driver puts in front of each 802.11
 * frame to describe how it was received (channel, rate, signal, flags).
 * It is not sent over the air. Reference: https://www.radiotap.org/
 *
 *   offset 0  it_version  u8   always 0
 *   offset 1  it_pad      u8
 *   offset 2  it_len      u16  little-endian; length of the WHOLE radiotap header
 *   offset 4  it_present  u32  little-endian bitmap of which fields follow;
 *                              bit 31 set = another u32 bitmap follows
 *   then the fields, in bit order, each aligned to its natural size
 *   (alignment is measured from the start of the radiotap header).
 */
#ifndef WIFIPARSE_RADIOTAP_H
#define WIFIPARSE_RADIOTAP_H

#define RADIOTAP_MIN_LEN 8u /* version, pad, it_len, one present word */

/* Bits in the first it_present word (radiotap.org "Defined fields"). */
#define RADIOTAP_PRESENT_TSFT  (1u << 0)  /* u64, 8-byte aligned */
#define RADIOTAP_PRESENT_FLAGS (1u << 1)  /* u8 */
#define RADIOTAP_PRESENT_EXT   (1u << 31) /* another present word follows */

#define RADIOTAP_TSFT_LEN 8u

/* Bits in the Flags field. */
#define RADIOTAP_FLAG_FCS_AT_END 0x10u /* frame includes the 4-byte FCS */

#endif
