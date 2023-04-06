// ----------------------------------------------------------------------------
// Common protocols/types
//-----------------------------------------------------------------------------
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP  0x0806

#define IP_PROTOCOLS_ICMP   1
#define IP_PROTOCOLS_IGMP   2
#define IP_PROTOCOLS_IPV4   4
#define IP_PROTOCOLS_TCP    6
#define IP_PROTOCOLS_UDP    17

typedef PortId_t switch_port_t;

typedef bit<4> round_type_t;
const round_type_t P12 = 1;
const round_type_t P8 = 2; 
const round_type_t P6 = 3;
const round_type_t P0 = 4;

// TODO: need more detailed states here
typedef bit<8>  state_t;
const state_t STATE_INIT = 10;
const state_t STATE_AD = 20;
const state_t STATE_AD_FINAL = 21;
const state_t STATE_PT = 30;
const state_t STATE_PT2 = 31;
const state_t STATE_PT3 = 32;
const state_t STATE_PT4 = 33;
const state_t STATE_PT_FINAL = 32;
const state_t STATE_CT = 40;
const state_t STATE_CT_FINAL = 41;
const state_t STATE_FINAL = 50;
const state_t STATE_TAG = 60;

struct ascon_t {
    bit<32> associated_data;
    bit<64> k0;
    bit<64> k1;
    bit<64> n0;
    bit<64> n1;

    bool    is_finalize;
    bool    is_absorb_pt;
#ifdef PAYLOAD_16B
    bool    is_absorb_pt2;
#elif PAYLOAD_32B
    bool    is_absorb_pt2;
    bool    is_absorb_pt3;
    bool    is_absorb_pt4;
#endif
}

// Switch Local Metadata  --------------------------------------------------------------------
struct switch_local_metadata_t {
    ascon_t ascon;
}

// Switch Bridged Metadata --------------------------------------------------------------------
header switch_bridged_metadata_h {
    // TODO
}

// Switch Header  --------------------------------------------------------------------
struct switch_header_t {
    switch_bridged_metadata_h bridge;
    ethernet_h ethernet;
    ipv4_h ipv4;
    udp_h udp;
    ascon_h ascon;
    ascon_meta_h ascon_meta;
    ascon_tag_h ascon_tag;
    ascon_out_h ascon_out;
    payload_h payload;
}   