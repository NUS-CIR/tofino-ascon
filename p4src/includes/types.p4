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

typedef bit<8> round_type_t;
const round_type_t P6 = 2;
const round_type_t P8 = 1; 
const round_type_t P12 = 0;

// TODO: need more detailed states here
typedef bit<8>  state_t;
const state_t STATE_RECV = 0;
const state_t STATE_INIT = 1;
const state_t STATE_AD = 2;
const state_t STATE_PT = 3;
const state_t STATE_CT = 4;
const state_t STATE_FIN = 5;

struct ascon_t {
    bool    is_absorb_pt;
    bool    is_finalize;
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