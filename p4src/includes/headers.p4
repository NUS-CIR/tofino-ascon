//-----------------------------------------------------------------------------
// Protocol Header Definitions
//-----------------------------------------------------------------------------

typedef bit<48> mac_addr_t;
typedef bit<16> ether_type_t;
typedef bit<32> ipv4_addr_t;

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    ether_type_t ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
}

header payload_h {
    bit<64> p0;
}

header ascon_h {
    bit<64>   s0;
    bit<64>   s1;
    bit<64>   s2;
    bit<64>   s3;
    bit<64>   s4;
}

header ascon_meta_h {
    bit<8>      curr_state;
    bit<8>      next_state;
    bit<8>      round_type;
    bit<8>      curr_round;
}

header ascon_out_h {
    bit<64> o0;
}

header ascon_tag_h {
    bit<64> tag0;
    bit<64> tag1;
}