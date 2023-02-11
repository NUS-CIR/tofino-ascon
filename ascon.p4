#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header ascon_h {
    bit<64>   s0;
    bit<64>   s1;
    bit<64>   s2;
    bit<64>   s3;
    bit<64>   s4;
}

struct my_ingress_headers_t {
    ethernet_h   ethernet;
    ascon_h      ascon;
}

struct my_ingress_metadata_t {
    bit<64> t0;
    bit<64> t1;
    bit<64> t2;
    bit<64> t3;
    bit<64> t4;

    bit<64> u0;
    bit<64> u1;
    bit<64> u2;
    bit<64> u3;
    bit<64> u4;

    bit<64> p0;
    bit<64> p1;
    bit<64> p2;
    bit<64> p3;
    bit<64> p4;

    bit<64> q0;
    bit<64> q1;
    bit<64> q2;
    bit<64> q3;
    bit<64> q4;
}

parser MyIngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
     state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition parse_ascon;
    }

    state parse_ascon {
        pkt.extract(hdr.ascon);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control MyIngress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{   
    Hash<bit<64>>(HashAlgorithm_t.IDENTITY) copy0;

    action addition() {
        hdr.ascon.s2 = hdr.ascon.s2 ^ 0x80;
    }

    action substitution() {
        hdr.ascon.s0 = hdr.ascon.s0 ^ hdr.ascon.s4;
        hdr.ascon.s4 = hdr.ascon.s4 ^ hdr.ascon.s3; 
        hdr.ascon.s2 = hdr.ascon.s2 ^ hdr.ascon.s1;
    }

    action start_sbox_0 () {
        meta.t0 = ~hdr.ascon.s1 & hdr.ascon.s2;
        meta.t1 = ~hdr.ascon.s2 & hdr.ascon.s3;
        meta.t2 = ~hdr.ascon.s3 & hdr.ascon.s4;
        meta.t3 = ~hdr.ascon.s4 & hdr.ascon.s0;
        meta.t4 = ~hdr.ascon.s0 & hdr.ascon.s1;
    }
    
    action start_sbox_1 () {
        meta.t0 = hdr.ascon.s0 ^ meta.t0;
        meta.t1 = hdr.ascon.s1 ^ meta.t1;
        meta.t2 = hdr.ascon.s2 ^ meta.t2;
        meta.t3 = hdr.ascon.s3 ^ meta.t3;
        meta.t4 = hdr.ascon.s4 ^ meta.t4;
    }

    action end_sbox() {
        meta.t1 = meta.t1 ^ meta.t0;
        meta.t0 = meta.t0 ^ meta.t4;
        meta.t3 = meta.t3 ^ meta.t2;
        meta.t2 = ~meta.t2;
    }

    action copy_meta() {
        meta.u0 = meta.t0;
        meta.u1 = meta.t1;
        meta.u2 = meta.t2;
        meta.u3 = meta.t3;
        meta.u4 = meta.t4;
    }

    action diffusion_0 () {
        // ROR(t.x[0], 19)
        @in_hash { meta.p0[63:32] = meta.t0[18:0] ++ meta.t0[63:51]; }
        // ROR(t.x[1], 61) 
    }
    
    action diffusion_1 () {
        // ROR(t.x[0], 19)
        @in_hash { meta.p0[31:0] = meta.t0[50:19]; }
        // ROR(t.x[1], 61) 
    }

    action diffusion_2 () {
        // ROR(t.x[0], 28);
        @in_hash { meta.q0[63:32] = meta.u0[27:0] ++ meta.u0[63:60]; }; 
        // ROR(t.x[1], 39);
    }
    action diffusion_3 () {
        // ROR(t.x[0], 28);
        @in_hash { meta.q0[31:0] = meta.u0[59:28]; }; 
        // ROR(t.x[1], 39);
    }

    action diffusion_4() {
        // s->x[0] = t.x[0] ^ ROR(t.x[0], 19) ^ ROR(t.x[0], 28);
        @in_hash { meta.p0 = meta.p0 ^ meta.q0; } 
        // s->x[1] = t.x[1] ^ ROR(t.x[1], 61) ^ ROR(t.x[1], 39);
    }

    action diffusion_5() {
        // s->x[0] = t.x[0] ^ ROR(t.x[0], 19) ^ ROR(t.x[0], 28);
        @in_hash { hdr.ascon.s0 = meta.t0 ^ meta.p0; } 
        // s->x[1] = t.x[1] ^ ROR(t.x[1], 61) ^ ROR(t.x[1], 39);
    }

    apply {
        // /* addition of round constant */
        // s->x[2] ^= C;
        addition();

        // /* printstate(" round constant", s); */
        // /* substitution layer */
        // s->x[0] ^= s->x[4];
        // s->x[4] ^= s->x[3];
        // s->x[2] ^= s->x[1];
        substitution();

        // /* start of keccak s-box */
        // t.x[0] = s->x[0] ^ (~s->x[1] & s->x[2]);
        // t.x[1] = s->x[1] ^ (~s->x[2] & s->x[3]);
        // t.x[2] = s->x[2] ^ (~s->x[3] & s->x[4]);
        // t.x[3] = s->x[3] ^ (~s->x[4] & s->x[0]);
        // t.x[4] = s->x[4] ^ (~s->x[0] & s->x[1]);
        start_sbox_0();
        start_sbox_1();
        
        // /* end of keccak s-box */
        // t.x[1] ^= t.x[0];
        // t.x[0] ^= t.x[4];
        // t.x[3] ^= t.x[2];
        // t.x[2] = ~t.x[2];
        end_sbox();

        copy_meta();
        
        // /* printstate(" substitution layer", &t); */
        // /* linear diffusion layer */
        // s->x[0] = t.x[0] ^ ROR(t.x[0], 19) ^ ROR(t.x[0], 28);
        // s->x[1] = t.x[1] ^ ROR(t.x[1], 61) ^ ROR(t.x[1], 39);
        // s->x[2] = t.x[2] ^ ROR(t.x[2], 1) ^ ROR(t.x[2], 6);
        // s->x[3] = t.x[3] ^ ROR(t.x[3], 10) ^ ROR(t.x[3], 17);
        // s->x[4] = t.x[4] ^ ROR(t.x[4], 7) ^ ROR(t.x[4], 41);
        diffusion_0();
        diffusion_1();
        diffusion_2();
        diffusion_3();
        diffusion_4();
        diffusion_5();

        // hdr.ascon.s0 = meta.t0;
        hdr.ascon.s1 = meta.t1;
        hdr.ascon.s2 = meta.t2;
        hdr.ascon.s3 = meta.t3;
        hdr.ascon.s4 = meta.t4;

        ig_tm_md.ucast_egress_port = 1;
    }
}

    /*********************  D E P A R S E R  ************************/

control MyIngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

    /***********************  P A R S E R  **************************/

parser MyEgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control MyEgress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {
    }
}

    /*********************  D E P A R S E R  ************************/

control MyEgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    MyIngressParser(),
    MyIngress(),
    MyIngressDeparser(),
    MyEgressParser(),
    MyEgress(),
    MyEgressDeparser()
) pipe;

Switch(pipe) main;
