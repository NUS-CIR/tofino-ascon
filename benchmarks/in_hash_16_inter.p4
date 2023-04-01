#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

//the 320 bit IV is fixed after the first round of Perms 
//ee9398aadb67f03d 8bb21831c60f1002 b48a92db98d5da62 43189921b8f8e3e8 348fa5c9d525e140
const bit<64> IV = 0x80400c0600000000;
const bit<64> input_str=0x0001020304050607;//64 bit string input supported

header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}
header try_h {
    bit<64>   s0;
    bit<64>   s1;
}

struct my_ingress_headers_t {
    ethernet_h   ethernet;
    try_h        ascon;
}

struct my_ingress_metadata_t {
    bit<64> t0;
    bit<64> t1;
    bit<64> t2;
    bit<64> t3;
    bit<64> t4;


    bit<16> p0;
    bit<16> p1;
    bit<16> p2;
    bit<16> p3;
    bit<16> p4;
    bit<16> p5;
    bit<16> p6;
    bit<16> p7;
    bit<16> p8;
    bit<16> p9;

    bit<16> q0;
    bit<16> q1;
    bit<16> q2;
    bit<16> q3;
    bit<16> q4;
    bit<16> q5;
    bit<16> q6;
    bit<16> q7;
    bit<16> q8;
    bit<16> q9;
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
        // transition accept;
  
    }

    state parse_ascon{
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

    action diffusion_0_0 () {
        // ROR(t.x[0], 19)
        @in_hash { meta.p0= meta.t0[18:3]; 
            //63:48 p0 47:32 p1 31:16 p2 15:0  p3
        }
        
    }
    
    action diffusion_1_0 () {
        // ROR(t.x[0], 19)
        @in_hash { meta.p1= meta.t0[2:0] ++ meta.t0[63:51]; 
        }
        
    }
    
    action diffusion_2_0 () {
        // ROR(t.x[0], 19)
        @in_hash { meta.p2= meta.t0[50:35]; 
        }
        
    }

    action diffusion_3_0 () {
        // ROR(t.x[0], 19)
        @in_hash { meta.p3= meta.t0[34:19]; 
        }
        
    }

    action diffusion_4_0 () {
        // ROR(t.x[0], 28);
        @in_hash { meta.q0 = meta.t0[27:12]; }
    }
    action diffusion_5_0 () {
        // ROR(t.x[0], 28);
        @in_hash { meta.q1 = meta.t0[11:0]++meta.t0[63:60]; }
        // ROR(t.x[1], 39);
    }

    action diffusion_6_0 () {
        // ROR(t.x[0], 28);
        @in_hash { meta.q2 = meta.t0[59:44]; }
        // ROR(t.x[1], 39);
    }

    action diffusion_7_0 () {
        // ROR(t.x[0], 28);
        @in_hash { meta.q3 = meta.t0[43:28]; }
        // ROR(t.x[1], 39);
    }


    action diffusion_8_0() {
        // s->x[0] = t.x[0] ^ ROR(t.x[0], 19) ^ ROR(t.x[0], 28);
        meta.p0 = meta.p0 ^ meta.q0; 
    }

    action diffusion_9_0() {
        // s->x[0] = t.x[0] ^ ROR(t.x[0], 19) ^ ROR(t.x[0], 28);
        meta.p1 = meta.p1 ^ meta.q1; 
    }

    action diffusion_10_0() {
        // s->x[0] = t.x[0] ^ ROR(t.x[0], 19) ^ ROR(t.x[0], 28);
        meta.p2 = meta.p2 ^ meta.q2; 
    }

    action diffusion_11_0() {
        // s->x[0] = t.x[0] ^ ROR(t.x[0], 19) ^ ROR(t.x[0], 28);
        meta.p3 = meta.p3 ^ meta.q3; 
    }

    action diffusion_12_0() {
        // s->x[0] = t.x[0] ^ ROR(t.x[0], 19) ^ ROR(t.x[0], 28);
        hdr.ascon.s0[63:48] = meta.t0[63:48] ^ meta.p0; 

    }
    action diffusion_13_0() {
        // s->x[0] = t.x[0] ^ ROR(t.x[0], 19) ^ ROR(t.x[0], 28);
        hdr.ascon.s0[47:32] = meta.t0[47:32] ^ meta.p1; 
    }

    action diffusion_14_0() {
        // s->x[0] = t.x[0] ^ ROR(t.x[0], 19) ^ ROR(t.x[0], 28);
        hdr.ascon.s0[31:16] = meta.t0[31:16] ^ meta.p2; 

    }

    action diffusion_15_0() {
        // s->x[0] = t.x[0] ^ ROR(t.x[0], 19) ^ ROR(t.x[0], 28);
        hdr.ascon.s0[15:0] = meta.t0[15:0] ^ meta.p3; 

    }

    apply {
        // for hdr.s0
        // @in_hash { meta.p1= meta.t0[18:0] ++ meta.t0[63:51];  }
        // @in_hash { meta.p2 = meta.t0[50:19]; }
        // meta.q1 = meta.t0[27:0] ++ meta.t0[63:60]; 
        // @in_hash { meta.q2 = meta.t0[59:28]; }
        // meta.p1 = meta.p1 ^ meta.q1;
        // meta.p2 = meta.p2 ^ meta.q2;
        // hdr.ascon.s0[63:32] = meta.t0[63:32] ^ meta.p1;
        // hdr.ascon.s0[31:0] = meta.t0[31:0] ^ meta.p2;
        diffusion_0_0();
        diffusion_1_0();
        diffusion_2_0();
        diffusion_3_0();
        diffusion_4_0();
        diffusion_5_0();
        diffusion_6_0();
        diffusion_7_0();
        diffusion_8_0();
        diffusion_9_0();
        diffusion_10_0();
        diffusion_11_0();
        diffusion_12_0();
        diffusion_13_0();
        diffusion_14_0();
        diffusion_15_0();

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
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ascon);
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
