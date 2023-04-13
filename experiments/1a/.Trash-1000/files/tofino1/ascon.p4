#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

// #include "loops_macro.h"

#define eg_port 0x9; //fow h/w needs to be 0x4 
#define recir_port 68;//for h/w needs to be a loopbacked port
//new header for encrypton including length of msg to be encrypted

//the 320 bit IV is fixed after the first round of Perms 
//ee9398aadb67f03d 8bb21831c60f1002 b48a92db98d5da62 43189921b8f8e3e8 348fa5c9d525e140
const bit<32> AD = 0x00010203;
const bit<64> IV = 0x80400c0600000000;
// const bit<64> input_str=0x0001020304050607;//64 bit string input supported
// const bit<128> input_str_2=0x000102030405060708090A0B0C0D0E0F;

#define K_0 0x0001020304050607;
#define K_1 0x08090A0B0C0D0E0F;
#define N_0 0x0001020304050607;
#define N_1 0x08090A0B0C0D0E0F;


typedef bit<16> ether_type_t;
const bit<16> ETHERTYPE_NORM = 0x8120;
const bit<16> ETHERTYPE_FIRST = 0x8122;
const bit<16> ETHERTYPE_RECIR = 0x8133; //using custom ether_type for checking b/w a normal and a recirc packet
const bit<16> ETHERTYPE_PARSE = 0x8134;
const bit<16> ETHERTYPE_IPV4 = 0x0800;

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
    bit<8>    curr_round;
}

header ascon_out_h{
    bit<64>   o0;
    bit<64>   o1;
}

header ascon_tag_h{
    bit<64> tag0;
    bit<64> tag1;
}

header ascon_in_len_h {//will have to be just before the payload
    bit<8> wrd_len;
    // bit<8> ad_len;
} 

header payload_64_h{
    bit<64> input_str;
}

struct my_ingress_headers_t {
    ethernet_h   ethernet;
    ascon_h      ascon;
    ascon_out_h  ascon_out;
    ascon_tag_h  ascon_tag;    
    ascon_in_len_h   ascon_in_len;
    payload_64_h payload_64; 
}

struct my_ingress_metadata_t {
    bit<64> t0;
    bit<64> t1;
    bit<64> t2;
    bit<64> t3;
    bit<64> t4;
    //these will be used as temp values for intermediate computation
    bit<64> p;   
    bit<64> q;
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
        // pkt.extract(hdr.ascon);
        // transition parse_ascon;
        
        transition select(hdr.ethernet.ether_type){
            ETHERTYPE_FIRST:parse_length;
            // ETHERTYPE_PARSE:parse_payload;
            ETHERTYPE_NORM:parse_ascon;
            ETHERTYPE_RECIR:parse_ascon_out;
            default:accept;
        }
    }
    // not emmiting it in the deparser
    state parse_length {
        pkt.extract(hdr.ascon_in_len);
        transition parse_payload_64;
        //transition select(hdr.ascon_in_len.wrd_len){
            
            // 0x1: parse_payload_64;
            // 0x2: parse_payload_128;
            // default:accept;
        //}

    }

    state parse_payload_64 {
        pkt.extract(hdr.payload_64);
        transition accept;
    }

    state parse_ascon {
        pkt.extract(hdr.ascon_in_len);
        pkt.extract(hdr.payload_64);
        pkt.extract(hdr.ascon);
        transition accept;
    }
    
    state parse_ascon_out {
        pkt.extract(hdr.ascon_in_len);
        pkt.extract(hdr.payload_64);
        pkt.extract(hdr.ascon);
        pkt.extract(hdr.ascon_out);
        pkt.extract(hdr.ascon_tag);
        
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
     // recirculate:increases round no., changes ether_type and assigns to recirc port(Port 6)
    action do_recirculate(){
        hdr.ascon.curr_round=hdr.ascon.curr_round +0x1;
        ig_tm_md.ucast_egress_port[8:7] = ig_intr_md.ingress_port[8:7];
        ig_tm_md.ucast_egress_port[6:0] = recir_port;
        // hdr.ethernet.ether_type=ETHERTYPE_RECIR;
    }

    #include "ascon_actions.p4"

    apply {
        // saving the input string
        // leave_data.execute();

        //Initialization for the first packet
        if(hdr.ethernet.ether_type==ETHERTYPE_FIRST){
            ascon_init();
        }
        //after 12 rounds for initialization
        if(hdr.ascon.curr_round==0xC){
            abs_ad();
        }
        //16th round, next time we want to parse 
        // if(hdr.ascon.curr_round==0x10){
        //     hdr.ethernet.ether_type= ETHERTYPE_PARSE;
        // }
        //after 18 rounds(the AD is absorbed)
        if(hdr.ascon.curr_round==0x12){
            // hdr.ascon_out.o0=hdr.ascon.s0;
            // hdr.ascon_out.o1=hdr.ascon.s0^0x0;
            abs_input_1();
            abs_input_2();
        }
        //check for 24th round after which the padding stage occurs     
        /* absorb final plaintext block */
        //   s.x[0] ^= LOADBYTES(in, len);
        //   s.x[0] ^= PAD(len);
        //   Currently working for only 8 byte string so can simply XOR with 0x80
        if(hdr.ascon.curr_round==0x18){
            abs_final();
        }

        // check for final round(36th round) after tag finalization
        if(hdr.ascon.curr_round==0x24){
            // hdr.ethernet.ether_type=ETHERTYPE_NORM;
            // ig_tm_md.ucast_egress_port =(bit<9>)hdr.ascon.dest_port;
            // hdr.ascon.s0=hdr.ascon_out.o0;
            //could have had a store here
            hdr.ascon.s3=hdr.ascon.s3 ^ K_0; 
            hdr.ascon.s4 =hdr.ascon.s4 ^ K_1;
            hdr.ascon_tag.tag0=hdr.ascon.s3;
            hdr.ascon_tag.tag1=hdr.ascon.s4;

            ig_tm_md.ucast_egress_port = eg_port;
            //reg.write(0,0xb);
        }
        else{
            #include  "ascon_round1.p4"
            // hdr.ascon.curr_round=hdr.ascon.curr_round +0x1;
            // #include  "ascon_round2.p4"
            do_recirculate();
        }
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
        pkt.emit(hdr.ascon_in_len);
        pkt.emit(hdr.payload_64);
        pkt.emit(hdr.ascon);
        pkt.emit(hdr.ascon_out);
        pkt.emit(hdr.ascon_tag);  
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
    ethernet_h   ethernet;
    ascon_h      ascon;
    ascon_out_h ascon_out;
    ascon_tag_h  ascon_tag;  
    ascon_in_len_h ascon_in_len;
    payload_64_h payload_64;
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
    bit<64> t0;
    bit<64> t1;
    bit<64> t2;
    bit<64> t3;
    bit<64> t4;

    bit<64> p;   
    bit<64> q;
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
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        // transition parse_ascon;
        
        transition select(hdr.ethernet.ether_type){
            ETHERTYPE_NORM:parse_ascon;
            ETHERTYPE_RECIR:parse_ascon_out;
            default:accept;
        }
    }

    state parse_ascon {
        pkt.extract(hdr.ascon_in_len);
        pkt.extract(hdr.payload_64);
        pkt.extract(hdr.ascon);
        transition accept;
    }
    
    state parse_ascon_out {
        pkt.extract(hdr.ascon_in_len);
        pkt.extract(hdr.payload_64);
        pkt.extract(hdr.ascon);
        pkt.extract(hdr.ascon_out);
        pkt.extract(hdr.ascon_tag);
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
    #include "ascon_actions.p4"
    apply {    
        if(hdr.ascon.curr_round!=0x24){
            #include "ascon_round1.p4"
            hdr.ascon.curr_round=hdr.ascon.curr_round +0x1;
            // #include "ascon_round2.p4"
            // hdr.ascon.curr_round=hdr.ascon.curr_round +0x1;
        }
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
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ascon_in_len);
        pkt.emit(hdr.payload_64);
        pkt.emit(hdr.ascon);
        pkt.emit(hdr.ascon_out);
        pkt.emit(hdr.ascon_tag);
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
