
{% if False %}
	#error This is a code template, not a P4 program. Please use the accompanying code generator. 
{% endif %}

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

// define the port resp. for Tf1 and Tf2
{%if model == 1%}
    #define eg_port 9; // for h/w 0x4 
    #define recir_port 68;// for h/w loopbacked port
{%else%}
    #define eg_port 9; 
    #define recir_port 6;// for h/w loopbacked port

//the 320 bit IV is fixed after the first round of Perms 
//ee9398aadb67f03d 8bb21831c60f1002 b48a92db98d5da62 43189921b8f8e3e8 348fa5c9d525e140
const bit<32> AD = 0x00010203;
const bit<64> IV = 0x80400c0600000000;

// const bit<64> input_str=0x0001020304050607;//64 bit string input supported
// const bit<128> input_str_2=0x000102030405060708090A0B0C0D0E0F;

//Keys and nonces
#define K_0 0x0001020304050607;
#define K_1 0x08090A0B0C0D0E0F;
#define N_0 0x0001020304050607;
#define N_1 0x08090A0B0C0D0E0F;

// diff ether_type for a different stage of ASCON
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

// ASCON state and round number
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

        transition select(hdr.ethernet.ether_type){
            ETHERTYPE_FIRST:parse_length;
            ETHERTYPE_NORM:parse_ascon;
            ETHERTYPE_RECIR:parse_ascon_out;
            default:accept;
        }
    }

    state parse_length {
        pkt.extract(hdr.ascon_in_len);
        transition parse_payload_64;    

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
    // recirculate: increases round num and assigns to recirc port(Port 6)
    action do_recirculate(){
        hdr.ascon.curr_round=hdr.ascon.curr_round +0x1;
        ig_tm_md.ucast_egress_port[8:7] = ig_intr_md.ingress_port[8:7];
        ig_tm_md.ucast_egress_port[6:0] = recir_port;
    }

    // includes the ASCON actions and tables
    #include "ascon_actions.p4"

    apply {

        //Initialization for the first packet
        if(hdr.ethernet.ether_type==ETHERTYPE_FIRST){
            ascon_init();
        }

        //after 12 rounds for initialization
        if(hdr.ascon.curr_round==0xC){
            abs_ad();
        }

        //after 18 rounds(the AD is absorbed)
        if(hdr.ascon.curr_round==0x12){
            abs_input_1();
            abs_input_2();
        }

        //check for 24th round after which the padding stage occurs     
        /* absorb final plaintext block */
        //   Currently working for only 8 byte string so can simply XOR with 0x80
        if(hdr.ascon.curr_round==0x18){
            abs_final();
        }

        // check for final round(36th round) after tag finalization
        if(hdr.ascon.curr_round==0x24){
            hdr.ascon.s3=hdr.ascon.s3 ^ K_0; 
            hdr.ascon.s4 =hdr.ascon.s4 ^ K_1;
            hdr.ascon_tag.tag0=hdr.ascon.s3;
            hdr.ascon_tag.tag1=hdr.ascon.s4;
            hdr.ascon_tag.setValid();
            ig_tm_md.ucast_egress_port[8:7] = ig_intr_md.ingress_port[8:7];
            ig_tm_md.ucast_egress_port[6:0] = eg_port;
        }
        else{
            #include  "ascon_round.p4"
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
