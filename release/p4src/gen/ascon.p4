#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

// define the port resp. for Tf1 and Tf2
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
    // Output ciph_text
    bit<64>   o0;
    bit<64>   o1;
    bit<64>   o2;
    bit<64>   o3;
}

header ascon_tag_h{
    bit<64> tag0;
    bit<64> tag1;
}

header payload_h{
    // Payload header
    bit<128> input_str; 
    bit<128> input_str_2;
    
}

struct my_ingress_headers_t {
    ethernet_h   ethernet;
    ascon_h      ascon;
    payload_h payload; 
    ascon_out_h  ascon_out;
    ascon_tag_h  ascon_tag;    
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
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type){
            // no processing needed for ETHERTYPE_FIRST
            // ETHERTYPE_FIRST:parse_length;
            ETHERTYPE_NORM:parse_ascon;
            ETHERTYPE_PARSE:parse_payload;
            ETHERTYPE_RECIR:parse_ascon_out;
            default:accept;
        }
    }

    state parse_ascon {
        pkt.extract(hdr.ascon);
        transition accept;
    }

    state parse_payload {
        pkt.extract(hdr.ascon);
        pkt.extract(hdr.payload);
        transition accept;
    }
    
    state parse_ascon_out {
        pkt.extract(hdr.ascon);
        pkt.extract(hdr.payload);
        pkt.extract(hdr.ascon_out); // tags need to be emitted at the end      
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
    // includes the ASCON actions and tables
    #include "ascon_actions.p4"

    action abs_input_1(){
        // domain seperation
        hdr.ascon.s4= hdr.ascon.s4 ^ 0x1;
        hdr.ascon.s0= hdr.ascon.s0 ^ hdr.payload.input_str[127:64];
    }

    action abs_input_3(){
        hdr.ascon.s0= hdr.ascon.s0 ^ hdr.payload.input_str[63:0];
    }
    action abs_input_4(){
        hdr.ascon_out.o1= hdr.ascon.s0;
    }
    action abs_input_5(){
        hdr.ascon.s0= hdr.ascon.s0 ^ hdr.payload.input_str_2[127:64];
    }
    action abs_input_6(){
        hdr.ascon_out.o2= hdr.ascon.s0;
    }
    action abs_input_7(){
        hdr.ascon.s0= hdr.ascon.s0^ hdr.payload.input_str_2[63:0];
    }
    action abs_input_8(){
        hdr.ascon_out.o3=hdr.ascon.s0;
    }

    // recirculate: increases round num and assigns to recirc port
    action do_recirculate(){
        // hdr.ascon.curr_round=hdr.ascon.curr_round + 0x1;
        ig_tm_md.ucast_egress_port[8:7] = ig_intr_md.ingress_port[8:7];
        ig_tm_md.ucast_egress_port[6:0] = recir_port;
    }
    table add_const{
        key={
            hdr.ascon.curr_round:exact;
        }
        actions= {
            addition(); 
            @defaultonly NoAction;
        }
        size=64;
        const entries ={

            0:addition(0xf0);
            1:addition(0xe1);
            2:addition(0xd2);
            3:addition(0xc3);
            4:addition(0xb4);
            5:addition(0xa5);
            6:addition(0x96);
            7:addition(0x87);
            8:addition(0x78);
            9:addition(0x69);
            10:addition(0x5a);
            11:addition(0x4b);

            12:addition(0x96);
            13:addition(0x87);
            14:addition(0x78);
            15:addition(0x69);
            16:addition(0x5a);
            17:addition(0x4b);

            18:addition(0x96);
            19:addition(0x87);
            20:addition(0x78);
            21:addition(0x69);
            22:addition(0x5a);
            23:addition(0x4b);
            24:addition(0x96);
            25:addition(0x87);
            26:addition(0x78);
            27:addition(0x69);
            28:addition(0x5a);
            29:addition(0x4b);
            30:addition(0x96);
            31:addition(0x87);
            32:addition(0x78);
            33:addition(0x69);
            34:addition(0x5a);
            35:addition(0x4b);
            36:addition(0x96);
            37:addition(0x87);
            38:addition(0x78);
            39:addition(0x69);
            40:addition(0x5a);
            41:addition(0x4b);
         

            42:addition(0xf0);
            43:addition(0xe1);
            44:addition(0xd2);
            45:addition(0xc3);
            46:addition(0xb4);
            47:addition(0xa5);
            48:addition(0x96);
            49:addition(0x87);
            50:addition(0x78);
            51:addition(0x69);
            52:addition(0x5a);
            53:addition(0x4b);
        
        }
    }


    apply {

        // initialization for the first packet
        if(hdr.ethernet.ether_type == ETHERTYPE_FIRST){
            ascon_init();
        }

        // after 18 rounds(the AD is absorbed)
        if(hdr.ascon.curr_round == 18){
            abs_input_1();
            abs_input_2();
        }

        // absorb final plaintext block, currently working for only multiple of 8 bytes PT so can simply XOR with 0x80
    
        if(hdr.ascon.curr_round == 42){
            abs_final();
        }

        #include  "ascon_round1.p4"
        hdr.ascon.curr_round=hdr.ascon.curr_round +0x1;
        do_recirculate();
        if(hdr.ascon.curr_round == 53) {   
            ig_tm_md.ucast_egress_port[8:7] = ig_intr_md.ingress_port[8:7];
            ig_tm_md.ucast_egress_port[6:0] = eg_port;
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
        pkt.emit(hdr.ascon);
        pkt.emit(hdr.payload);
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
    payload_h payload;
    ascon_out_h ascon_out;
    ascon_tag_h  ascon_tag;  
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
    state start {
        pkt.extract(eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);  
        transition select(hdr.ethernet.ether_type){
            ETHERTYPE_NORM:parse_ascon;
            ETHERTYPE_PARSE:parse_payload;
            ETHERTYPE_RECIR:parse_ascon_out;
            default:accept;
        }
    }

    state parse_ascon {
        pkt.extract(hdr.ascon);
        transition accept;
    }

    state parse_payload {
        pkt.extract(hdr.ascon);
        pkt.extract(hdr.payload);
        transition accept;
    }
    
    state parse_ascon_out {
        pkt.extract(hdr.ascon);
        pkt.extract(hdr.payload);
        pkt.extract(hdr.ascon_out);
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
    
    // includes the ASCON actions and tables
    #include "ascon_actions.p4"

    action abs_input_1(){
        // domain seperation
        hdr.ascon.s4= hdr.ascon.s4 ^ 0x1;
        hdr.ascon.s0= hdr.ascon.s0 ^ hdr.payload.input_str[127:64];
    }

    action abs_input_3(){
        hdr.ascon.s0= hdr.ascon.s0 ^ hdr.payload.input_str[63:0];
    }
    action abs_input_4(){
        hdr.ascon_out.o1= hdr.ascon.s0;
    }
    action abs_input_5(){
        hdr.ascon.s0= hdr.ascon.s0 ^ hdr.payload.input_str_2[127:64];
    }
    action abs_input_6(){
        hdr.ascon_out.o2= hdr.ascon.s0;
    }
    action abs_input_7(){
        hdr.ascon.s0= hdr.ascon.s0^ hdr.payload.input_str_2[63:0];
    }
    action abs_input_8(){
        hdr.ascon_out.o3=hdr.ascon.s0;
    }

    table add_const{
        key={
            hdr.ascon.curr_round:exact;
        }
        actions= {
            addition(); 
            @defaultonly NoAction;
        }
        size=64;
        const entries ={
            0:addition(0xf0);
            1:addition(0xe1);
            2:addition(0xd2);
            3:addition(0xc3);
            4:addition(0xb4);
            5:addition(0xa5);
            6:addition(0x96);
            7:addition(0x87);
            8:addition(0x78);
            9:addition(0x69);
            10:addition(0x5a);
            11:addition(0x4b);

            12:addition(0x96);
            13:addition(0x87);
            14:addition(0x78);
            15:addition(0x69);
            16:addition(0x5a);
            17:addition(0x4b);

            18:addition(0x96);
            19:addition(0x87);
            20:addition(0x78);
            21:addition(0x69);
            22:addition(0x5a);
            23:addition(0x4b);

            24:addition(0x96);
            25:addition(0x87);
            26:addition(0x78);
            27:addition(0x69);
            28:addition(0x5a);
            29:addition(0x4b);

            30:addition(0x96);
            31:addition(0x87);
            32:addition(0x78);
            33:addition(0x69);
            34:addition(0x5a);
            35:addition(0x4b);

            36:addition(0x96);
            37:addition(0x87);
            38:addition(0x78);
            39:addition(0x69);
            40:addition(0x5a);
            41:addition(0x4b);

         

            42:addition(0xf0);
            43:addition(0xe1);
            44:addition(0xd2);
            45:addition(0xc3);
            46:addition(0xb4);
            47:addition(0xa5);
            48:addition(0x96);
            49:addition(0x87);
            50:addition(0x78);
            51:addition(0x69);
            52:addition(0x5a);
            53:addition(0x4b);
        }
    }


    apply {

        // absorb final plaintext block, currently working for only multiple of 8 bytes PT so can simply XOR with 0x80


        #include  "ascon_round1.p4"
        hdr.ascon.curr_round=hdr.ascon.curr_round +0x1;
        if(hdr.ascon.curr_round == 54){   
            hdr.ascon.s3=hdr.ascon.s3 ^ K_0; 
            hdr.ascon.s4 =hdr.ascon.s4 ^ K_1;
            hdr.ascon_tag.tag0=hdr.ascon.s3;
            hdr.ascon_tag.tag1=hdr.ascon.s4;
            hdr.ascon_tag.setValid();
        }
  
        // after 12 rounds for initialization
        if(hdr.ascon.curr_round == 12){
            abs_ad();
        }
        if(hdr.ascon.curr_round == 24){
            abs_input_3();
            abs_input_4();
        }
        
        if(hdr.ascon.curr_round == 30){
            abs_input_5();
            abs_input_6();
        }
        if(hdr.ascon.curr_round == 36){
            abs_input_7();
            abs_input_8();
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
        pkt.emit(hdr.ascon);
        pkt.emit(hdr.payload);
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