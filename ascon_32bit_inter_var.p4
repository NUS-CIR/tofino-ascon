#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

//the 320 bit IV is fixed after the first round of Perms 
//ee9398aadb67f03d 8bb21831c60f1002 b48a92db98d5da62 43189921b8f8e3e8 348fa5c9d525e140
const bit<320> IV = 0xee9398aadb67f03d8bb21831c60f1002b48a92db98d5da6243189921b8f8e3e8348fa5c9d525e140;

const bit<64> input_str=0x0001020304050607;

//using custom ether_type for checking b/w a normal and a recirc packet
typedef bit<16> ether_type_t;
const bit<16> ETHERTYPE_TPID = 0x8100;
const bit<16> ETHERTYPE_NORM = 0x8120;
const bit<16> ETHERTYPE_RECIR = 0x8133;
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
    bit<16>   dest_port;
    bit<8>    curr_round; 
}

// header ascon_meta_h{
//     bit<16>   dest_port;
//     bit<8>    curr_round; 
// }

struct my_ingress_headers_t {
    ethernet_h   ethernet;
    ascon_h      ascon;
    // ascon_meta_h ascon_meta;
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

    bit<32> p0;
    bit<32> p1;
    bit<32> p2;
    bit<32> p3;
    bit<32> p4;
    bit<32> p5;
    bit<32> p6;
    bit<32> p7;
    bit<32> p8;
    bit<32> p9;

    bit<32> q0;
    bit<32> q1;
    bit<32> q2;
    bit<32> q3;
    bit<32> q4;
    bit<32> q5;
    bit<32> q6;
    bit<32> q7;
    bit<32> q8;
    bit<32> q9;
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
        // transition select(hdr.ethernet.ether_type){
        //     ETHERTYPE_NORM:parse_ascon;
        //     ETHERTYPE_RECIR:parse_ascon_meta;
        //     default:accept;
        // }
    }

    state parse_ascon {
        pkt.extract(hdr.ascon);
        transition accept;
    }
    
    // state parse_ascon_meta {
    //     pkt.extract(hdr.ascon);
    //     pkt.extract(hdr.ascon_meta);
    //     transition accept;
    // }
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
    Hash<bit<64>>(HashAlgorithm_t.IDENTITY) copy0;// should be 256 if making use of Identity default hashing

    Register<bit<8>,bit<8>>(1,0x0) reg;

    RegisterAction<bit<8>, bit<8>, bit<8>>(reg)
        leave_data = {
            void apply(inout bit<8> register_data) { 
                register_data = register_data+1;
            }
        };

    action ascon_init(){
        hdr.ascon.s0= input_str ^ 0xee9398aadb67f03d;
        hdr.ascon.s1= 0x8bb21831c60f1002;   
        hdr.ascon.s2= 0xb48a92db98d5da62;
        hdr.ascon.s3= 0x43189921b8f8e3e8;
        hdr.ascon.s4= 0x348fa5c9d525e140;
    }
    action first_pass(){
		//first pass init

		hdr.ascon.curr_round =0x0;
        ascon_init();

        // hdr.ascon_meta.setValid();
		// routing_decision();
	}

    action addition(bit<64> const_i) {
        hdr.ascon.s2 = hdr.ascon.s2 ^ const_i;
    }

    action substitution() {
        hdr.ascon.s0 = hdr.ascon.s0 ^ hdr.ascon.s4;
        hdr.ascon.s4 = hdr.ascon.s4 ^ hdr.ascon.s3;
      //  hdr.ascon.s2 = hdr.ascon.s2 ^ const_i;              //TODO:depends on implementation
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


    action diffusion_0_0 () {
        // ROR(t.x[0], 19)
        @in_hash { meta.p0= meta.t0[18:0] ++ meta.t0[63:51];  }
    }
    
    action diffusion_1_0 () {
        // ROR(t.x[0], 19)
        @in_hash { meta.p1 = meta.t0[50:19]; }
        // ROR(t.x[1], 61) 
    }

    action diffusion_2_0 () {
        // ROR(t.x[0], 28);
        @in_hash { meta.q0 = meta.u0[27:0] ++ meta.u0[63:60]; }
        // ROR(t.x[1], 39);
    }
    action diffusion_3_0 () {
        // ROR(t.x[0], 28);
        @in_hash { meta.q1 = meta.u0[59:28]; }
        // ROR(t.x[1], 39);
    }

    action diffusion_4_0() {
        // s->x[0] = t.x[0] ^ ROR(t.x[0], 19) ^ ROR(t.x[0], 28);
        @in_hash { meta.p0 = meta.p0 ^ meta.q0; } 
    }

    action diffusion_5_0() {
        // s->x[0] = t.x[0] ^ ROR(t.x[0], 19) ^ ROR(t.x[0], 28);
        @in_hash { meta.p1 = meta.p1 ^ meta.q1; } 
    }

    action diffusion_6_0() {
        // s->x[0] = t.x[0] ^ ROR(t.x[0], 19) ^ ROR(t.x[0], 28);
        @in_hash { hdr.ascon.s0[63:32] = meta.t0[63:32] ^ meta.p0; } 

    }

    action diffusion_7_0() {
        // s->x[0] = t.x[0] ^ ROR(t.x[0], 19) ^ ROR(t.x[0], 28);
        @in_hash { hdr.ascon.s0[31:0] = meta.t0[31:0] ^ meta.p1; } 

    }


// for the second diffusion layer
    action diffusion_0_1 () {
        @in_hash { meta.p2 = meta.t1[60:29];        }
        // ROR(t.x[1], 61) 
    }
    
    action diffusion_1_1 () {
        @in_hash { meta.p3 = meta.t1[28:0]++ meta.t1[63:61]; }
        // ROR(t.x[1], 61) 
    }

    action diffusion_2_1 () {
        @in_hash { meta.q2 = meta.u1[38:7]; }
        // ROR(t.x[1], 39);
    }
    action diffusion_3_1 () {
        @in_hash { meta.q3 = meta.u1[6:0]++ meta.u1[63:39]; }
        // ROR(t.x[1], 39);
    }

    action diffusion_4_1() {
        @in_hash { meta.p2 = meta.p2 ^ meta.q2; } 
        // s->x[1] = t.x[1] ^ ROR(t.x[1], 61) ^ ROR(t.x[1], 39);
    }

    action diffusion_5_1() {
        @in_hash { meta.p3 = meta.p3 ^ meta.q3; } 
        // s->x[1] = t.x[1] ^ ROR(t.x[1], 61) ^ ROR(t.x[1], 39);
    }

    action diffusion_6_1() {
        @in_hash { hdr.ascon.s1[63:32] = meta.t1[63:32] ^ meta.p2; } 
        // s->x[1] = t.x[1] ^ ROR(t.x[1], 61) ^ ROR(t.x[1], 39);
    }

    action diffusion_7_1() {
        @in_hash { hdr.ascon.s1[31:0] = meta.t1[31:0] ^ meta.p3; } 
        // s->x[1] = t.x[1] ^ ROR(t.x[1], 61) ^ ROR(t.x[1], 39);
    }


// for the third diffusion layer
    action diffusion_0_2 () {
        @in_hash { meta.p4 = meta.t2[0:0]++meta.t2[63:33];  }
        // ROR(t.x[2], 1)
    }
    
    action diffusion_1_2 () {
        @in_hash { meta.p5 = meta.t2[32:1]; }
        // ROR(t.x[2], 1)
    }

    action diffusion_2_2 () {
        @in_hash { meta.q4 = meta.u2[5:0]++meta.u2[63:38]; }
        // ROR(t.x[2], 6)
    }
    action diffusion_3_2 () {
        @in_hash { meta.q5 = meta.u2[37:6]; }
        // ROR(t.x[2], 6)
    }

    action diffusion_4_2() {
        @in_hash { meta.p4 = meta.p4 ^ meta.q4; } 
        //   s->x[2] = t.x[2] ^ ROR(t.x[2], 1) ^ ROR(t.x[2], 6);
    }

    action diffusion_5_2() {
        @in_hash { meta.p5 = meta.p5 ^ meta.q5; } 
        //   s->x[2] = t.x[2] ^ ROR(t.x[2], 1) ^ ROR(t.x[2], 6);
    }

    action diffusion_6_2() {
        @in_hash { hdr.ascon.s2[63:32] = meta.t2[63:32] ^ meta.p4; } 
        //   s->x[2] = t.x[2] ^ ROR(t.x[2], 1) ^ ROR(t.x[2], 6);
    }

    action diffusion_7_2() {
        @in_hash { hdr.ascon.s2[31:0] = meta.t2[31:0] ^ meta.p5; } 
        //   s->x[2] = t.x[2] ^ ROR(t.x[2], 1) ^ ROR(t.x[2], 6);
    }


// for the fourth diffusion layer
    action diffusion_0_3 () {
        @in_hash { meta.p6= meta.t3[9:0]++meta.t3[63:42];  }
        // ROR(t.x[3], 10)
    }
    
    action diffusion_1_3 () {
        @in_hash { meta.p7 = meta.t3[41:10]; }
        // ROR(t.x[3], 10)
    }

    action diffusion_2_3 () {
        @in_hash { meta.q6 = meta.u3[16:0]++meta.u3[63:49]; }
        // ROR(t.x[3], 17)
    }
    action diffusion_3_3 () {
        @in_hash { meta.q7 = meta.u3[48:17]; }
        // ROR(t.x[3], 17)
    }

    action diffusion_4_3() {
        @in_hash { meta.p6 = meta.p6 ^ meta.q6; } 
        //   s->x[3] = t.x[3] ^ ROR(t.x[3], 10) ^ ROR(t.x[3], 17);
    }

    action diffusion_5_3() {
        @in_hash { meta.p7 = meta.p7 ^ meta.q7; } 
        //   s->x[3] = t.x[3] ^ ROR(t.x[3], 10) ^ ROR(t.x[3], 17);
    }

    action diffusion_6_3() {
        @in_hash { hdr.ascon.s3[63:32] = meta.t3[63:32]^ meta.p6; } 
        //   s->x[3] = t.x[3] ^ ROR(t.x[3], 10) ^ ROR(t.x[3], 17);
    }

    action diffusion_7_3() {
        @in_hash { hdr.ascon.s3[31:0] = meta.t3[31:0]^ meta.p7; } 
        //   s->x[3] = t.x[3] ^ ROR(t.x[3], 10) ^ ROR(t.x[3], 17);
    }


// for the final diffusion layer
    action diffusion_0_4 () {
        @in_hash { meta.p8 = meta.t4[6:0]++meta.t4[63:39];  }
        // ROR(t.x[4], 7)
    }
    
    action diffusion_1_4 () {
        @in_hash { meta.p9 = meta.t4[38:7]; }
        // ROR(t.x[4], 7)
    }

    action diffusion_2_4 () {
        @in_hash { meta.q8 = meta.u4[40:9]; }
        // ROR(t.x[4], 41)
    }
    action diffusion_3_4 () {
        @in_hash { meta.q9 = meta.u4[8:0]++ meta.u4[63:41]; }
        // ROR(t.x[4], 41)
    }

    action diffusion_4_4() {
        @in_hash { meta.p8 = meta.p8 ^ meta.q8; } 
        //   s->x[4] = t.x[4] ^ ROR(t.x[4], 7) ^ ROR(t.x[4], 41);
    }

    action diffusion_5_4() {
        @in_hash { meta.p9 = meta.p9 ^ meta.q9; } 
        //   s->x[4] = t.x[4] ^ ROR(t.x[4], 7) ^ ROR(t.x[4], 41);
    }

    action diffusion_6_4() {
        @in_hash { hdr.ascon.s4[63:32] = meta.t4[63:32]^ meta.p8; } 
        //   s->x[4] = t.x[4] ^ ROR(t.x[4], 7) ^ ROR(t.x[4], 41);
    }

    action diffusion_7_4() {
        @in_hash { hdr.ascon.s4[31:0] = meta.t4[31:0] ^ meta.p9; } 
        //   s->x[4] = t.x[4] ^ ROR(t.x[4], 7) ^ ROR(t.x[4], 41);
    }

    action do_recirculate(){
        hdr.ascon.curr_round=hdr.ascon.curr_round +0x1;
        ig_tm_md.ucast_egress_port[8:7] = ig_intr_md.ingress_port[8:7];
        ig_tm_md.ucast_egress_port[6:0] = 0x6;
        hdr.ethernet.ether_type=ETHERTYPE_RECIR;
    }
    

    table add_const{
        key={
            hdr.ascon.curr_round:exact;
        }
        actions= {
            addition(); 
            @defaultonly NoAction;
        }
        size=32;
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
            12:addition(0xf0);
            13:addition(0xe1);
            14:addition(0xd2);         
            15:addition(0xc3);
            16:addition(0xb4);
            17:addition(0xa5);
            18:addition(0x96);
            19:addition(0x87);
            20:addition(0x78);
            21:addition(0x69);
            22:addition(0x5a);
            23:addition(0x4b);
        }
    } 


    apply {
        //pkt count register
        leave_data.execute(0x0);

        //Initialization for the first packet
        if(hdr.ethernet.ether_type==ETHERTYPE_NORM){
            first_pass();
        }

        if(hdr.ascon.curr_round==0xc){
            hdr.ascon.s0[63:56]=hdr.ascon.s0[63:56]^0x80;
        }
        
        // check for final round(24th round)
        if(hdr.ascon.curr_round==0x18){
            // hdr.ethernet.ether_type=ETHERTYPE_NORM;
            // ig_tm_md.ucast_egress_port =(bit<9>)hdr.ascon.dest_port;

            ig_tm_md.ucast_egress_port =(bit<9>)0x9;
            //reg.write(0,0xb);
        }
        else{
            // /* addition of round constant */
            add_const.apply();

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
            
            // /* linear diffusion layer */
            // s->x[0] = t.x[0] ^ ROR(t.x[0], 19) ^ ROR(t.x[0], 28);
            // s->x[1] = t.x[1] ^ ROR(t.x[1], 61) ^ ROR(t.x[1], 39);
            // s->x[2] = t.x[2] ^ ROR(t.x[2], 1) ^ ROR(t.x[2], 6);
            // s->x[3] = t.x[3] ^ ROR(t.x[3], 10) ^ ROR(t.x[3], 17);
            // s->x[4] = t.x[4] ^ ROR(t.x[4], 7) ^ ROR(t.x[4], 41);

            // for hdr.s0
            diffusion_0_0();
            diffusion_1_0();
            diffusion_2_0();
            diffusion_3_0();
            diffusion_4_0();
            diffusion_5_0();
            diffusion_6_0();
            diffusion_7_0();

            // for hdr.s1
            diffusion_0_1();
            diffusion_1_1();
            diffusion_2_1();
            diffusion_3_1();
            diffusion_4_1();
            diffusion_5_1();
            diffusion_6_1();
            diffusion_7_1();

            // for hdr.s2
            diffusion_0_2();
            diffusion_1_2();
            diffusion_2_2();
            diffusion_3_2();
            diffusion_4_2();
            diffusion_5_2();
            diffusion_6_2();
            diffusion_7_2();

            // for hdr.s3
            diffusion_0_3(); 
            diffusion_1_3();
            diffusion_2_3();
            diffusion_3_3();
            diffusion_4_3();
            diffusion_5_3();
            diffusion_6_3();
            diffusion_7_3();        

            // for hdr.s4
            diffusion_0_4();
            diffusion_1_4();
            diffusion_2_4();
            diffusion_3_4();
            diffusion_4_4();
            diffusion_5_4();
            diffusion_6_4();
            diffusion_7_4();

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
        pkt.emit(hdr.ascon);
        // pkt.emit(hdr.ascon_meta);
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
