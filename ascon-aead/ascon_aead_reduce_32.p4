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

#define K_0 0x0001020304050607;
#define K_1 0x08090A0B0C0D0E0F;
#define N_0 0x0001020304050607;
#define N_1 0x08090A0B0C0D0E0F;


typedef bit<16> ether_type_t;
const bit<16> ETHERTYPE_INIT = 0x8199;
const bit<16> ETHERTYPE_NORM = 0x8120;
const bit<16> ETHERTYPE_RECIR = 0x8133; //using custom ether_type for checking b/w a normal and a recirc packet
const bit<16> ETHERTYPE_RECIR0 = 0x8134;
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

header ascon_out_final_h{
    bit<64>   f0;
    bit<64>   f1;
    bit<64>   f2;
    bit<64>   f3;
}

struct my_ingress_headers_t {
    ethernet_h   ethernet;
    ascon_h      ascon;
    ascon_out_h ascon_out;
    ascon_out_final_h ascon_final;
}

struct my_ingress_metadata_t {
    bit<64> t0;
    bit<64> t1;
    bit<64> t2;
    bit<64> t3;
    bit<64> t4;

    // bit<64> p;   
    // bit<64> q;
    bit<32> p8;
    bit<32> p9;
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
        
        transition select(hdr.ethernet.ether_type){
            // ETHERTYPE_NORM:parse_ascon;
            ETHERTYPE_INIT:parse_ascon_out_0;
            // ETHERTYPE_RECIR0:parse_ascon_out_0;
            ETHERTYPE_RECIR:parse_ascon_final;
            default:parse_ascon;
        }
    }

    state parse_ascon {
        pkt.extract(hdr.ascon);
        pkt.extract(hdr.ascon_out);
        transition accept;
    }
    
    state parse_ascon_out_0 {
        pkt.extract(hdr.ascon);
        // pkt.extract(hdr.ascon_out);
        transition accept;
    }

    state parse_ascon_final {
        pkt.extract(hdr.ascon);
        // pkt.advance(328);
        pkt.extract(hdr.ascon_final);
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
    // Hash<bit<64>>(HashAlgorithm_t.IDENTITY) copy0;// should be 256 if making use of Identity default hashing

    Register<bit<8>,bit<8>>(1,0x0) reg;
    // for verifying the round counts in recirc
    RegisterAction<bit<8>, bit<8>, bit<8>>(reg)
        leave_data = {
            void apply(inout bit<8> register_data) { 
                register_data = register_data+1;
            }
        };
    //fixed initialization stage
    @name("init") action ascon_init(){
        //x0=bc830fbef3a1651b x1=487a66865036b909 x2=a031b0c5810c1cd6 x3=dd7ce72083702217 x4=9b17156ede557ce6
        // keeping till after the 2nd key xor + domain seperation into account
        hdr.ascon.s0= input_str ^ 0xbc830fbef3a1651b;
        hdr.ascon.s1= 0x487a66865036b909;   
        hdr.ascon.s2= 0xa031b0c5810c1cd6;
        hdr.ascon.s3= 0xdd7ce72083702217;
        hdr.ascon.s4= 0x9b17156ede557ce6;
        hdr.ascon_out.o0=hdr.ascon.s0;
        hdr.ascon_out.o1=0x0;
    }
    //first pass init
    @name("first")action first_pass(){
		hdr.ascon.curr_round =0x0;
        ascon_init();
        hdr.ascon_out.setValid();
        // hdr.ethernet.ether_type=ETHERTYPE_NORM;
		// routing_decision();
	}
    //constant addition at the start of round using a table
    @name("add")action addition(bit<64> const_i) {
        hdr.ascon.s2 = hdr.ascon.s2 ^ const_i;
    }

    @name("subst")action substitution() {
        hdr.ascon.s0 = hdr.ascon.s0 ^ hdr.ascon.s4;
        hdr.ascon.s4 = hdr.ascon.s4 ^ hdr.ascon.s3;
      //  hdr.ascon.s2 = hdr.ascon.s2 ^ const_i;              //TODO:depends on implementation
        hdr.ascon.s2 = hdr.ascon.s2 ^ hdr.ascon.s1;
    }

    @name("sb0")action start_sbox_0 () {
        meta.t0 = ~hdr.ascon.s1 & hdr.ascon.s2;
        meta.t1 = ~hdr.ascon.s2 & hdr.ascon.s3;
        meta.t2 = ~hdr.ascon.s3 & hdr.ascon.s4;
        meta.t3 = ~hdr.ascon.s4 & hdr.ascon.s0;
        meta.t4 = ~hdr.ascon.s0 & hdr.ascon.s1;
    }
    
    @name("sb1")action start_sbox_1 () {
        meta.t0 = hdr.ascon.s0 ^ meta.t0;
        meta.t1 = hdr.ascon.s1 ^ meta.t1;
        meta.t2 = hdr.ascon.s2 ^ meta.t2;
        meta.t3 = hdr.ascon.s3 ^ meta.t3;
        meta.t4 = hdr.ascon.s4 ^ meta.t4;
    }

    @name("end_sb")action end_sbox() {
        meta.t1 = meta.t1 ^ meta.t0;
        meta.t0 = meta.t0 ^ meta.t4;
        meta.t3 = meta.t3 ^ meta.t2;
        meta.t2 = ~meta.t2;
    }


    // recirculate:increases round no., changes ether_type and assigns to recirc port(Port 6)
    @name("recirc") action do_recirculate(){
        hdr.ascon.curr_round=hdr.ascon.curr_round +0x1;
        ig_tm_md.ucast_egress_port[8:7] = ig_intr_md.ingress_port[8:7];
        ig_tm_md.ucast_egress_port[6:0] = 0x6;
        // hdr.ethernet.ether_type=ETHERTYPE_RECIR;
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
            0:addition(0x96);
            1:addition(0x87);
            2:addition(0x78);
            3:addition(0x69);
            4:addition(0x5a);
            5:addition(0x4b);
            6:addition(0xf0);
            7:addition(0xe1);
            8:addition(0xd2);         
            9:addition(0xc3);
            10:addition(0xb4);
            11:addition(0xa5);
            12:addition(0x96);
            13:addition(0x87);
            14:addition(0x78);
            15:addition(0x69);
            16:addition(0x5a);
            17:addition(0x4b);
            18:addition(0xf0);
            19:addition(0xe1);
            20:addition(0xd2);         
           
        }
    } 


    apply {
        //pkt count register
        // leave_data.execute(0x0);

        //Initialization for the first packet
        if(hdr.ascon.curr_round==0x0){
            first_pass();
        }

        //check for 12th round after which the padding stage occurs
        /* absorb final plaintext block */
        //   s.x[0] ^= LOADBYTES(in, len);
        //   s.x[0] ^= PAD(len);
        //   p[31:0]2(&s);
        //   Currently working for only 8 byte string so can simply XOR with 0x80
        if(hdr.ascon.curr_round==0x6){
            // hdr.ascon_out.o0=hdr.ascon.s0;
            // hdr.ascon_out.o1=hdr.ascon.s0^0x0;
            hdr.ascon.s0=hdr.ascon.s0^0x0;
            hdr.ascon.s0[63:56]=hdr.ascon.s0[63:56]^0x80;
            hdr.ascon.s1=hdr.ascon.s1^K_0;
            hdr.ascon.s2=hdr.ascon.s2^K_1;

        }
        
        // check for final round(18th round)
        if(hdr.ascon.curr_round==0x12){

            hdr.ascon_out.o0=hdr.ascon.s3 ^ K_0; 
            hdr.ascon_out.o1=hdr.ascon.s4 ^ K_1;
            hdr.ascon_out.setValid();
            // hdr.ascon.s1=hdr.ascon_out.o1;
            do_recirculate();
            hdr.ethernet.ether_type=ETHERTYPE_RECIR;

        }
        else if(hdr.ethernet.ether_type==ETHERTYPE_RECIR){
            meta.q8=hdr.ascon_final.f0[63:32];
            meta.q9=hdr.ascon_final.f0[31:0];
            meta.p8=hdr.ascon_final.f1[63:32];
            meta.p9=hdr.ascon_final.f1[31:0];
            
            hdr.ascon_final.f0=hdr.ascon_final.f3;
            hdr.ascon_final.f1=hdr.ascon_final.f2;
            hdr.ascon_final.f2[63:32]=meta.q8;
            hdr.ascon_final.f2[31:0]=meta.q9;
            hdr.ascon_final.f3[63:32]=meta.p8;
            hdr.ascon_final.f3[63:32]=meta.p9;
            ig_tm_md.ucast_egress_port =(bit<9>)0x9;
        }
        else {
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

            // for hdr.s0
            @in_hash{meta.p8 = (meta.t0[18:0] ++ meta.t0[63:51]) ^ (meta.t0[27:0] ++ meta.t0[63:60]);}
            @in_hash{meta.p9 = meta.t0[50:19] ^ meta.t0[59:28];}
            hdr.ascon.s0[63:32] = meta.t0[63:32] ^ meta.p8;
            hdr.ascon.s0[31:0] = meta.t0[31:0] ^ meta.p9 ;


            // for hdr.s1
            @in_hash{meta.q8= (meta.t1[60:29]) ^ (meta.t1[38:7]);}
            @in_hash{meta.q9 = (meta.t1[28:0]++ meta.t1[63:61]) ^ (meta.t1[6:0]++ meta.t1[63:39]);}
            hdr.ascon.s1[63:32] = meta.t1[63:32] ^ meta.q8;
            hdr.ascon.s1[31:0] = meta.t1[31:0] ^ meta.q9;

            // for hdr.s2
            @in_hash{meta.p8= (meta.t2[0:0]++meta.t2[63:33]) ^ (meta.t2[5:0]++meta.t2[63:38]);}
            @in_hash{meta.p9  = meta.t2[32:1] ^ meta.t2[37:6];}
            hdr.ascon.s2[63:32] = meta.t2[63:32] ^ meta.p8;
            hdr.ascon.s2[31:0] = meta.t2[31:0] ^ meta.p9 ;

            // for hdr.s3
            @in_hash{meta.q8 = (meta.t3[9:0]++meta.t3[63:42]) ^ (meta.t3[16:0]++meta.t3[63:49]);}
            @in_hash{meta.q9 = meta.t3[41:10]^ meta.t3[48:17];}
            hdr.ascon.s3[63:32] = meta.t3[63:32] ^ meta.q8;
            hdr.ascon.s3[31:0] = meta.t3[31:0] ^ meta.q9;       

            // // for hdr.s4

            @in_hash{meta.p8 = (meta.t4[6:0]++meta.t4[63:39]) ^ (meta.t4[40:9]);}
            @in_hash{meta.p9  = meta.t4[38:7] ^ meta.t4[8:0]++ meta.t4[63:41];}
            hdr.ascon.s4[63:32] = meta.t4[63:32] ^ meta.p8;
            hdr.ascon.s4[31:0] = meta.t4[31:0] ^ meta.p9 ;

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
        // if(hdr.ascon_out.isValid()){    
        pkt.emit(hdr.ascon_out);
        // }
        // if(hdr.ascon_final.isValid()){
        pkt.emit(hdr.ascon_final);
        // }
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
