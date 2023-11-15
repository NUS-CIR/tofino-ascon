/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/


#define eg_dev_port 8 // needs to be changed for 1c
#define ig_dev_port 0 // needs to be changed for 1c

const bit<32> lat_tb = 65536;
/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header vlan_tag_h {
    bit<3>   pcp;
    bit<1>   cfi;
    bit<12>  vid;
    bit<16>  ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_h   ethernet;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    bit<32> index;
    bit<32> delta;
}

    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
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
        transition accept;
    }

}

    /***************** M A T C H - A C T I O N  *********************/

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    //first val in <,> is size and second is index
    Register<bit<32>,bit<32>>(1) reg;
    // for keeping the packet loss count
    RegisterAction<bit<32>, _, bit<32>>(reg) pkt_out = {
        void apply(inout bit<32> register_data) { 
            register_data = register_data+1;
        }
    };

    // RegisterAction< _, _, bit<32>>(reg)
    //     pkt_in = {
    //         void apply(inout bit<32> register_data) { 
    //             register_data = register_data-1;
    //         }
    //     };

    Register<bit<32>,bit<32>>(1) reg_2;
    // for keeping index of latency register using packet count
    RegisterAction< _, _, bit<32>>(reg_2) check = {
        void apply(inout bit<32> register_data, out bit<32> rv) { 
            register_data = register_data+1;
            rv=register_data;
        }
    };
    
    Register<bit<32>,bit<16>>(lat_tb) latency;
    RegisterAction< _, _, bit<32>>(latency) lat_update = {
        void apply(inout bit<32> register_data) { 
            register_data = (bit<32>)meta.delta;
        }
    };

    // action count_in(){
    //     pkt_in.execute(0);
    // }
    
    action fetch_index(){
        meta.index=check.execute(0);
    }
    action latency_update_1(){
        meta.delta= ig_prsr_md.global_tstamp[31:0] - hdr.ethernet.src_addr[31:0];
    }

    action latency_update_2(){
            
        lat_update.execute(meta.index[15:0]);
    }

    apply {
        if(ig_intr_md.ingress_port == 68) {
            // pipe 0 traffic gen --> port3 tf2
            pkt_out.execute(0);
            ig_tm_md.ucast_egress_port = eg_dev_port;
        } 

        if(ig_intr_md.ingress_port == ig_dev_port){
            // count_in();
            fetch_index();
            latency_update_1();
            latency_update_2();
        }
        // else if (ig_intr_md.ingress_port == 196) {
        //     // pipe 1 traffic gen --> port4 tf2
        //     ig_tm_md.ucast_egress_port = 156;
        // } else {
        //     ig_dprsr_md.drop_ctl = 0x0;
        // }
    }
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
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
    ethernet_h   ethernet;
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
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
        transition accept;
    }

}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
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
        hdr.ethernet.src_addr = eg_prsr_md.global_tstamp;
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
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
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
