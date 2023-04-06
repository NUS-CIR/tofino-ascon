//=============================================================================
// Ingress parser
//=============================================================================
parser SwitchIngressParser(packet_in pkt,
                           out switch_header_t hdr,
                           out switch_local_metadata_t local_md,
                           out ingress_intrinsic_metadata_t ig_intr_md) {
    
    state start {
        pkt.extract(ig_intr_md);
        // Check for resubmit flag if packet is resubmitted.
        // transition select(ig_intr_md.resubmit_flag) {
        //    1 : parse_resubmit;
        //    0 : parse_port_metadata;
        // }
        transition parse_port_metadata;
    }

    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);    

        // TODO: temporary
        pkt.extract(hdr.ascon);

        transition accept;
    }
}

//----------------------------------------------------------------------------
// Ingress deparser
//----------------------------------------------------------------------------
control SwitchIngressDeparser(packet_out pkt,
                              inout switch_header_t hdr,
                              in switch_local_metadata_t local_md,
                              in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    
    apply {
        pkt.emit(hdr);
    }
}

//----------------------------------------------------------------------------
// Egress parser
//----------------------------------------------------------------------------
parser SwitchEgressParser(packet_in pkt,
                          out switch_header_t hdr,
                          out switch_local_metadata_t local_md,
                          out egress_intrinsic_metadata_t eg_intr_md) {
                        

    state start {
        pkt.extract(eg_intr_md);

        // TODO: temporary
        pkt.extract(hdr.ascon);
        
        transition accept;
    }
}

//----------------------------------------------------------------------------
// Egress deparser
//----------------------------------------------------------------------------
control SwitchEgressDeparser(packet_out pkt,
                             inout switch_header_t hdr,
                             in switch_local_metadata_t local_md,
                             in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {
        pkt.emit(hdr);
    }
}