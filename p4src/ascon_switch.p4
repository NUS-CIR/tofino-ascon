#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "includes/headers.p4"
#include "includes/types.p4"
#include "includes/parde.p4"
#include "includes/ascon.p4"

control SwitchIngress(
    inout switch_header_t hdr,
    inout switch_local_metadata_t local_md,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    
    AEAD_IG() ascon_aead;

    apply {
        ascon_aead.apply(hdr, local_md);
    }
}

control SwitchEgress(
    inout switch_header_t hdr,
    inout switch_local_metadata_t local_md,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {

    AEAD_EG() ascon_aead;

    apply {
        ascon_aead.apply(hdr, local_md);
    }
}

Pipeline <switch_header_t, switch_local_metadata_t, switch_header_t, switch_local_metadata_t> (SwitchIngressParser(),
        SwitchIngress(),
        SwitchIngressDeparser(),
        SwitchEgressParser(),
        SwitchEgress(),
        SwitchEgressDeparser()) pipe;

Switch(pipe) main;