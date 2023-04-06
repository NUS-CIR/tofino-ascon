//the 320 bit IV is fixed after the first round of Perms 
//ee9398aadb67f03d 8bb21831c60f1002 b48a92db98d5da62 43189921b8f8e3e8 348fa5c9d525e140
const bit<32> AD = 0x00010203;
const bit<64> IV = 0x80400c0600000000;
// const bit<64> input_str=0x0001020304050607;//64 bit string input supported
// const bit<128> input_str_2=0x000102030405060708090A0B0C0D0E0F;

#define K_0 0x0001020304050607
#define K_1 0x08090A0B0C0D0E0F
#define N_0 0x0001020304050607
#define N_1 0x08090A0B0C0D0E0F

control ROUND (
    inout switch_header_t hdr,
    inout switch_local_metadata_t local_md
) {
    bit<64> t0 = 0;
    bit<64> t1 = 0;
    bit<64> t2 = 0;
    bit<64> t3 = 0;
    bit<64> t4 = 0;

    action addition(bit<64> const_i) {
        hdr.ascon.s2 = hdr.ascon.s2 ^ const_i;
    }

    action substitution() {
        hdr.ascon.s0 = hdr.ascon.s0 ^ hdr.ascon.s4;
        hdr.ascon.s4 = hdr.ascon.s4 ^ hdr.ascon.s3;
        hdr.ascon.s2 = hdr.ascon.s2 ^ hdr.ascon.s1;
    }

    action start_sbox_0 () {
        t0 = ~hdr.ascon.s1 & hdr.ascon.s2;
        t1 = ~hdr.ascon.s2 & hdr.ascon.s3;
        t2 = ~hdr.ascon.s3 & hdr.ascon.s4;
        t3 = ~hdr.ascon.s4 & hdr.ascon.s0;
        t4 = ~hdr.ascon.s0 & hdr.ascon.s1;
    }
    
    action start_sbox_1 () {
        t0 = hdr.ascon.s0 ^ t0;
        t1 = hdr.ascon.s1 ^ t1;
        t2 = hdr.ascon.s2 ^ t2;
        t3 = hdr.ascon.s3 ^ t3;
        t4 = hdr.ascon.s4 ^ t4;
    }

    action end_sbox() {
        t1 = t1 ^ t0;
        t0 = t0 ^ t4;
        t3 = t3 ^ t2;
        t2 = ~t2;
    }

    table add_const {
        key = {
            hdr.ascon_meta.round_type : exact;
            hdr.ascon_meta.curr_round : exact;
        }
        actions = {
            addition; 
            NoAction;
        }
        default_action = NoAction();
        const entries ={
            /* P12 */
            (P12, 0) : addition(0xf0);
            (P12, 1) : addition(0xe1);
            (P12, 2) : addition(0xd2);
            (P12, 3) : addition(0xc3);
            (P12, 4) : addition(0xb4);
            (P12, 5) : addition(0xa5);
            (P12, 6) : addition(0x96);
            (P12, 7) : addition(0x87);
            (P12, 8) : addition(0x78);
            (P12, 9) : addition(0x69);
            (P12, 10) : addition(0x5a);
            (P12, 11) : addition(0x4b);

            /* P8 */
            (P8, 0) : addition(0xb4);
            (P8, 1) : addition(0xa5);
            (P8, 2) : addition(0x96);
            (P8, 3) : addition(0x87);
            (P8, 4) : addition(0x78);
            (P8, 5) : addition(0x69);
            (P8, 6) : addition(0x5a);
            (P8, 7) : addition(0x4b);

            /* P6 */
            (P6, 0) : addition(0x96);
            (P6, 1) : addition(0x87);
            (P6, 2) : addition(0x78);
            (P6, 3) : addition(0x69);
            (P6, 4) : addition(0x5a);
            (P6, 5) : addition(0x4b);
        }
    } 

    action state_transition_action(state_t next_state, round_type_t round_type) {
        hdr.ascon_meta.curr_state = next_state;
        hdr.ascon_meta.round_type = round_type;
        hdr.ascon_meta.curr_round = 0;
    }

    action state_transition_default_action() {
        hdr.ascon_meta.curr_round = hdr.ascon_meta.curr_round + 1; 
    }

    table state_transition {
        key = {
            hdr.ascon_meta.curr_state : exact;
            hdr.ascon_meta.round_type : exact;
            hdr.ascon_meta.curr_round + 1 : exact @name("hdr.ascon_meta.curr_round");
        }
        actions = {
            state_transition_action;
            state_transition_default_action;
        }
        default_action = state_transition_default_action;
        // const entries = {
        //     (STATE_INIT, P12, 11)       : state_transition_action(STATE_AD, P6);
        //     (STATE_AD_FINAL, P6, 5)     : state_transition_action(STATE_PT, P6);
        //     (STATE_PT, P6, 5)           : state_transition_action(STATE_PT_FINAL, P12);
        //     (STATE_PT_FINAL, P12, 11)   : state_transition_action(STATE_FINAL, P0);
        // }
    }

    apply {
        /* addition of round constant */
        add_const.apply();
        
        /* substitution layer */
        substitution();

        /* start of keccak s-box */
        start_sbox_0();
        start_sbox_1();

        /* end of keccak s-box */    
        end_sbox();

        /* linear diffusion layer */ 
        @in_hash{hdr.ascon.s0[63:32] = t0[63:32] ^ (t0[18:0] ++ t0[63:51]) ^ (t0[27:0] ++ t0[63:60]);}
        @in_hash{hdr.ascon.s0[31:0] = t0[31:0] ^ t0[50:19] ^ t0[59:28];}

        @in_hash{hdr.ascon.s1[63:32] = t1[63:32] ^ (t1[60:29]) ^ (t1[38:7]);}
        @in_hash{hdr.ascon.s1[31:0] = t1[31:0] ^ (t1[28:0]++ t1[63:61]) ^ (t1[6:0]++ t1[63:39]);}

        @in_hash{hdr.ascon.s2[63:32] = t2[63:32] ^ (t2[0:0]++t2[63:33]) ^ (t2[5:0]++t2[63:38]);}
        @in_hash{hdr.ascon.s2[31:0] = t2[31:0] ^ t2[32:1] ^ t2[37:6];}

        @in_hash{hdr.ascon.s3[63:32] = t3[63:32] ^ (t3[9:0]++t3[63:42]) ^ (t3[16:0]++t3[63:49]);}
        @in_hash{hdr.ascon.s3[31:0] = t3[31:0] ^ t3[41:10]^ t3[48:17];}

        @in_hash{hdr.ascon.s4[63:32] = t4[63:32] ^ (t4[6:0]++t4[63:39]) ^ (t4[40:9]);}
        @in_hash{hdr.ascon.s4[31:0] = t4[31:0] ^ t4[38:7] ^ t4[8:0]++ t4[63:41];}   

        state_transition.apply();
    }
}

control AEAD_IG (
    inout switch_header_t hdr,
    inout switch_local_metadata_t local_md    
) {

    /* inititalize */
    action init_1st_key_xor() {
        hdr.ascon.s0 = IV;
        hdr.ascon.s1 = K_0;   
        hdr.ascon.s2 = K_1;
        hdr.ascon.s3 = N_0;
        hdr.ascon.s4 = N_1;
    }

    action init_2nd_key_xor() {
        hdr.ascon.s3 = hdr.ascon.s3 ^ K_0;
        hdr.ascon.s4 = hdr.ascon.s4 ^ K_1;
    }

    action inititalize() {
        hdr.ascon.setValid();
        init_1st_key_xor();

        hdr.ascon_meta.setValid();
        hdr.ascon_meta.curr_state = STATE_INIT;
        hdr.ascon_meta.round_type = P12;
        hdr.ascon_meta.curr_round = 0;
    }

    /* associated data block */
    action absorb_ad() {
        init_2nd_key_xor();

        // Note: we assume that the AD is 32 bits  
        hdr.ascon.s0[63:32] = hdr.ascon.s0[63:32] ^ local_md.ascon.associated_data;
        hdr.ascon.s0[31:24] = hdr.ascon.s0[31:24] ^ 0x80;
    }

    action domain_separation() {
        hdr.ascon.s4 = hdr.ascon.s4 ^ 0x1;   
    }

    /* full plaintext blocks */
    action absorb_pt() {
        domain_separation();

        hdr.ascon_out.setValid();
        hdr.ascon.s0= hdr.ascon.s0 ^ hdr.payload.p0;
        local_md.ascon.is_absorb_pt = true;
    }

#ifdef PAYLOAD_16B 
    action absorb_pt2() {
        domain_separation();

        hdr.ascon_out.setValid();
        hdr.ascon.s0= hdr.ascon.s0 ^ hdr.payload.p1;
        local_md.ascon.is_absorb_pt2 = true;
    }
#elif PAYLOAD_32B
    action absorb_pt2() {
        domain_separation();

        hdr.ascon_out.setValid();
        hdr.ascon.s0= hdr.ascon.s0 ^ hdr.payload.p1;
        local_md.ascon.is_absorb_pt2 = true;
    }

    action absorb_pt3() {
        domain_separation();

        hdr.ascon_out.setValid();
        hdr.ascon.s0= hdr.ascon.s0 ^ hdr.payload.p2;
        local_md.ascon.is_absorb_pt3 = true;
    }

    action absorb_pt4() {
        domain_separation();

        hdr.ascon_out.setValid();
        hdr.ascon.s0= hdr.ascon.s0 ^ hdr.payload.p3;
        local_md.ascon.is_absorb_pt4 = true;
    }
#endif

    /* final plaintext block */
    action final_1st_key_xor() {
        hdr.ascon.s1 = hdr.ascon.s1 ^ K_0;
        hdr.ascon.s2 = hdr.ascon.s2 ^ K_1;
    }

    action absorb_pt_final() {
        hdr.ascon.s0[63:56]  = hdr.ascon.s0[63:56] ^ 0x80;
        final_1st_key_xor();
    }

    /* finalize */
    action final_2nd_key_xor() {
        hdr.ascon.s3 = hdr.ascon.s3 ^ K_0; 
        hdr.ascon.s4 = hdr.ascon.s4 ^ K_1;
    }

    action finalize() {
        final_2nd_key_xor();
        local_md.ascon.is_finalize = true;
    }

    /* set tag */
    action set_tag() {
        hdr.ascon_tag.setValid();
        hdr.ascon_tag.tag0 = hdr.ascon.s3;
        hdr.ascon_tag.tag1 = hdr.ascon.s4;
    }

    table ascon_states {
        key = {
            hdr.ascon_meta.curr_state : exact;
            hdr.ascon_meta.round_type : exact;
            hdr.ascon_meta.curr_round : exact;
        }
        actions = {
            absorb_ad;
            absorb_pt;
            absorb_pt_final;
            finalize;
            NoAction;
        }
        default_action = NoAction();
        // const entries = {
        //     (STATE_AD_FINAL, P6, 0)     : absorb_ad();
        //     (STATE_PT, P6, 0)           : absorb_pt();
        //     (STATE_PT_FINAL, P12, 0)    : absorb_pt_final();
        //     (STATE_FINAL, P0, 0)        : finalize();
        // }
    }

    ROUND() ascon_round;

    apply{
        if(!hdr.ascon.isValid() && !hdr.ascon_meta.isValid()) {
            inititalize();
        }
        
        if(ascon_states.apply().hit) {
            if(local_md.ascon.is_absorb_pt) {
                hdr.ascon_out.o0 = hdr.ascon.s0;
            } 
#ifdef PAYLOAD_16B
            else if(local_md.ascon.is_absorb_pt2) {
                hdr.ascon_out.o1 = hdr.ascon.s0;
            }            
#elif PAYLOAD_32B
            else if(local_md.ascon.is_absorb_pt2) {
                hdr.ascon_out.o1 = hdr.ascon.s0;
            }
            else if(local_md.ascon.is_absorb_pt3) {
                hdr.ascon_out.o2 = hdr.ascon.s0;
            }
            else if(local_md.ascon.is_absorb_pt4) {
                hdr.ascon_out.o3 = hdr.ascon.s0;
            }            
#endif
            else if(local_md.ascon.is_finalize) {
                set_tag();
            }
        }

        if(!local_md.ascon.is_finalize) {
            ascon_round.apply(hdr, local_md);
        }
    }
}

control AEAD_EG (
    inout switch_header_t hdr,
    inout switch_local_metadata_t local_md    
) {

    ROUND() ascon_round;

    apply {
        if(hdr.ascon.isValid() && hdr.ascon_meta.isValid()) {
            ascon_round.apply(hdr, local_md);
        }
    }
}