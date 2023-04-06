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

control ROUND(
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
            (0, 0) : addition(0xf0);
            (0, 1) : addition(0xe1);
            (0, 2) : addition(0xd2);
            (0, 3) : addition(0xc3);
            (0, 4) : addition(0xb4);
            (0, 5) : addition(0xa5);
            (0, 6) : addition(0x96);
            (0, 7) : addition(0x87);
            (0, 8) : addition(0x78);
            (0, 9) : addition(0x69);
            (0, 10) : addition(0x5a);
            (0, 11) : addition(0x4b);

            /* P8 */
            (1, 0) : addition(0xb4);
            (1, 0) : addition(0xa5);
            (1, 0) : addition(0x96);
            (1, 0) : addition(0x87);
            (1, 0) : addition(0x78);
            (1, 0) : addition(0x69);
            (1, 0) : addition(0x5a);
            (1, 0) : addition(0x4b);

            /* P6 */
            (2, 0) : addition(0x96);
            (2, 1) : addition(0x87);
            (2, 2) : addition(0x78);
            (2, 3) : addition(0x69);
            (2, 4) : addition(0x5a);
            (2, 5) : addition(0x4b);
        }
    } 

    apply {
        // TODO: perform state transitions here
        hdr.ascon_meta.curr_round = hdr.ascon_meta.curr_round + 1; 


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
    }
}

control ASCON_AEAD(
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
        hdr.ascon_meta.curr_state = INIT;
        hdr.ascon_meta.next_state = STATE_AD;
        hdr.ascon_meta.round_type = P12;
        hdr.ascon_meta.curr_round = 0;
    }

    /* associated data block */
    action absorb_ad() {
        init_2nd_key_xor();

        // Note: we assume that AD is less than 63 bits      
        hdr.ascon.s0[63:32] = hdr.ascon.s0[63:32] ^ AD;
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
            hdr.ascon_meta.round_type : ternary;
            hdr.ascon_meta.curr_round : ternary;
        }
        actions = {
            absorb_ad;
            absorb_pt;
            absorb_pt_final;
            NoAction;
        }
        default_action = NoAction();
        const entries = {
            (STATE_AD, P6, 0) : absorb_ad();
            // TODO
        }
    }

    ROUND() ascon_round;

    apply{
        if(!hdr.ascon.isValid() && !hdr.ascon_meta.isValid()) {
            inititalize();
        }
        
        ascon_states.apply();
        if(local_md.ascon.is_absorb_pt) {
            hdr.ascon_out.o0 = hdr.ascon.s0;
        } else if(local_md.ascon.is_finalize) {
            set_tag();
        }

        ascon_round.apply(hdr, local_md);
    }
}
