//constant addition at the start of round using a table
#ifdef BIT_32
action addition(bit<32> const_i) {
    hdr.ascon.s2_1 = hdr.ascon.s2_1 ^ const_i;
}

action substitution() {
    hdr.ascon.s0_0 = hdr.ascon.s0_0 ^ hdr.ascon.s4_0;
    hdr.ascon.s0_1 = hdr.ascon.s0_1 ^ hdr.ascon.s4_1;

    hdr.ascon.s4_0 = hdr.ascon.s4_0 ^ hdr.ascon.s3_0;
    hdr.ascon.s4_1 = hdr.ascon.s4_1 ^ hdr.ascon.s3_1;

    hdr.ascon.s2_0 = hdr.ascon.s2_0 ^ hdr.ascon.s1_0;
    hdr.ascon.s2_1 = hdr.ascon.s2_1 ^ hdr.ascon.s1_1;
}

action start_sbox_0 () {
    meta.t0_0 = ~hdr.ascon.s1_0 & hdr.ascon.s2_0;
    meta.t0_1 = ~hdr.ascon.s1_1 & hdr.ascon.s2_1;

    meta.t1_0 = ~hdr.ascon.s2_0 & hdr.ascon.s3_0;
    meta.t1_1 = ~hdr.ascon.s2_1 & hdr.ascon.s3_1;

    meta.t2_0 = ~hdr.ascon.s3_0 & hdr.ascon.s4_0;
    meta.t2_1 = ~hdr.ascon.s3_1 & hdr.ascon.s4_1;
    
    meta.t3_0 = ~hdr.ascon.s4_0 & hdr.ascon.s0_0;
    meta.t3_1 = ~hdr.ascon.s4_1 & hdr.ascon.s0_1;

    meta.t4_0 = ~hdr.ascon.s0_0 & hdr.ascon.s1_0;
    meta.t4_1 = ~hdr.ascon.s0_1 & hdr.ascon.s1_1;
}

action start_sbox_1 () {
    meta.t0_0 = hdr.ascon.s0_0 ^ meta.t0_0;
    meta.t0_1 = hdr.ascon.s0_1 ^ meta.t0_1;

    meta.t1_0 = hdr.ascon.s1_0 ^ meta.t1_0;
    meta.t1_1 = hdr.ascon.s1_1 ^ meta.t1_1;

    meta.t2_0 = hdr.ascon.s2_0 ^ meta.t2_0;
    meta.t2_1 = hdr.ascon.s2_1 ^ meta.t2_1;

    meta.t3_0 = hdr.ascon.s3_0 ^ meta.t3_0;
    meta.t3_1 = hdr.ascon.s3_1 ^ meta.t3_1;

    meta.t4_0 = hdr.ascon.s4_0 ^ meta.t4_0;
    meta.t4_1 = hdr.ascon.s4_1 ^ meta.t4_1;
}

action end_sbox() {
    meta.t1_0 = meta.t1_0 ^ meta.t0_0;
    meta.t1_1 = meta.t1_1 ^ meta.t0_1;
    
    meta.t0_0 = meta.t0_0 ^ meta.t4_0;
    meta.t0_1 = meta.t0_1 ^ meta.t4_1;
    
    meta.t3_0 = meta.t3_0 ^ meta.t2_0;
    meta.t3_1 = meta.t3_1 ^ meta.t2_1;

    meta.t2_0 = ~meta.t2_0;
    meta.t2_1 = ~meta.t2_1;
}
#else
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
#endif

