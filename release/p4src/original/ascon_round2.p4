/* addition of round constant */
add_const2.apply();

/* substitution layer */
substitution();
start_sbox_0();
start_sbox_1();
end_sbox();

/* Linear diffusion layer */
// for hdr.s0
@in_hash{hdr.ascon.s0[63:32] = meta.t0[63:32] ^ (meta.t0[18:0] ++ meta.t0[63:51]) ^ (meta.t0[27:0] ++ meta.t0[63:60]);}
@in_hash{hdr.ascon.s0[31:0] = meta.t0[31:0] ^ meta.t0[50:19] ^ meta.t0[59:28];}

// for hdr.s1
@in_hash{hdr.ascon.s1[63:32] = meta.t1[63:32] ^ (meta.t1[60:29]) ^ (meta.t1[38:7]);}
@in_hash{hdr.ascon.s1[31:0] = meta.t1[31:0] ^ (meta.t1[28:0]++ meta.t1[63:61]) ^ (meta.t1[6:0]++ meta.t1[63:39]);}

// for hdr.s2
@in_hash{hdr.ascon.s2[63:32] = meta.t2[63:32] ^ (meta.t2[0:0]++meta.t2[63:33]) ^ (meta.t2[5:0]++meta.t2[63:38]);}
@in_hash{hdr.ascon.s2[31:0] = meta.t2[31:0] ^ meta.t2[32:1] ^ meta.t2[37:6];}

// for hdr.s3
@in_hash{hdr.ascon.s3[63:32] = meta.t3[63:32] ^ (meta.t3[9:0]++meta.t3[63:42]) ^ (meta.t3[16:0]++meta.t3[63:49]);}
@in_hash{hdr.ascon.s3[31:0] = meta.t3[31:0] ^ meta.t3[41:10]^ meta.t3[48:17];}

// for hdr.s4
@in_hash{hdr.ascon.s4[63:32] = meta.t4[63:32] ^ (meta.t4[6:0]++meta.t4[63:39]) ^ (meta.t4[40:9]);}
@in_hash{hdr.ascon.s4[31:0] = meta.t4[31:0] ^ meta.t4[38:7] ^ meta.t4[8:0]++ meta.t4[63:41];}   

