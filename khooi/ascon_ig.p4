// /* addition of round constant */
addition(0x96);

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

#ifdef BIT_32
// for hdr.s0
// @in_hash{meta.p[63:32] = (meta.t0[18:0] ++ meta.t0[63:51]) ^ (meta.t0[27:0] ++ meta.t0[63:60]);}
// @in_hash{ meta.p0 = (meta.t0_1[18:0] ++ meta.t0_0[31:19]) ^ (meta.t0_1[27:0] ++ meta.t0_0[31:28]); }
@in_hash{ hdr.ascon.s0_0 = meta.t0_0 ^ (meta.t0_1[18:0] ++ meta.t0_0[31:19]) ^ (meta.t0_1[27:0] ++ meta.t0_0[31:28]); }
// @in_hash{meta.p[31:0] = meta.t0[50:19] ^ meta.t0[59:28];}
// @in_hash{ meta.p1 = (meta.t0_0[18:0] ++ meta.t0_1[31:19]) ^ (meta.t0_0[27:0] ++ meta.t0_1[31:28]); }
@in_hash{ hdr.ascon.s0_1 = meta.t0_1 ^ (meta.t0_0[18:0] ++ meta.t0_1[31:19]) ^ (meta.t0_0[27:0] ++ meta.t0_1[31:28]); } 
// hdr.ascon.s0[63:32] = meta.t0[63:32] ^ meta.p[63:32];
// hdr.ascon.s0_0 = meta.t0_0 ^ meta.p0;
// hdr.ascon.s0[31:0] = meta.t0[31:0] ^ meta.p[31:0];
// hdr.ascon.s0_1 = meta.t0_1 ^ meta.p1;

// // for hdr.s1
// // @in_hash{meta.q[63:32] = (meta.t1[60:29]) ^ (meta.t1[38:7]);}
// @in_hash { meta.q0 = (meta.t1_0[28:0] ++ meta.t1_1[31:29]) ^ (meta.t1_0[6:0] ++ meta.t1_1[31:7]); }
// // @in_hash{meta.q[31:0] = (meta.t1[28:0]++ meta.t1[63:61]) ^ (meta.t1[6:0]++ meta.t1[63:39]);}
// @in_hash { meta.q1 = (meta.t1_1[28:0] ++ meta.t1_0[31:29]) ^ (meta.t1_1[6:0] ++ meta.t1_0[31:7]); }
// // hdr.ascon.s1[63:32] = meta.t1[63:32] ^ meta.q[63:32];
// hdr.ascon.s1_0 = meta.t1_0 ^ meta.q0;
// // hdr.ascon.s1[31:0] = meta.t1[31:0] ^ meta.q[31:0];
// hdr.ascon.s1_1 = meta.t1_1 ^ meta.q1;

// // for hdr.s2
// // @in_hash{meta.p[63:32] = (meta.t2[0:0]++meta.t2[63:33]) ^ (meta.t2[5:0]++meta.t2[63:38]);}
// @in_hash { meta.p0 = (meta.t2_1[0:0] ++ meta.t2_0[31:1]) ^ (meta.t2_1[5:0] ++ meta.t2_0[31:6]); }
// // @in_hash{meta.p[31:0] = meta.t2[32:1] ^ meta.t2[37:6];}
// @in_hash { meta.p1 = (meta.t2_0[0:0] ++ meta.t2_1[31:1]) ^ (meta.t2_0[5:0] ++ meta.t2_1[31:6]); }
// // hdr.ascon.s2[63:32] = meta.t2[63:32] ^ meta.p[63:32];
// hdr.ascon.s2_0 = meta.t2_0 ^ meta.p0;
// // hdr.ascon.s2[31:0] = meta.t2[31:0] ^ meta.p[31:0];
// hdr.ascon.s2_1 = meta.t2_1 ^ meta.p1;

// // for hdr.s3
// // @in_hash{meta.q[63:32] = (meta.t3[9:0]++meta.t3[63:42]) ^ (meta.t3[16:0]++meta.t3[63:49]);}
// @in_hash { meta.q0 = (meta.t3_1[9:0] ++ meta.t3_0[31:10]) ^ (meta.t3_1[16:0] ++ meta.t3_0[31:17]); }
// // @in_hash{meta.q[31:0] = meta.t3[41:10]^ meta.t3[48:17];}
// @in_hash { meta.q1 = (meta.t3_0[9:0] ++ meta.t3_1[31:10]) ^ (meta.t3_0[16:0] ++ meta.t3_1[31:17]); }
// // hdr.ascon.s3[63:32] = meta.t3[63:32] ^ meta.q[63:32];
// hdr.ascon.s3_0 = meta.t3_0 ^ meta.q0;
// // hdr.ascon.s3[31:0] = meta.t3[31:0] ^ meta.q[31:0];
// hdr.ascon.s3_1 = meta.t3_1 ^ meta.q1;

// // for hdr.s4
// // @in_hash{meta.p[63:32] = (meta.t4[6:0]++meta.t4[63:39]) ^ (meta.t4[40:9]);}
// @in_hash { meta.p0 = (meta.t4_1[6:0] ++ meta.t4_0[31:7]) ^ (meta.t4_0[8:0] ++ meta.t4_1[31:9]); }
// // @in_hash{meta.p[31:0] = meta.t4[38:7] ^ meta.t4[8:0]++ meta.t4[63:41];}
// @in_hash { meta.p1 = (meta.t4_0[6:0] ++ meta.t4_1[31:7]) ^ (meta.t4_1[8:0] ++ meta.t4_0[31:9]); }
// // hdr.ascon.s4[63:32] = meta.t4[63:32] ^ meta.p[63:32];
// hdr.ascon.s4_0 = meta.t4_0 ^ meta.p0;
// // hdr.ascon.s4[31:0] = meta.t4[31:0] ^ meta.p[31:0];     
// hdr.ascon.s4_1 = meta.t4_1 ^ meta.p1;
#else
// for hdr.s0
// @in_hash{meta.p[63:32] = (meta.t0[18:0] ++ meta.t0[63:51]) ^ (meta.t0[27:0] ++ meta.t0[63:60]);}
// @in_hash{meta.p[31:0] = meta.t0[50:19] ^ meta.t0[59:28];}
// hdr.ascon.s0[63:32] = meta.t0[63:32] ^ meta.p[63:32];
// hdr.ascon.s0[31:0] = meta.t0[31:0] ^ meta.p[31:0];
@in_hash{hdr.ascon.s0[63:32] = meta.t0[63:32] ^ (meta.t0[18:0] ++ meta.t0[63:51]) ^ (meta.t0[27:0] ++ meta.t0[63:60]);}
@in_hash{hdr.ascon.s0[31:0] = meta.t0[31:0] ^ meta.t0[50:19] ^ meta.t0[59:28];}
// hdr.ascon.s0[63:32] = meta.t0[63:32] ^ meta.p[63:32];
// hdr.ascon.s0[31:0] = meta.t0[31:0] ^ meta.p[31:0];



// for hdr.s1
// @in_hash{meta.q[63:32] = (meta.t1[60:29]) ^ (meta.t1[38:7]);}
// @in_hash{meta.q[31:0] = (meta.t1[28:0]++ meta.t1[63:61]) ^ (meta.t1[6:0]++ meta.t1[63:39]);}
// hdr.ascon.s1[63:32] = meta.t1[63:32] ^ meta.q[63:32];
// hdr.ascon.s1[31:0] = meta.t1[31:0] ^ meta.q[31:0];
@in_hash{hdr.ascon.s1[63:32] = meta.t1[63:32] ^ (meta.t1[60:29]) ^ (meta.t1[38:7]);}
@in_hash{hdr.ascon.s1[31:0] = meta.t1[31:0] ^ (meta.t1[28:0]++ meta.t1[63:61]) ^ (meta.t1[6:0]++ meta.t1[63:39]);}


// for hdr.s2
// @in_hash{meta.p[63:32] = (meta.t2[0:0]++meta.t2[63:33]) ^ (meta.t2[5:0]++meta.t2[63:38]);}
// @in_hash{meta.p[31:0] = meta.t2[32:1] ^ meta.t2[37:6];}
// hdr.ascon.s2[63:32] = meta.t2[63:32] ^ meta.p[63:32];
// hdr.ascon.s2[31:0] = meta.t2[31:0] ^ meta.p[31:0];
@in_hash{hdr.ascon.s2[63:32] = meta.t2[63:32] ^ (meta.t2[0:0]++meta.t2[63:33]) ^ (meta.t2[5:0]++meta.t2[63:38]);}
@in_hash{hdr.ascon.s2[31:0] = meta.t2[31:0] ^ meta.t2[32:1] ^ meta.t2[37:6];}


// for hdr.s3
// @in_hash{meta.q[63:32] = (meta.t3[9:0]++meta.t3[63:42]) ^ (meta.t3[16:0]++meta.t3[63:49]);}
// @in_hash{meta.q[31:0] = meta.t3[41:10]^ meta.t3[48:17];}
// hdr.ascon.s3[63:32] = meta.t3[63:32] ^ meta.q[63:32];
// hdr.ascon.s3[31:0] = meta.t3[31:0] ^ meta.q[31:0];
@in_hash{hdr.ascon.s3[63:32] = meta.t3[63:32] ^ (meta.t3[9:0]++meta.t3[63:42]) ^ (meta.t3[16:0]++meta.t3[63:49]);}
@in_hash{hdr.ascon.s3[31:0] = meta.t3[31:0] ^ meta.t3[41:10]^ meta.t3[48:17];}


// // for hdr.s4

// @in_hash{meta.p[63:32] = (meta.t4[6:0]++meta.t4[63:39]) ^ (meta.t4[40:9]);}
// @in_hash{meta.p[31:0] = meta.t4[38:7] ^ meta.t4[8:0]++ meta.t4[63:41];}
// hdr.ascon.s4[63:32] = meta.t4[63:32] ^ meta.p[63:32];
// hdr.ascon.s4[31:0] = meta.t4[31:0] ^ meta.p[31:0];   
@in_hash{hdr.ascon.s4[63:32] = meta.t4[63:32] ^ (meta.t4[6:0]++meta.t4[63:39]) ^ (meta.t4[40:9]);}
@in_hash{hdr.ascon.s4[31:0] = meta.t4[31:0] ^ meta.t4[38:7] ^ meta.t4[8:0]++ meta.t4[63:41];}     
#endif 