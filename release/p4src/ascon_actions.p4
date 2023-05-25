// Fixed initialization stage
action ascon_init(){
    // this remains same regardless of the key or i/p size
    // x0=bc830fbef3a1651b x1=487a66865036b909 x2=a031b0c5810c1cd6 x3=dd7ce72083702217 x4=9b17156ede557ce6
    // keeping till after the 2nd key xor + domain seperation into account
    hdr.ascon.s0= IV;
    hdr.ascon.s1= K_0;   
    hdr.ascon.s2= K_1;
    hdr.ascon.s3= N_0;
    hdr.ascon.s4= N_1;
    
    hdr.ascon.curr_round =0x0;
    hdr.ethernet.ether_type=ETHERTYPE_NORM;
    hdr.ascon.setValid();
}

// Absorb AD
action abs_ad(){
    // XORing the 32bit AD with s0
    hdr.ascon.s3= hdr.ascon.s3^ K_0;
    hdr.ascon.s4= hdr.ascon.s4^ K_1;
    // XOR with 0 has no effect on the rest 32 bits
    hdr.ascon.s0[63:32]= hdr.ascon.s0[63:32]^ AD;
    hdr.ascon.s0[31:24]=hdr.ascon.s0[31:24]^0x80;
}

// Absorb plaintext
action abs_input_1(){
    // domain seperation
    hdr.ascon.s4= hdr.ascon.s4 ^ 0x1;
    hdr.ascon.s0= hdr.ascon.s0 ^ hdr.payload.input_str[{{payload_byte*8-1}}:{{(payload_byte-1)*8}}];
}

action abs_input_2(){
    hdr.ascon_out.o0= hdr.ascon.s0;
    hdr.ascon_out.setValid();
    hdr.ethernet.ether_type= ETHERTYPE_RECIR;
}

action abs_input_3(){
    hdr.ascon.s0= hdr.ascon.s0 ^ hdr.payload[{{(payload_byte-1)*8-1}}:{{(payload_byte-2)*8}}];
}

action abs_input_4(){
    hdr.ascon_out.o1= hdr.ascon.s0;
}

action abs_input_5(){
    hdr.ascon.s0= hdr.ascon.s0 ^ hdr.payload[{{(payload_byte-2)*8-1}}:{{(payload_byte-3)*8}}];
}

action abs_input_6(){
    hdr.ascon_out.o2= hdr.ascon.s0;
}

action abs_input_7(){
    hdr.ascon.s0= hdr.ascon.s0^ hdr.payload[{{(payload_byte-3)*8-1}}:0];
}

action abs_input_8(){
    hdr.ascon_out.o3=hdr.ascon.s0;
}
action abs_final(){
    hdr.ascon.s0[63:56]=hdr.ascon.s0[63:56]^0x80;
    hdr.ascon.s1=hdr.ascon.s1^K_0;
    hdr.ascon.s2=hdr.ascon.s2^K_1;
}

//constant addition at the start of round using a table
action addition(bit<64> const_i) {
    hdr.ascon.s2 = hdr.ascon.s2 ^ const_i;
}

action substitution() {
    hdr.ascon.s0 = hdr.ascon.s0 ^ hdr.ascon.s4;
    hdr.ascon.s4 = hdr.ascon.s4 ^ hdr.ascon.s3;
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


        12:addition(0x96);
        13:addition(0x87);
        14:addition(0x78);
        15:addition(0x69);
        16:addition(0x5a);
        17:addition(0x4b);

    {% for i in range(payload_byte/8) %}
        18 + i*6:addition(0x96);
        19 + i*6:addition(0x87);
        20 + i*6:addition(0x78);
        21 + i*6:addition(0x69);
        22 + i*6:addition(0x5a);
        23 + i*6:addition(0x4b);
    {% endfor %}

    
        {{18 + payload_byte*6}}:addition(0xf0);
        {{18 + payload_byte*6 + 1}}:addition(0xe1);
        {{18 + payload_byte*6 + 2}}:addition(0xd2);         
        {{18 + payload_byte*6 + 3}}:addition(0xc3);
        {{18 + payload_byte*6 + 4}}:addition(0xb4);
        {{18 + payload_byte*6 + 5}}:addition(0xa5);
        {{18 + payload_byte*6 + 6}}:addition(0x96);
        {{18 + payload_byte*6 + 7}}:addition(0x87);
        {{18 + payload_byte*6 + 8}}:addition(0x78);
        {{18 + payload_byte*6 + 9}}:addition(0x69);
        {{18 + payload_byte*6 + 10}}:addition(0x5a);
        {{18 + payload_byte*6 + 11}}:addition(0x4b);       
        
    }
} 

table add_const2{
    key={
        hdr.ascon.curr_round:exact;
    }
    actions= {
        addition(); 
        @defaultonly NoAction;
    }
    size=64;
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


        12:addition(0x96);
        13:addition(0x87);
        14:addition(0x78);
        15:addition(0x69);
        16:addition(0x5a);
        17:addition(0x4b);

    {% for i in range(payload_byte/8) %}
        18 + i*6:addition(0x96);
        19 + i*6:addition(0x87);
        20 + i*6:addition(0x78);
        21 + i*6:addition(0x69);
        22 + i*6:addition(0x5a);
        23 + i*6:addition(0x4b);
    {% endfor %}

    
        {{18 + payload_byte*6}}:addition(0xf0);
        {{18 + payload_byte*6 + 1}}:addition(0xe1);
        {{18 + payload_byte*6 + 2}}:addition(0xd2);         
        {{18 + payload_byte*6 + 3}}:addition(0xc3);
        {{18 + payload_byte*6 + 4}}:addition(0xb4);
        {{18 + payload_byte*6 + 5}}:addition(0xa5);
        {{18 + payload_byte*6 + 6}}:addition(0x96);
        {{18 + payload_byte*6 + 7}}:addition(0x87);
        {{18 + payload_byte*6 + 8}}:addition(0x78);
        {{18 + payload_byte*6 + 9}}:addition(0x69);
        {{18 + payload_byte*6 + 10}}:addition(0x5a);
        {{18 + payload_byte*6 + 11}}:addition(0x4b);       
        
    }
} 
