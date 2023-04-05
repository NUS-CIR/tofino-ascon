  //a fixed initialization stage
    action ascon_init(){
        //this remains same regardless of the key or i/p size

        //x0=bc830fbef3a1651b x1=487a66865036b909 x2=a031b0c5810c1cd6 x3=dd7ce72083702217 x4=9b17156ede557ce6
        // keeping till after the 2nd key xor + domain seperation into account
        hdr.ascon.s0= IV;
        hdr.ascon.s1= K_0;   
        hdr.ascon.s2= K_1;
        hdr.ascon.s3= N_0;
        hdr.ascon.s4= N_1;
        hdr.ascon.state-=0x0;
		hdr.ascon.curr_round =0x0;

        hdr.ascon.setValid();
        // hdr.ascon_out.o0=hdr.ascon.s0;
    }

    //absorb AD
    action abs_ad(){
        //XORing the 32bit AD with s0
        hdr.ascon.s3= hdr.ascon.s3^ K_0;
        hdr.ascon.s4= hdr.ascon.s4^ K_1;
        //XOR with 0 has no effect on the rest 32 bits
        hdr.ascon.s0[63:32]= hdr.ascon.s0[63:32]^ AD;
    }

    //absorb plaintext
    action abs_input(){
        //domain seperation
        hdr.ascon.s4= hdr.ascon.s4^0x1;
        //
        hdr.ascon.s0= hdr.ascon.s0^input_str;
        hdr.ascon_out.o0=hdr.ascon.s0;
        hdr.ascon_out.setValid();
        hdr.ethernet.ether_type=ETHERTYPE_RECIR;
		// routing_decision();
	}

    action abs_final(){
        hdr.ascon.s0=hdr.ascon.s0^0x0;
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
            12:addition(0xf0);
            13:addition(0xe1);
            14:addition(0xd2);
            15:addition(0x96);
            16:addition(0x87);
            17:addition(0x78);
            18:addition(0x69);
            19:addition(0x5a);
            20:addition(0x4b);
            21:addition(0xf0);
            22:addition(0xe1);
            23:addition(0xd2);         
            24:addition(0xc3);
            25:addition(0xb4);
            26:addition(0xa5);
            27:addition(0x96);
            28:addition(0x87);
            29:addition(0x78);
            30:addition(0x69);
            31:addition(0x5a);
            32:addition(0x4b);
            33:addition(0xf0);
            34:addition(0xe1);
            35:addition(0xd2);         
           
        }
    } 