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
        
		hdr.ascon.curr_round =0x0;
        hdr.ethernet.ether_type=ETHERTYPE_NORM;
        hdr.ascon.setValid();
    }

    //absorb AD
    action abs_ad(){
        //XORing the 32bit AD with s0
        hdr.ascon.s3= hdr.ascon.s3^ K_0;
        hdr.ascon.s4= hdr.ascon.s4^ K_1;
        //XOR with 0 has no effect on the rest 32 bits
        hdr.ascon.s0[63:32]= hdr.ascon.s0[63:32]^ AD;
        hdr.ascon.s0[31:24]=hdr.ascon.s0[31:24]^0x80;
    }

    //absorb plaintext
    action abs_input_1(){
        //domain seperation
        hdr.ascon.s4= hdr.ascon.s4^0x1;
        hdr.ascon.s0= hdr.ascon.s0^ hdr.payload_64.input_str;
    	// routing_decision();
	}
    action abs_input_2(){
        hdr.ascon_out.o0=hdr.ascon.s0;
        hdr.ascon_out.setValid();
        hdr.ethernet.ether_type=ETHERTYPE_RECIR;
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


            18:addition(0x96);
            19:addition(0x87);
            20:addition(0x78);
            21:addition(0x69);
            22:addition(0x5a);
            23:addition(0x4b);

            24:addition(0xf0);
            25:addition(0xe1);
            26:addition(0xd2);         
            27:addition(0xc3);
            28:addition(0xb4);
            29:addition(0xa5);
            30:addition(0x96);
            31:addition(0x87);
            32:addition(0x78);
            33:addition(0x69);
            34:addition(0x5a);
            35:addition(0x4b);       
           
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


            18:addition(0x96);
            19:addition(0x87);
            20:addition(0x78);
            21:addition(0x69);
            22:addition(0x5a);
            23:addition(0x4b);

            24:addition(0xf0);
            25:addition(0xe1);
            26:addition(0xd2);         
            27:addition(0xc3);
            28:addition(0xb4);
            29:addition(0xa5);
            30:addition(0x96);
            31:addition(0x87);
            32:addition(0x78);
            33:addition(0x69);
            34:addition(0x5a);
            35:addition(0x4b);
               
           
        }
    } 