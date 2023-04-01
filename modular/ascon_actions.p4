  //a fixed initialization stage
    action ascon_init(){
        //this remains same regardless of the key or i/p size
        
        //x0=bc830fbef3a1651b x1=487a66865036b909 x2=a031b0c5810c1cd6 x3=dd7ce72083702217 x4=9b17156ede557ce6
        // keeping till after the 2nd key xor + domain seperation into account
        hdr.ascon.s0= input_str ^ 0xbc830fbef3a1651b;
        hdr.ascon.s1= 0x487a66865036b909;   
        hdr.ascon.s2= 0xa031b0c5810c1cd6;
        hdr.ascon.s3= 0xdd7ce72083702217;
        hdr.ascon.s4= 0x9b17156ede557ce6;
        hdr.ascon_out.o0=hdr.ascon.s0;
    }
    //first pass init
    action first_pass(){
        //
        hdr.ascon.setValid();
		hdr.ascon.curr_round =0x0;
        ascon_init();
        hdr.ascon_out.setValid();
		// routing_decision();
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