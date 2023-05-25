######### STANDARD MODULE IMPORTS ########
from __future__ import print_function
import unittest
import logging 
import grpc   
import pdb
from scapy.all import *

######### PTF modules for BFRuntime Client Library APIs #######
import importlib
import ptf
from ptf.testutils import *
from ptf.mask import *
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc

########## Basic Initialization ############
class P4ProgramTest(BfRuntimeTest):
    def setUp(self):
        self.client_id = 0
        # Use your own program name below
        self.p4_name   = test_param_get("ascon", "")

        self.dev       = 0
        self.dev_tgt   = gc.Target(self.dev, pipe_id=0xFFFF)
        
        print("\n")
        print("Test Setup")
        print("==========")

        BfRuntimeTest.setUp(self, self.client_id, self.p4_name)
        
        # This is the simple case when you run only one program on the target.
        # Otherwise, you might have to retrieve multiple bfrt_info objects and
        # in that case you will need to specify program name as a parameter
        self.bfrt_info = self.interface.bfrt_info_get()
        
        print("    Connected to Device: {}, Program: {}, ClientId: {}".format(
            self.dev, self.p4_name, self.client_id))

        # Create a list of all ports available on the device
        self.swports = []

        for (device, port, ifname) in ptf.config['interfaces']:
            self.swports.append(port)
        self.swports.sort()
        # print("Interfaces:", ptf.config['interfaces'])
        print("    SWPorts:", self.swports)

            
    def tearDown(self):
        print("\n")
        print("Test TearDown:")
        print("==============")

        self.cleanUp()
        
        # Call the Parent tearDown
        BfRuntimeTest.tearDown(self)

    # Use Cleanup Method to clear the tables before and after the test starts
    # (the latter is done as a part of tearDown()
    def cleanUp(self):
        print("\n")
        print("Table Cleanup:")
        print("==============")

# The main test
class Ascon(P4ProgramTest):

    def runTest(self):
    #     ingress_port = self.swports[test_param_get("ingress_port",  0)]
    #     egress_port  = self.swports[test_param_get("egress_port",   1)]
        ingress_port= 1
        egress_port= 9

        print("\n")
        print("Test Run")
        print("========")
        
        #sendp(Ether(type=0x8122)/("\x01\x00\x01\x02\x03\x04\x05\x06\x07"), iface="veth1")
        pkt = Ether(type=0x8122)/("\x01\x00\x01\x02\x03\x04\x05\x06\x07")
        send_packet(self,ingress_port,pkt)

        expt_pkt = Ether(type=0x8133)/(b'\x01\x00\x01\x02\x03\x04\x05\x06\x07\x01?|\xbb$\xabe\xc5\xce\x9d\x1a~~\t\xe6n\xe9\xe9\x8c\x05qJ\xa3\n\xc2\xe6\xd6\xfa#\t\xef&\xd1\xe6\xdf \xfa\xeb3\xa6$wc\xf8\xbal\xe9\x1e\xd1\x00\x00\x00\x00\x00\x00\x00\x00\xc2\xe6\xd6\xfa#\t\xef&\xd1\xe6\xdf \xfa\xeb3\xa6\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00') 
        print("Expected packet is: \n")
        hexdump(expt_pkt)
        expt_pkt = Mask(expt_pkt)
        expt_pkt.set_do_not_care_scapy(Ether, "dst")
        expt_pkt.set_do_not_care_scapy(Ether, "src")

        verify_packet(self, expt_pkt, egress_port)
        print("\nVerified Packet received on port %d" % egress_port)


        ############# That's it! ##############