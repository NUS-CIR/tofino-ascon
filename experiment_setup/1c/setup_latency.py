# THIS IS FOR 4 ROUND/PASS TOFINO2

#!/usr/bin/env python3
import sys
import os
import argparse
import time
import scapy
from scapy.all import *

sde_install = os.environ['SDE_INSTALL']
sys.path.append('%s/lib/python2.7/site-packages/tofino'%(sde_install))
sys.path.append('%s/lib/python2.7/site-packages/p4testutils'%(sde_install))
sys.path.append('%s/lib/python2.7/site-packages'%(sde_install))
# import grpc
# import time
# from pprint import pprint
# import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2

# Assumes valid PYTHONPATH
import bfrt_grpc.client as gc

# Connect to the BF Runtime server
for bfrt_client_id in range(10):
    try:
        interface = gc.ClientInterface(
            grpc_addr="localhost:50052",
            client_id=bfrt_client_id,
            device_id=0,
            num_tries=1,
        )
        print("Connected to BF Runtime Server as client", bfrt_client_id)
        break
    except:
        print("Could not connect to BF Runtime Server")
        quit

# Get information about the running program
bfrt_info = interface.bfrt_info_get()
print("The target is running the P4 program: {}".format(bfrt_info.p4_name_get()))

# Establish that you are the "main" client
if bfrt_client_id == 0:
    interface.bind_pipeline_config(bfrt_info.p4_name_get())

# Get the target device, currently setup for all pipes
target = gc.Target(device_id=0, pipe_id=0xffff)

# For getting the dev_ports from the front panel ports itself
def get_devport(frontpanel, lane):
    port_hdl_info = bfrt_info.table_get("$PORT_HDL_INFO")
    key = port_hdl_info.make_key(
        [gc.KeyTuple("$CONN_ID", frontpanel), gc.KeyTuple("$CHNL_ID", lane)]
    )
    for data, _ in port_hdl_info.entry_get(target, [key], {"from_hw": False}):
        devport = data.to_dict()["$DEV_PORT"]
        if devport:
            return devport


port17 = get_devport(17, 0)
port18 = get_devport(18, 0)
print(port17)
print(port18)
# port18=0
port_tbl = bfrt_info.table_get("$PORT")
# port_tbl.entry_mod(target,[],[])
# print("Removed ports")

port_tbl_keys = [
    port_tbl.make_key([gc.KeyTuple("$DEV_PORT", port17)]),
    port_tbl.make_key([gc.KeyTuple("$DEV_PORT", port18)]),
]
port_tbl_data = [
    port_tbl.make_data(
        [
            gc.DataTuple("$SPEED", str_val="BF_SPEED_100G"),
            gc.DataTuple("$FEC", str_val="BF_FEC_TYP_NONE"),
            gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_FORCE_DISABLE"),
            gc.DataTuple("$PORT_DIR", str_val="PM_PORT_DIR_DEFAULT"),
            gc.DataTuple("$PORT_ENABLE", bool_val=True),
        ]
    ),
    port_tbl.make_data(
        [
            gc.DataTuple("$SPEED", str_val="BF_SPEED_100G"),
            gc.DataTuple("$FEC", str_val="BF_FEC_TYP_NONE"),
            gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_FORCE_DISABLE"),
            gc.DataTuple("$PORT_DIR", str_val="PM_PORT_DIR_DEFAULT"),
            gc.DataTuple("$PORT_ENABLE", bool_val=True),
        ]
    ),
]
port_tbl.entry_add(target, port_tbl_keys, port_tbl_data)
print("Added Ports")

time.sleep(5)

# Getting the pktgen tables
pktgen_buffer = bfrt_info.table_get("tf1.pktgen.pkt_buffer")
pktgen_port = bfrt_info.table_get("tf1.pktgen.port_cfg")
pktgen_app = bfrt_info.table_get("tf1.pktgen.app_cfg")

# sport_value = 1234
src_mac = "00:AA:BB:CC:DD:EE"
dst_mac = "00:EE:DD:CC:BB:AA"
p=Ether(src=src_mac, dst=dst_mac,type=0x8122)/(b'\x01'*50)
p.show()
packet_len = len(p) -6

# Configuring pktgen port
pktgen_port_key = pktgen_port.make_key([gc.KeyTuple('dev_port', 68)])
pktgen_port_action_data = pktgen_port.make_data([gc.DataTuple('pktgen_enable', bool_val=True)])
pktgen_port.entry_mod(target,[pktgen_port_key],[pktgen_port_action_data])

# Configuring pktgen buffer
offset = 0
pktgen_pkt_buf_key = pktgen_buffer.make_key([gc.KeyTuple('pkt_buffer_offset', offset),gc.KeyTuple('pkt_buffer_size', packet_len)])
pktgen_pkt_buf_action_data = pktgen_buffer.make_data([gc.DataTuple('buffer', bytearray(bytes(p)[6:]))])
pktgen_buffer.entry_mod(target,[pktgen_pkt_buf_key],[pktgen_pkt_buf_action_data])

if len(sys.argv) > 1:
    timer = int(sys.argv[1])
else:
    timer = 100

f=open('latency_tf2.txt','w')

packet_loss=0
entries=[i for i in range(100,65000,40)]

while(packet_loss<10):
    # writing some of the latency values to a file
    f.write("For timer ="+str(timer)+"\n")
    print("Timer ="+ str(timer))
    ## Configuring pktgen app
    pktgen_app_key = pktgen_app.make_key([gc.KeyTuple('app_id', 0)])
    pktgen_app_action_data = pktgen_app.make_data([gc.DataTuple('timer_nanosec', timer),
                                                        gc.DataTuple('app_enable', bool_val=True),
                                                        gc.DataTuple('pkt_len', packet_len),
                                                        gc.DataTuple('pkt_buffer_offset', 0),
                                                        gc.DataTuple('pipe_local_source_port', 68),
                                                        gc.DataTuple('increment_source_port', bool_val=False),
                                                        gc.DataTuple('batch_count_cfg', 0),
                                                        gc.DataTuple('packets_per_batch_cfg', 1),
                                                        gc.DataTuple('ibg', 0),
                                                        gc.DataTuple('ibg_jitter', 0),
                                                        gc.DataTuple('ipg', 0),
                                                        gc.DataTuple('ipg_jitter', 0),
                                                        gc.DataTuple('batch_counter', 0),
                                                        gc.DataTuple('pkt_counter', 0),
                                                        gc.DataTuple('trigger_counter', 0)],
                                                        'trigger_timer_periodic')
    pktgen_app.entry_mod(target,[pktgen_app_key],[pktgen_app_action_data])
    print("Packet generation is completed")

    time.sleep(2) # Sleep for 7 seconds

    dev_ports=[port17,port18]
    # Getting the rates
    port_stat_table = bfrt_info.table_get("$PORT_STAT")
    keys = [ port_stat_table.make_key([gc.KeyTuple('$DEV_PORT', dp)])for dp in dev_ports ]
    # data = [port_stat_table.make_data([gc.DataTuple('poll_intv_ms', 2000)])]
    # k1= [port_stat_table.make_key([gc.KeyTuple('$DEV_PORT', port17)]) ]
    # port_stat_table.entry_set_poll_intv_ms(target,'poll_intv_ms' ,2000)# from_hw
    
    resp = list(port_stat_table.entry_get(target, keys, {'from_hw': False}, None))
    # print(resp)
    # for i, res in enumerate(resp):
    data_dict0 = resp[0][0].to_dict()      
    tx_pps_17 = data_dict0['$TX_PPS']
    rx_pps_17 = data_dict0['$RX_PPS']
    tx_rate_17 = data_dict0['$TX_RATE']
    rx_rate_17 = data_dict0['$RX_RATE']

    data_dict1 = resp[1][0].to_dict()
    tx_pps_18 = data_dict1['$TX_PPS']
    rx_pps_18 = data_dict1['$RX_PPS']
    tx_rate_18 = data_dict1['$TX_RATE']
    rx_rate_18 = data_dict1['$RX_RATE']

    print("For port 17, Tx rate = "+str(tx_rate_17)+" Tx Pps = "+str(tx_pps_17))
    print("For port 18, Rx rate = "+str(rx_rate_18)+" Rx Pps = "+str(rx_pps_18))

    # time.sleep(4)

    pktgen_app_action_data=pktgen_app.make_data([gc.DataTuple('app_enable',bool_val=False)])                                            
    pktgen_app.entry_mod(target,[pktgen_app_key],[pktgen_app_action_data])
    print("packet gen is stopped")


    pkt_out = bfrt_info.table_get("pipe.Ingress.reg")
    key = [pkt_out.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])]
    # data = [pkt_count.make_data([gc.DataTuple('SwitchIngress.active.f1', 0)])]

    for data, key in pkt_out.entry_get(target, key, {"from_hw": True}):
        out = data.to_dict()["Ingress.reg.f1"]

    print("The packet out of 1c is",out[0])


    pkt_in = bfrt_info.table_get("pipe.Ingress.reg_2")
    key_2 = [pkt_in.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])]
    # data = [pkt_count.make_data([gc.DataTuple('SwitchIngress.active.f1', 0)])]

    for data, key_2 in pkt_in.entry_get(target, key_2, {"from_hw": True}):
        count = data.to_dict()["Ingress.reg_2.f1"]

    print("The packet in to 1c is",count[0])

    packet_loss=out[0]-count[0]
    # if(packet_loss>1):
    timer=timer-1
        # print("packet loss")

    # making the register count 0 again
    key = [pkt_out.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])]
    data = [pkt_out.make_data([gc.DataTuple("Ingress.reg.f1", 0)])]
    pkt_out.entry_mod(target,key,data)

    key_2 = [pkt_in.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])]
    data = [pkt_in.make_data([gc.DataTuple("Ingress.reg_2.f1", 0)])]
    pkt_in.entry_mod(target,key_2,data)

   

    for i in entries:
        lat = bfrt_info.table_get("pipe.Ingress.latency")
        key_3 = [lat.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])]
        for data, key_3 in lat.entry_get(target, key_3, {"from_hw": True}):
            lat_val = data.to_dict()["Ingress.latency.f1"]
        f.write(str(lat_val[0])+", ")
    
    f.write("\n")

f.close()


# if()
# time.sleep(1) # Sleep for 1 second
# pktgen_app_action_data=pktgen_app.make_data([gc.DataTuple('app_enable',bool_val=True)])                                            
# pktgen_app.entry_mod(target,[pktgen_app_key],[pktgen_app_action_data])
# print("packet gen is stopped")


# If we ever need a forwarding logic at 1c
    # forwarding = bfrt_info.table_get("Ingress.forwarding")
    # forwarding_keys = [
    #     forwarding.make_key([gc.KeyTuple("ig_intr_md.ingress_port", port17)])
    # ]
    # forwarding_data = [
    #     forwarding.make_data(
    #         [gc.DataTuple("egress_port", port18)], "Ingress.set_egress_port"
    #     )
    # ]
    # forwarding.entry_add(target, forwarding_keys, forwarding_data)
    # print("Programmed Forwarding Table")



# target = gc.Target(device_id=0, pipe_id=0xffff)
# global global_grpc_comm_interface
# bfrt_info = global_grpc_comm_interface.bfrt_info_get("tcp_fsm")
# pktgen_buffer = bfrt_info.table_get("tf1.pktgen.pkt_buffer")
# pktgen_port = bfrt_info.table_get("tf1.pktgen.port_cfg")
# pktgen_app = bfrt_info.table_get("tf1.pktgen.app_cfg")

# sport_value = 1234
# iface=ports.CPU_NETWORK_INTERFACE
# src_mac = "00:AA:BB:CC:DD:EE"
# dst_mac = "00:EE:DD:CC:BB:AA"
# p=Ether(src=src_mac, dst=dst_mac)/Dot1Q(vlan=7)/IP(src="42.42.42.42" , dst="1.1.1.1")/TCP(dport=443, sport=sport_value,flags='R')
# p.show()
# packet_len = len(p)
# ## Configuring pktgen port
# pktgen_port_key = pktgen_port.make_key([gc.KeyTuple('dev_port', 68)])
# pktgen_port_action_data = pktgen_port.make_data([gc.DataTuple('pktgen_enable', bool_val=True)])
# pktgen_port.entry_add(target,[pktgen_port_key],[pktgen_port_action_data])
# ## Configuring pktgen buffer
# offset = 0
# pktgen_pkt_buf_key = pktgen_buffer.make_key([gc.KeyTuple('pkt_buffer_offset', offset),gc.KeyTuple('pkt_buffer_size', packet_len)])
# pktgen_pkt_buf_action_data = pktgen_buffer.make_data([gc.DataTuple('buffer', bytearray(bytes(p)))])
# pktgen_buffer.entry_add(target,[pktgen_pkt_buf_key],[pktgen_pkt_buf_action_data])

# ## Configuring pktgen app
# pktgen_app_key = pktgen_app.make_key([gc.KeyTuple('app_id', 0)])
# pktgen_app_action_data = pktgen_app.make_data([gc.DataTuple('timer_nanosec', 500000000),
#                                                     gc.DataTuple('app_enable', bool_val=True),
#                                                     gc.DataTuple('pkt_len', packet_len),
#                                                     gc.DataTuple('pkt_buffer_offset', 0),
#                                                     gc.DataTuple('pipe_local_source_port', 68),
#                                                     gc.DataTuple('increment_source_port', bool_val=False),
#                                                     gc.DataTuple('batch_count_cfg', 0),
#                                                     gc.DataTuple('packets_per_batch_cfg', 1),
#                                                     gc.DataTuple('ibg', 10000),
#                                                     gc.DataTuple('ibg_jitter', 0),
#                                                     gc.DataTuple('ipg', 500),
#                                                     gc.DataTuple('ipg_jitter', 1000),
#                                                     gc.DataTuple('batch_counter', 0),
#                                                     gc.DataTuple('pkt_counter', 0),
#                                                     gc.DataTuple('trigger_counter', 0)],
#                                                     'trigger_timer_periodic')
# pktgen_app.entry_add(target,[pktgen_app_key],[pktgen_app_action_data])


# def connect():
#     # Connect to BfRt Server
#     interface = gc.ClientInterface(grpc_addr='localhost:50052', client_id=0, device_id=0)
#     target = gc.Target(device_id=0, pipe_id=0xFFFF)
#     # print('Connected to BfRt Server!')

#     # Get the information about the running program
#     bfrt_info = interface.bfrt_info_get()
#     # print('The target is running the', bfrt_info.p4_name_get())

#     # Establish that you are working with this program
#     interface.bind_pipeline_config(bfrt_info.p4_name_get())
#     return interface, target, bfrt_info

# def disable(connection):
#     interface = connection[0]
#     target = connection[1]
#     bfrt_info = connection[2]
#     active_reg = bfrt_info.table_get('pipe.SwitchIngress.active')
#     key = [active_reg.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])]
#     data = [active_reg.make_data([gc.DataTuple('SwitchIngress.active.f1', 0)])]
#     active_reg.entry_mod(target, key, data)
#     print('xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')
#     print('OPERATION: Switching is disabled! :(')
#     print('xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')

# def enable(connection):
#     interface = connection[0]
#     target = connection[1]
#     bfrt_info = connection[2]
#     active_reg = bfrt_info.table_get('pipe.SwitchIngress.active')
#     key = [active_reg.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])]
#     data = [active_reg.make_data([gc.DataTuple('SwitchIngress.active.f1', 1)])]
#     active_reg.entry_mod(target, key, data)
#     print('xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')
#     print('OPERATION: Switching is enabled! :D')
#     print('xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')

# def configure(connection, sequence, sess_num):
#     interface = connection[0]
#     target = connection[1]
#     bfrt_info = connection[2]
#     sess_reg = bfrt_info.table_get('pipe.SwitchIngress.session')
#     key = [sess_reg.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])]
#     data = [sess_reg.make_data([gc.DataTuple('SwitchIngress.session.f1', sess_num)])]
#     sess_reg.entry_mod(target, key, data)
#     counter_reg = bfrt_info.table_get('pipe.SwitchIngress.counter')
#     key = [counter_reg.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])]
#     data = [counter_reg.make_data([gc.DataTuple('SwitchIngress.counter.f1', sequence)])]
#     counter_reg.entry_mod(target, key, data)
#     print('xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')
#     print('OPERATION: Updated session number to ' + str(sess_num) + ' and message sequence number to ' + str(sequence))
#     print('xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')


# def main():
#     parser1 = argparse.ArgumentParser()
#     group = parser1.add_mutually_exclusive_group()
#     group.add_argument(
#         '--disable', default=False, action='store_true',
#         help='disable switch forwarding'
#     )
#     group.add_argument(
#         '--enable', default=False, action='store_true',
#         help='enable switch forwarding'
#     )
#     parser2 = argparse.ArgumentParser()
#     subparsers = parser2.add_subparsers()
#     subparser1 = subparsers.add_parser('config')

#     subparser1.add_argument(

#         '--sequence', type=int, default=1, required=True,

#         help='specify starting message sequence number'

#     )

#     subparser1.add_argument(

#         '--session', type=int, default=0, required=True,

#         help='specify current session number'

#     )

#     args, extras = parser1.parse_known_args()
#     to_disable = args.disable
#     to_enable = args.enable
    
#     if to_disable or to_enable:

#         pprint(args)

#         if len(extras) > 0:

#             print('PARSER: Remaining arguments are omitted.')

#     else:

#         if len(extras) > 0 and extras[0] in ['config']:

#             args = parser2.parse_args(extras, namespace=args)

#             pprint(args)

#     sequence = args.sequence if 'sequence' in args else None

#     sess_num = args.session if 'session' in args else None

#     if to_disable:

#         disable(connect())

#         return

#     if to_enable:

#         enable(connect())

#         return

#     if not sequence == None and not sess_num == None:

#         configure(connect(), sequence, sess_num)

#         return

#     print('Nothing was done. :)')

# if __name__ == '__main__':
#     main()
