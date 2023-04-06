all:
	~/tools/p4_build.sh ascon_switch.p4

tf1-aead:
	~/tools/p4_build.sh ascon_switch.p4 -DAEAD

tf1-aead-16b:
	~/tools/p4_build.sh ascon_switch.p4 -DAEAD -DPAYLOAD_16B

tf1-aead-32b:
	~/tools/p4_build.sh ascon_switch.p4 -DAEAD -DPAYLOAD_32B

tf2:
	~/tools/p4_build.sh ascon_switch.p4 --with-tofino2

tf2-aead:
	~/tools/p4_build.sh ascon_switch.p4 --with-tofino2 -DAEAD

tf2-aead-16b:
	~/tools/p4_build.sh ascon_switch.p4 --with-tofino2 -DAEAD -DPAYLOAD_16B

tf2-aead-32b:
	~/tools/p4_build.sh ascon_switch.p4 --with-tofino2 -DAEAD -DPAYLOAD_32B