# tofino-ascon
This is the P4 implementation of the ASCON-AEAD(reference C code in ## ascon-aead)
The 1a and 1c folders in ##experiments include copy of the files used on the h/w switches for testing.
##release contains the jinja templates(doesn't correctly generate for 32 byte input cases yet) for different ASCON configurations
##ad and ##scale include the P4 implmentations with different AD lengths and different recirc ports resp.
