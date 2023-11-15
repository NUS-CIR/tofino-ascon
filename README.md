# tofino-ascon

This is the P4 implementation of the ASCON-AEAD(reference C code in [ascon-aead](https://github.com/khooi8913/tofino-ascon/tree/euro-p4/ascon-aead/c-src)).

[release](https://github.com/khooi8913/tofino-ascon/tree/euro-p4//release) contains the jinja templates(doesn't correctly generate for 32 byte input cases yet) for different ASCON configurations.

The 1a and 1c folders in [experiments](https://github.com/khooi8913/tofino-ascon/tree/euro-p4//experiment_setup) include copy of the files used on the h/w switches for testing.

[ad](https://github.com/khooi8913/tofino-ascon/tree/euro-p4/reference_p4_index/ad) and [scale](https://github.com/khooi8913/tofino-ascon/tree/euro-p4/reference_p4_index/scale) include the pre-generated P4 implmentations with different AD lengths and different recirc ports resp.

## Note

This repo is under construction and clean up. 
We expect to perform a proper release later this year after EuroP4, which will be tagged.
We thank you for your patience.
