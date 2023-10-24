# tofino-ascon
This is the P4 implementation of the ASCON-AEAD(reference C code in [ascon-aead](https://github.com/khooi8913/tofino-ascon/tree/release/ascon-aead/c-src)).

The 1a and 1c folders in [experiments](https://github.com/khooi8913/tofino-ascon/tree/release/experiments) include copy of the files used on the h/w switches for testing.

[Release](https://github.com/khooi8913/tofino-ascon/tree/release/release) contains the jinja templates(doesn't correctly generate for 32 byte input cases yet) for different ASCON configurations.

[AD](https://github.com/khooi8913/tofino-ascon/tree/release/AD) and [scale](https://github.com/khooi8913/tofino-ascon/tree/release/scale) include the P4 implmentations with different AD lengths and different recirc ports resp.

## Note

This repo is under construction and clean up. 
We expect to perform a proper release later this year after EuroP4, which will be tagged.
We thank you for your patience.
