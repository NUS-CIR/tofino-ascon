# input format -- <template_filename> <gen_P4_filepath> <tofino_model> <rounds/pass> <payload_size(bytes)> 
python3 p4gen.py p4src/ascon.p4template p4src/gen/ascon.p4 --tf1 1 1 8