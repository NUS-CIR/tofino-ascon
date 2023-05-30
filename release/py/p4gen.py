import argparse
import json
import jinja2
import math

# class SetModelAction(argparse.Action):
#     def __call__(self, parser, namespace, values, option_string=None):
#         print(option_string)
#         if option_string == '--tf1_rpp':
#             setattr(namespace, 'tofino_model', 1)
#         elif option_string == '--tf2_rpp':
#             setattr(namespace, 'tofino_model', 2)
parser = argparse.ArgumentParser(description="ASCON Parser")

parser.add_argument("template_filename", metavar="template_filename", type=str,
                    help="Filename for input Jinja/P4 template.")

parser.add_argument("P4_filename", metavar="P4_filename", type=str,
                    help="Filename for output P4 data plane program.")

# parser.add_argument('tofino_model', metavar="model",type=int, choices=[1, 2], help='Tofino Model (1 or 2)')

# # Add the "rounds_per_pass" argument with conditional choices


# group = parser.add_mutually_exclusive_group()
# group.add_argument('--tf1_rpp', dest='rpp', type=int, action=SetModelAction, choices=[1, 2], help='Rounds per pass for Tofino 1')
# group.add_argument('--tf2_rpp', dest='rpp', type=int, action=SetModelAction, choices=[1, 2, 3, 4], help='Rounds per pass for Tofino 2')


parser.add_argument('tofino_model', metavar="model", choices=['tf1', 'tf2'],
    help='Tofino Model (tf1 or tf2)')

parser.add_argument('rpp', metavar="rpp", type=int, help='Rounds per pass')
# Add payload size
parser.add_argument('payload_size',metavar="payload", type=int, choices=[8, 16, 24, 32], help='Payload size (8, 16, 24, or 32 bytes)')

# Parse the arguments
args = parser.parse_args()

if(args.tofino_model == 'tf1'):
    args.tofino_model= 1
else:
    args.tofino_model= 2   
    
print("model", args.tofino_model)
print("rpp", args.rpp)
print("payload", int(args.payload_size/8))

# Validate the arguments based on the tofino_model
if args.tofino_model == 1 and args.rpp not in [1, 2]:
    parser.error('For Tofino Model 1, rounds per pass can only be 1 or 2')
elif args.tofino_model == 2 and args.rpp not in [1, 2, 3, 4]:
    parser.error('For Tofino Model 2, rounds per pass can be 1, 2, 3, or 4')

with open(args.template_filename,'r') as f:
    template_txt=f.read()
    t = jinja2.Template(template_txt,  trim_blocks=True, lstrip_blocks=True)

# Adding the arguments to render the Jinja file int((args.payload_size)/8)
output = (t.render(model=args.tofino_model,rpp=args.rpp, payload_byte= int((args.payload_size)/8)))

with open(args.P4_filename, 'w') as f:
    f.write(output)
    

# if args.verbose:
print("Generated P4 source, %d lines. Successfully saved to %s"%(len(output.split("\n")),args.P4_filename))