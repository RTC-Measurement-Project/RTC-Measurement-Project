import wireshark_extract
import os
import sys


def identify_os():
    if sys.platform.startswith('win'):
        return 'Windows'
    elif sys.platform.startswith('darwin'):
        return 'Mac OS'
    elif sys.platform.startswith('linux'):
        return 'Linux'
    else:
        return 'Unknown'


base_dir = os.path.dirname(os.path.abspath(
    __file__))  # get the current directory

if (identify_os() == 'Windows'):
    divider = "\\"
elif (identify_os() == 'Mac OS'):
    divider = "/"

with open('tshark_location.txt', 'r') as file:
    tshark_dir = file.read().strip()

# https://gitlab.com/wireshark/wireshark/-/issues/19113
input_path = base_dir + divider + "inputs" + divider
file_name = input_path + 'packets_caller.pcapng'
out_name = "test.json"
stun_filter = 'stun'
wireshark_profile = "WebRTC"
add_arg = "-NNnd -C " + wireshark_profile
caller_json = wireshark_extract.get_packet_json(
    file_name, out_name, stun_filter, add_arg)
