import re
import ipaddress
import os
import sys
import geoip2.database


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


def is_ipv4(text):
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ipv4_addresses = re.findall(ipv4_pattern, text)
    if ipv4_addresses:
        return True
    else:
        return False


def is_ipv6(text):
    ipv6_pattern = r'\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b|\b(?:[0-9A-Fa-f]{1,4}:){0,6}(?:(?:[0-9A-Fa-f]{1,4}:){1,6})?:[0-9A-Fa-f]{1,4}\b'
    ipv6_addresses = re.findall(ipv6_pattern, text)
    if ipv6_addresses:
        return True
    else:
        return False


def generate_display_filter(ip_addresses):
    display_filter = ''
    for ip_address in ip_addresses:
        if display_filter:
            display_filter += ' or '
        if (is_ipv4(ip_address)):
            display_filter += f'ip.src == {ip_address} or ip.dst == {ip_address}'
        elif (is_ipv6(ip_address)):
            display_filter += f'ipv6.src == {ip_address} or ipv6.dst == {ip_address}'
    return display_filter


def generate_simple_display_filter(ip_addresses):
    display_filter = ''
    for ip_address in ip_addresses:
        if display_filter:
            display_filter += ' or '
        if (is_ipv4(ip_address)):
            display_filter += f'ip.addr == {ip_address}'
        elif (is_ipv6(ip_address)):
            display_filter += f'ipv6.addr == {ip_address}'
        else:
            raise ValueError(f'Invalid IP address: {ip_address}')
    return display_filter


def check_ip_address_type(ip_address):
    try:
        ip = ipaddress.ip_address(ip_address)
        if ip.is_private:
            return "Private"
        else:
            return "Public"
    except ValueError:
        return "Invalid IP address"


def no_private_ip(ip_addresses):
    ip = []
    for ip_address in ip_addresses:
        if check_ip_address_type(ip_address) == "Public":
            ip.append(ip_address)
    return ip


def read_file_into_list(file_path):
    lines_list = []
    with open(file_path, 'r') as file:
        for line in file:
            lines_list.append(line.strip())
    return lines_list


def get_ip_company(ip):
    # Replace with the actual path to your GeoLite2-ASN database file
    reader = geoip2.database.Reader('GeoLite2-ASN.mmdb')
    try:
        response = reader.asn(ip)
        asn = response.autonomous_system_organization
        return asn
    except geoip2.errors.AddressNotFoundError:
        return "Not found"


if __name__ == "__main__":
    file_path = base_dir + divider + 'ip_addresses.txt'
    ip_list = read_file_into_list(file_path)
    print("{} IP addresses.".format(len(ip_list)))
    
    # Function 1: get filter code for only public IP addresses in the list
    # new_ip_list = no_private_ip(ip_list)
    # filter_code = generate_display_filter(new_ip_list)
    # print(f'\n{filter_code}\n')

    # Function 2: get filter code for all IP addresses in the list
    filter_code = generate_simple_display_filter(ip_list)
    print(f'\n({filter_code})\n')

    # Function 3: get company name for each IP address in the list
    # for ip in ip_list:
    #     print(f'{get_ip_company(ip)}: {ip}')
