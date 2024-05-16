import netifaces


def get_active_interface():
    gateways = netifaces.gateways()
    default_gateway = gateways['default']

    for interface, details in default_gateway.items():
        if details[1] is not None:
            return details[1]

    return None


def get_ipv4_address(interface):
    addresses = netifaces.ifaddresses(interface)[netifaces.AF_INET]
    return addresses[0]['addr'] if addresses else None


def get_ipv6_address(interface):
    addresses = netifaces.ifaddresses(interface)[netifaces.AF_INET6]
    return addresses[0]['addr'] if addresses else None


def get_ipv4_list():
    ipv4_addresses = []
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        try:
            addresses = netifaces.ifaddresses(interface)[netifaces.AF_INET]
            ipv4_addresses.extend(address['addr'] for address in addresses)
        except KeyError:
            pass
    return ipv4_addresses


def get_ipv6_list():
    ipv6_addresses = []
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        try:
            addresses = netifaces.ifaddresses(interface)[netifaces.AF_INET6]
            ipv6_addresses.extend(address['addr'] for address in addresses)
        except KeyError:
            pass
    return ipv6_addresses


if __name__ == "__main__":
    most_active_interface = get_active_interface()
    ipv4_address = get_ipv4_address(most_active_interface)
    ipv6_address = get_ipv6_address(most_active_interface)

    print("Most active interface:", most_active_interface)
    print("IPv4 address:", ipv4_address)
    print("IPv6 address:", ipv6_address)
