import block_ip
import unblock_ip
import get_local_ip
import ping_test
import time
import threading
import os
import ast
import ipaddress


def check_ip_address_type(ip_address):
    try:
        ip = ipaddress.ip_address(ip_address)
        if ip.is_private:
            return "Private"
        else:
            return "Public"
    except ValueError:
        return "Invalid IP address"


def is_ipv6(address):
    # if ('%' in address):
    #     return  False
    try:
        ip = ipaddress.ip_address(address)
        return ip.version == 6
    except ValueError:
        return False


def is_ipv4(address):
    try:
        ip = ipaddress.ip_address(address)
        return ip.version == 4
    except ValueError:
        return False


max_time = 1000  # seconds
most_active_interface = get_local_ip.get_active_interface()

if (os.system('clear') == 1):
    os.system('cls')

ipv4_address = get_local_ip.get_ipv4_address(most_active_interface)
ipv6_address = get_local_ip.get_ipv6_address(most_active_interface)
ipv4_list = get_local_ip.get_ipv4_list()
ipv6_list = get_local_ip.get_ipv6_list()
print(f"[ Local IPv4 Addresses ] | [ Local IPv6 Addresses ]: \n\n{ipv4_list} | {ipv6_list}\n")


ip_string = input('Enter [ Remote IPv4 Addresses ] | [ Remote IPv6 Addresses ] to block: ')
ipv4, ipv6 = ip_string.split('|')
ipv4 = ast.literal_eval(ipv4)
ipv6 = ast.literal_eval(ipv6)
for i in range(len(ipv4)-1, -1, -1):
    ip = ipv4[i]
    if (is_ipv4(ip) == False):
        print(f"\"{ip}\" is not valid")
        ipv4.remove(ip)
for i in range(len(ipv6)-1, -1, -1):
    ip = ipv6[i]
    if (not is_ipv6(ip) or check_ip_address_type(ip) != "Public"):
        print(f"\"{ip}\" is not valid")
        ipv6.remove(ip)

all_ip = ipv4 + ipv6
print(all_ip)

print("\n[Test IP 1]----------------------------------------\n")

for ip in all_ip:
    test1 = ping_test.perform_ping_test(ip)
    if (test1 == True):
        print(f"Ping test to {ip} was successful!")
    else:
        print(f"Ping test to {ip} failed.")

print("\n[Block IP]----------------------------------------\n")

for ip in all_ip:
    block_ip.block_ip(ip)

print("\n[Test IP 2]----------------------------------------\n")

for ip in all_ip:
    test2 = ping_test.perform_ping_test(ip)
    if (test2 == True):
        print(f"Ping test to {ip} was successful!")
    else:
        print(f"Ping test to {ip} failed.")

print("\n[Waiting]----------------------------------------\n")


def timer(stop_event, max_time, current_time):
    t = 0
    while t < max_time and not stop_event.is_set():
        print(f"Time left: {max_time - t} seconds", end="\r")
        t += 1
        current_time[0] = t
        time.sleep(1)  # Delay of 1 second between counts

    if not stop_event.is_set():
        print(f"Time used: {t} seconds")

        print("\n[Unblock IP]----------------------------------------\n")

        for ip in all_ip:
            unblock_ip.unblock_ip(ip)

        print("\n[Test IP 3]----------------------------------------\n")

        for ip in all_ip:
            test3 = ping_test.perform_ping_test(ip)
            if (test3 == True):
                print(f"Ping test to {ip} was successful!")
            else:
                print(f"Ping test to {ip} failed.")
        os._exit(1)


def manual_stop_timer(stop_event, t):
    # time.sleep(1)
    user_input = input(f"Enter 'q' to unblock: \n")
    print(f"Your input was: {user_input}")
    while (user_input != 'q'):
        user_input = input("Enter 'q' to unblock: \n")
        print(f"Your input was: {user_input}")
    stop_event.set()
    print(f"Time used: {t[0]} seconds")

    print("\n[Unblock IP]----------------------------------------\n")

    for ip in all_ip:
        unblock_ip.unblock_ip(ip)

    print("\n[Test IP 3]----------------------------------------\n")

    for ip in all_ip:
        test3 = ping_test.perform_ping_test(ip)
        if (test3 == True):
            print(f"Ping test to {ip} was successful!")
        else:
            print(f"Ping test to {ip} failed.")
    os._exit(1)


current_time = [None]
stop_event = threading.Event()
count_thread = threading.Thread(
    target=timer, args=(stop_event, max_time, current_time))
input_thread = threading.Thread(
    target=manual_stop_timer, args=(stop_event, current_time))
input_thread.start()
count_thread.start()
