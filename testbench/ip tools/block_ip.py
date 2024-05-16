# For MacOS: need to run with "sudo python block_ip.py"
# For Windows: need to run vscode or cmd as administrator

import os
import sys
import subprocess


def block_ip_mac(ip):
    with open('/etc/pf.conf', 'a') as file:
        line = f'block drop from any to {ip}\n'
        print(f"\n\"{line.strip()}\" is added to /etc/pf.conf\n")
        file.write(line)

    cmd1 = "sudo pfctl -f /etc/pf.conf"
    cmd2 = "sudo pfctl -e"
    os.system(cmd1)
    # print(f">>> \"{cmd1}\" is executed to load PF config\n")
    os.system(cmd2)
    # print(f">>> \"{cmd2}\" is executed to enable PF config\n")


def block_ip_win(ip):
    try:
        # Execute netsh command to add a firewall rule
        command = f"netsh advfirewall firewall add rule name=\"BLOCK IP ADDRESS - {ip}\" dir=out action=block remoteip={ip}"
        subprocess.run(command, shell=True, check=True)
        # print(f"Blocked traffic to {ip}")
    except subprocess.CalledProcessError as e:
        print(f"Error blocking traffic to {ip}: {e}")


def identify_os():
    if sys.platform.startswith('win'):
        return 'Windows'
    elif sys.platform.startswith('darwin'):
        return 'Mac OS'
    elif sys.platform.startswith('linux'):
        return 'Linux'
    else:
        return 'Unknown'
    
def block_ip(ip):
    if (identify_os() == 'Windows'):
        block_ip_win(ip)
    elif (identify_os() == 'Mac OS'):
        block_ip_mac(ip)


if __name__ == "__main__":
    ip = input('Enter the remote IP address to block: ')
    block_ip(ip)
