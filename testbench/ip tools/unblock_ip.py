# For MacOS: need to run with "sudo python unblock_ip.py"
# For Windows: need to run vscode or cmd as administrator

import os
import sys
import subprocess


def unblock_ip_mac(ip):
    # Read the contents of the file into a list
    with open('/etc/pf.conf', 'r') as file:
        old_lines = file.readlines()

    # Remove the last line that matches the specific text
    target_line = f'block drop from any to {ip}'
    new_lines = [line for line in old_lines if not line.strip() == target_line]
    if (old_lines == new_lines):
        print(f"\n\"{target_line.strip()}\" is not found in /etc/pf.conf\n")
    else:
        print(f"\n\"{target_line.strip()}\" is removed from /etc/pf.conf\n")

    # Write the modified list back to the file
    with open('/etc/pf.conf', 'w') as file:
        file.writelines(new_lines)

    cmd1 = "sudo pfctl -f /etc/pf.conf"
    cmd2 = "sudo pfctl -e"
    os.system(cmd1)
    # print(f">>> \"{cmd1}\" is executed to load PF config\n")
    os.system(cmd2)
    # print(f">>> \"{cmd2}\" is executed to enable PF config\n")


def unblock_ip_win(ip):
    try:
        # Execute netsh command to add a firewall rule
        command = f"netsh advfirewall firewall delete rule name=\"BLOCK IP ADDRESS - {ip}\" remoteip={ip}"
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
    
def unblock_ip(ip):
    if (identify_os() == 'Windows'):
        unblock_ip_win(ip)
    elif (identify_os() == 'Mac OS'):
        unblock_ip_mac(ip)


if __name__ == "__main__":
    ip = input('Enter the remote IP address to unblock: ')
    unblock_ip(ip)
