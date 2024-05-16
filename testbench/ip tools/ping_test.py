import subprocess

def perform_ping_test(host):
    # Run the ping command
    # result = subprocess.run(['ping', '-c', '1', host], capture_output=True, text=True)
    result = subprocess.Popen(['ping', host], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    
    count = 0
    for line in result.stdout:
        count += 1
        if (count >= 3):
            # print(">>> " + line.strip())
            if ("timeout" in line or "failure" in line):
                result.terminate()
                return False
            else:
                result.terminate()
                return True

if __name__ == "__main__":
    # Perform the ping test
    host = input("Enter the remote IP address to ping: ")
    ping_success = perform_ping_test(host)

    # Display the result
    if ping_success:
        print(f"Ping test to {host} was successful!")
    else:
        print(f"Ping test to {host} failed.")

