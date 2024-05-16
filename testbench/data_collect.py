import os
from selenium import webdriver
from time import sleep
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import subprocess
import shutil
import sys
import psutil


def browser_init(download_dir):  # initialize the browser
    options = webdriver.ChromeOptions()
    options.page_load_strategy = 'eager'  # "eager" for faster loading
    options.add_experimental_option('excludeSwitches', ['enable-logging'])
    options.add_argument("use-fake-device-for-media-stream")
    options.add_argument("use-fake-ui-for-media-stream")
    prefs = {"download.default_directory": download_dir}
    options.add_experimental_option("prefs", prefs)
    browser = webdriver.Chrome(options=options)
    return browser


def app_init(browser, app_link):  # initialize the app
    browser.get(app_link)  # open the app
    app_window = browser.current_window_handle
    return app_window


def webrtc_internals_init(browser):  # initialize the webrtc-internals page
    # create a new tab for webrtc-internals and switch to it
    browser.switch_to.new_window('tab')
    browser.get("chrome://webrtc-internals")
    browser.implicitly_wait(1)  # wait for elements to load
    print("WebRTC-internals page is loaded.")
    rtc_window = browser.current_window_handle
    return rtc_window


def tshark_init(tshark_dir, interface, traffic_dir):
    command = [tshark_dir, '-i', interface, '-w', traffic_dir]
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("Start tshark process...")
    return process


def terminate_call(browser, process, rtc_window, download_btn_xpath1, download_btn_xpath2, download_dir, new_dump_name, old_dump_name):
    browser.switch_to.window(rtc_window)
    browser.find_element(By.XPATH, download_btn_xpath1).click()
    browser.find_element(By.XPATH, download_btn_xpath2).click()
    sleep(3)  # wait for download to finish
    print("The dump file is downloaded.")
    os.rename(download_dir + old_dump_name,
              download_dir + new_dump_name)
    if (tshark_terminate(process)):
        print("The captured traffic is saved.")
    else:
        print("Error: can't terminate tshark process.")
    browser.quit()


def tshark_terminate(process):
    process.terminate()
    print("Terminating tshark process...")
    sleep(3)
    if process.poll() is not None:
        # Process has terminated
        returncode = process.returncode
        print("Process has terminated with return code:", returncode)
        return True
    else:
        # Process is still running
        print("Process is still running")
        return False


def identify_os():
    if sys.platform.startswith('win'):
        return 'Windows'
    elif sys.platform.startswith('darwin'):
        return 'Mac OS'
    elif sys.platform.startswith('linux'):
        return 'Linux'
    else:
        return 'Unknown'


def get_most_active_interface():
    interfaces = psutil.net_io_counters(pernic=True)
    most_active_interface = None
    max_bytes_sent = 0

    for interface, stats in interfaces.items():
        bytes_sent = stats.bytes_sent
        bytes_recv = stats.bytes_recv
        if (bytes_sent == bytes_recv):
            continue
        if (bytes_sent > max_bytes_sent):
            max_bytes_sent = bytes_sent
            most_active_interface = interface

    return most_active_interface


if __name__ == "__main__":
    if (os.system('clear') == 1):
        os.system('cls')

    ans = input("Select your role (1: caller / 2: receiver): ")
    while (ans != '1' and ans != '2'):
        ans = input("Select your role (1: caller / 2: receiver): ")
    if (ans == '1'):
        print("You are the caller.")
        role = "caller"
    else:
        print("You are the receiver.")
        role = "receiver"

    download_btn_xpath1 = "/html/body/p/details/summary"
    download_btn_xpath2 = "/html/body/p/details/div/div[1]/a/button"
    if (identify_os() == 'Windows'):
        with open('tshark_location.txt', 'r') as file:
            tshark_dir = file.read().strip()
        divider = "\\"
    elif (identify_os() == 'Mac OS'):
        tshark_dir = "tshark"
        divider = "/"
    base_dir = os.path.dirname(os.path.abspath(
        __file__))  # get the current directory
    download_dir = base_dir + divider + "data"
    old_dump_name = divider + "webrtc_internals_dump.txt"
    new_dump_name = divider + "dump_" + role + ".txt"
    traffic_dir = download_dir + divider + "packets_" + role + ".pcapng"

    interface = get_most_active_interface()
    if interface is None:
        print("No active interface found.")
        exit(1)
    app_link = "https://discord.com/channels/@me"
    # app_link = "https://www.messenger.com/login/"

    shutil.rmtree(download_dir, ignore_errors=True)
    os.mkdir(download_dir)  # create a new download folder
    browser = browser_init(download_dir)
    app_window = app_init(browser, app_link)
    rtc_window = webrtc_internals_init(browser)
    process = tshark_init(tshark_dir, interface, traffic_dir)
    browser.switch_to.window(app_window)
    print("Ready to collect call data...\n")

    ans = input("Enter q if the call is end: ")
    while (ans != 'q'):
        ans = input("Enter q if the call is end: ")

    terminate_call(browser, process, rtc_window, download_btn_xpath1,
                   download_btn_xpath2, download_dir, new_dump_name, old_dump_name)
