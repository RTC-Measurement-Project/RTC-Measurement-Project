import os
from selenium import webdriver
import time
from time import sleep
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select
import subprocess
import shutil
import sys

app_link = "https://www.messenger.com/login/"


def browser_init(download_dir):  # initialize the browser
    options = webdriver.ChromeOptions()
    options.page_load_strategy = 'eager'  # "eager" for faster loading
    options.add_argument("use-fake-device-for-media-stream")
    options.add_argument("use-fake-ui-for-media-stream")
    prefs = {"download.default_directory": download_dir}
    options.add_experimental_option("prefs", prefs)
    browser = webdriver.Chrome(options=options)
    return browser


def app_init(browser, receiver_tab_xpath):  # initialize the app
    # check if password_caller.txt exists. if exists, read username and password from it
    if os.path.exists("password_caller.txt"):
        with open("password_caller.txt", "r") as f:
            myusername = f.readline()
            mypassword = f.readline()
        if len(myusername) == 0 or len(mypassword) == 0:
            print("Error: password_caller.txt is not in the correct format.")
            return
    # if not, ask user to input username and password and save them to password_caller.txt
    else:
        myusername = input("Enter username: ")
        mypassword = input("Enter password: ")
        with open("password_caller.txt", "w") as f:
            f.write(myusername + "\n")
            f.write(mypassword + "\n")

    browser.get(app_link)  # open the app
    browser.implicitly_wait(1)  # wait for elements to load
    browser.find_element(By.ID, "email").send_keys(myusername)
    browser.find_element(By.ID, "pass").send_keys(mypassword)
    browser.find_element(By.ID, "loginbutton").click()
    caller_window = browser.current_window_handle
    print("Loading caller page...")
    while (not hasElement(browser, receiver_tab_xpath)):
        pass
    browser.find_element(By.XPATH, receiver_tab_xpath).click()
    print("Caller page is loaded.")

    return caller_window


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


def call_out_init(browser, caller_window, call_btn_xpath, receiver_name_xpath):
    browser.switch_to.window(caller_window)
    print("Start calling...")
    browser.find_element(By.XPATH, call_btn_xpath).click()
    windows = browser.window_handles
    call_window = windows[2]  # record the popup window

    browser.switch_to.window(call_window)
    # wait for the call window to be fully loaded
    while (not hasElement(browser, receiver_name_xpath)):
        pass
    browser.implicitly_wait(1)  # wait for elements to load
    print("Waiting for the call to be answered...")
    return call_window


def is_call_timeout(browser, timeout, call_window, waiting_sign_xpath):
    browser.switch_to.window(call_window)
    start = time.time()
    while (hasElement(browser, waiting_sign_xpath)):
        end = time.time()
        print("The call has been ringing for " +
              str(end - start) + " seconds.", end="\r")
        if ((end - start) > timeout):
            print("\nThe call is timeout for " + str(timeout) + " seconds.")
            return True
    print("")
    return False  # the call is not timeout but might be received or refused


def is_call_refused(browser, call_window, close_call_btn_xpath):
    browser.switch_to.window(call_window)
    if (hasElement(browser, close_call_btn_xpath)):
        browser.find_element(By.XPATH, close_call_btn_xpath).click()
        print("The call is refused.")
        return True
    return False


def call_control(browser, call_duration, call_window, receiver_icon_xpath, recall_btn_xpath, end_call_btn_xpath):
    browser.switch_to.window(call_window)
    while (not hasElement(browser, receiver_icon_xpath)):  # wait for the call box to be fully loaded
        pass
    print("The call is answered.")

    start = time.time()
    while (True):
        end = time.time()
        print("The call has been connected for " +
              str(end - start) + " seconds.", end="\r")
        hasRecall = hasElement(browser, recall_btn_xpath)
        if (((end - start) > call_duration) or hasRecall):
            if (not hasRecall):
                browser.find_element(By.XPATH, end_call_btn_xpath).click()
            print("\nThe call is ended.")
            return


def terminate_call_success(browser, process, rtc_window, download_btn_xpath1, download_btn_xpath2, download_dir, dump_name):
    browser.switch_to.window(rtc_window)
    browser.find_element(By.XPATH, download_btn_xpath1).click()
    browser.find_element(By.XPATH, download_btn_xpath2).click()
    sleep(3)  # wait for download to finish
    print("The dump file is downloaded.")
    os.rename(download_dir + "\\webrtc_internals_dump.txt",
              download_dir + dump_name)

    if (tshark_terminate(process)):
        print("The captured traffic is saved.")
    else:
        print("Error: can't terminate tshark process.")

    print("Complete a sucessful call!")
    browser.quit()


def terminate_call_failure(browser, process, traffic_dir):
    if (tshark_terminate(process)):
        pass
    else:
        print("Error: can't terminate tshark process.")
    try:
        os.remove(traffic_dir)
        print("The captured traffic is deleted.")
    except FileNotFoundError:
        print(f"File {traffic_dir} not found")
    except OSError as e:
        print(f"Error occurred while deleting {traffic_dir}: {e}")

    print("The call fails.")
    browser.quit()

# The followings are internal functions


def hasElement(browser, xpath):  # check if an element exists
    try:
        browser.find_element(By.XPATH, xpath)
    except:
        return False
    return True


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


if __name__ == "__main__":
    timeout = 20  # set timeout
    call_duration = 10  # set call duration
    call_success = False
    interface = "WLAN"

    receiver_tab_xpath = "/html/body/div[1]/div/div/div/div[2]/div/div/div/div[1]/div[1]/div[1]/div/div[2]/div/div/div/div/div[3]/div/div/div/div/div[2]/div/div/div/div/a"
    call_btn_xpath = "/html/body/div[1]/div/div/div/div[2]/div/div/div/div[1]/div[1]/div[2]/div/div/div/div/div/div/div[1]/div/div[2]/div/div[1]/span/div"
    download_btn_xpath1 = "/html/body/p/details/summary"
    download_btn_xpath2 = "/html/body/p/details/div/div[1]/a/button"
    receiver_name_xpath = "/html/body/div/div/div/div/div/div/div/div/div/div[1]/div/div[1]/div/div/div/div/div[1]/div/div/div[2]/div/div/div/div[2]/div/div[1]/span"
    receiver_icon_xpath = "/html/body/div/div/div/div/div/div/div/div/div/div[1]/div/div[1]/div/div/div/div/div[1]/div/div/div[2]/div/div/div/div/div/div/div[1]/div[2]/div[1]/div/img"
    waiting_sign_xpath = "/html/body/div/div/div/div/div/div/div/div/div/div[1]/div/div[1]/div/div/div/div/div[1]/div/div/div[2]/div/div/div/div[2]/div/div[2]/span/span"
    end_call_btn_xpath = "/html/body/div/div/div/div/div/div/div/div/div/div[1]/div/div[1]/div/div/div/div/div[1]/div/div/div[3]/div/div[1]/div[2]/div/div/div[2]/div[5]/span/div/div/div"
    close_call_btn_xpath = "/html/body/div/div/div/div/div/div/div/div/div/div[1]/div/div[1]/div/div/div[3]/div/div[1]/div[2]/div/div/div[2]/div[2]/button"
    recall_btn_xpath = "/html/body/div/div/div/div/div/div/div/div/div/div[1]/div/div[1]/div/div/div[1]/div/div/div/div[2]/div/div/button"

    if (identify_os() == 'Windows'):
        tshark_dir = "D:\\Wireshark\\tshark"
    elif (identify_os() == 'Mac OS'):
        tshark_dir = "tshark"
    # base_dir = "C:\\Users\\Sam\\Desktop\\WebRTC_Testbench"
    base_dir = os.path.dirname(os.path.abspath(
        __file__))  # get the current directory
    download_dir = base_dir + "\\data"
    dump_name = "\\webrtc_dump_caller.txt"
    traffic_dir = download_dir + "\\captured_traffic_caller.pcapng"

    start = time.time()

    # delete the download folder
    shutil.rmtree(download_dir, ignore_errors=True)
    os.mkdir(download_dir)  # create a new download folder
    browser = browser_init(download_dir)
    caller_window = app_init(browser, receiver_tab_xpath)
    rtc_window = webrtc_internals_init(browser)
    process = tshark_init(tshark_dir, interface, traffic_dir)
    call_window = call_out_init(browser, caller_window,
                                call_btn_xpath, receiver_name_xpath)
    if ((not is_call_timeout(browser, timeout, call_window, waiting_sign_xpath)) and (not is_call_refused(browser, call_window, close_call_btn_xpath))):
        call_control(browser, call_duration, call_window,
                     receiver_icon_xpath, recall_btn_xpath, end_call_btn_xpath)
        terminate_call_success(browser, process, rtc_window, download_btn_xpath1,
                               download_btn_xpath2, download_dir, dump_name)
    else:
        terminate_call_failure(browser, process, traffic_dir)

    end = time.time()
    print("Run time: ", end - start)
