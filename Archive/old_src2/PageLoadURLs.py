#!/bin/env/python3
#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~# IMPORTS #~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#
import pandas, argparse, json, netifaces as ni, time
from subprocess import Popen
from threading import RLock
from datetime import datetime
from traceback import print_exc
from uuid import uuid4

# selenium imports
from colorama import init, Fore
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

# in-project imports
from network_condition import *
from algo import analyze_pcap

from analisys_threading import thread_func



#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~# GLOBALS #~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#
version = 2

init()
RED = Fore.RED
CYAN = Fore.CYAN
GREEN = Fore.GREEN
BLUE = Fore.BLUE
RESET = Fore.RESET

# Dictionary to turn into dataframe to turn intu CSV file
df_dict = {
    # '': [],
    'experiment_id': [],
    'url': [],
    'pcap_name': [],
    'loss': [],
    'latency': [],
    'throughput_bytes': [],
    'browser_onLoad_time': [],
    'time_delta': [],
    'label': []
}

# global lock for concurrent data logging
lock = RLock()

#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~# ARGS #~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#
def get_args():
    parser = argparse.ArgumentParser(
        prog='sudo python3 PageLoadURLs.py [Options]',
        description='A Research Program That Opens URLs (Given in a CSV File),'
                    ' Calculates and Stores the Timing Values in a CSV file',
        epilog='Created by Daniel Lisachuk for FlashNetworks QoE Project'
    )

    parser.add_argument('-i', '--interface',
                        dest='interface',
                        required=True,
                        help='Interface To capture if [-p] is flaged \n(Default: "wlan0")')

    parser.add_argument('-r', '--read-from',
                        dest='input_file',
                        default='../Archive/top10milliondomains.csv',
                        help="Input CSV File. MUST Contain 'url' Field, \n(Default: POC/Data/top10milliondomains.csv)")

    parser.add_argument('-f', '--feature',
                        dest='feature',
                        default='Domain',
                        help="Name of Feature that Contains the URL in Input CSV File,"
                             "\n(Default: domain)")

    parser.add_argument('-w', '--write-to',
                        dest='output_file',
                        default='../Results/Page_load_DF.csv',
                        help="Output CSV File. \n(Default: POC/Results/page_load_df.csv)")

    parser.add_argument('-v', '--verbose',
                        dest='verbose',
                        action='store_true',
                        help="Print Runtime Reports (Run in Verbose Mode)")

    parser.add_argument('--headless',
                        dest='headless',
                        action='store_true',
                        help="Start Browser in Headless Mode (Invisible)")

    parser.add_argument('--chromium',
                        dest='chromium',
                        action='store_true',
                        help="Use Chromium Instead of Chrome")

    return parser.parse_args()


#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~# DATA IO #~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#
def get_urls(args):
    '''
        extracts and returns a list of all the domains listed in the input file under the given column name
        alongside a list of all the domains already contained in the result file (to avoid double checking)
    '''
    url_dataset = pandas.read_csv(args.input_file)
    try:
        checked_urls = pandas.read_csv(args.output_file)['url'].values
        print('[+] DF Loaded')
    except FileNotFoundError:
        print('[!] Could Not Find DF, Will Create New One')
        checked_urls = []
    return url_dataset[args.feature].values, checked_urls


def log_results_to_dict(eid, url, pcap_name, b_time, latency, loss, throughput_bytes, delta, label):
    '''
        logs results to the global dictionary that will be converted
         to the dataframe (by `pandas`, to be written to CSV)
    '''
    '''
        b_onload as label version
    '''
    df_dict['experiment_id'].append(eid)
    df_dict['url'].append(url)
    df_dict['pcap_name'].append(pcap_name)
    df_dict['loss'].append(loss)
    df_dict['latency'].append(latency)
    df_dict['throughput_bytes'].append(throughput_bytes)
    df_dict['browser_onLoad_time'].append(b_time)
    df_dict['time_delta'].append(delta)
    df_dict['label'].append(label)
    # '''
    #     n as label version
    # '''
    # df_dict['experiment_id'].append(eid)
    # df_dict['url'].append(url)
    # df_dict['pcap_name'].append(pcap_name)
    # df_dict['loss'].append(loss)
    # df_dict['latency'].append(latency)
    # df_dict['throughput_bytes'].append(throughput_bytes)
    # df_dict['browser_onLoad_time'].append(b_time)
    # df_dict['estimated_time'].append(est_t)
    # df_dict['chosen_n'].append(n)
    # df_dict['label'].append(label)


# to be constructed into a dict->pandas.DataFrame->to_csv
def write_results_to_csv(args):
    '''
        writes results to output CSV file
        if doesn't exist - it creates one
        if it does - it merges together the new data with the existing data
    '''
    try:
        frames = [pandas.read_csv(args.output_file), pandas.DataFrame(df_dict)]
        pandas.concat(frames, ignore_index=True).to_csv(args.output_file, index=False)
    except FileNotFoundError:
        pandas.DataFrame(df_dict).to_csv(args.output_file, index=False)
    print(f'\twritten {len(df_dict["url"])} new lines')


#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~# SELENIUM #~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#
def preform_experiment(browser, delay, index, ip, loss_p, url, eid, verbose=False):
    '''
        experiment:
        starts tcpdump, calls a url through SELENIUM, waits for 20 seconds and closes tcpdump.
        then, starts an analisys thread
    '''
    print(f'[+] {GREEN}{datetime.now()}{RESET} : Sending URL {GREEN}{url}{RESET} NO. {index} for page load timing')

    # Recording will be saved with name of format "ch.{URL}.pcap" / "ff.{URL}.pcap"
    pcap_name = f'../pcaps/v{version}/{eid}.Delay{delay}.Loss{loss_p}.{url}.pcap'

    # Start TCPDUMP
    print('\t[>] Recording Start...')
    tcpdump = Popen(['sudo', 'tcpdump', '-w', pcap_name, 'host', ip])

    print('\t[>] Chromium Start...')
    browser.get('https://' + url)
    print('\t[>] Chromium Done!')

    time.sleep(0.5)

    # get browser's point of view of timings
    print('\t[>] Getting Browser Times...')
    b_strat = browser.execute_script('return window.performance.timing.domainLookupStart')
    b_end = browser.execute_script('return window.performance.timing.loadEventEnd')
    b_onload = b_end - b_strat

    # wait for tcpdump to capture some packets
    time.sleep(20)

    # Stop TCPDUMP
    # tcpdump.send_signal(2)  # sig 2 - SIGINT || DOESN'T WORK - permissions
    call(['sudo', 'killall', 'tcpdump'])
    print('\t[>] Recording Stop...')

    # for throughput
    print('\t[>] Calculating ThroughPut')
    agg = analyze_pcap(core_domain=url, pcap_name=pcap_name, disconnect_threshold=0)
    throughput = agg.tp
    # thread_func(core_dom=url, pcap_name=pcap_name, browser_time=b_onload, nominal_delay=delay, nominal_loss=loss_p, logger_func=log_results_to_dict)

    time.sleep(2)

    # log everything
    for dt in [0.1, 0.2, 0.5, 1]:
        label = (int(b_onload) + 1) / dt
        print(f'{RED}WRITING LINE:{RESET} {eid}, {url}, {pcap_name}, {b_onload}, {delay}, {loss_p}, {throughput}, {dt}, {label}')
        log_results_to_dict(eid=eid,
                            url=url,
                            pcap_name=pcap_name,
                            b_time=b_onload,
                            latency=delay,
                            loss=loss_p,
                            throughput_bytes=throughput,
                            delta=dt,
                            label=label)
    # log_results_to_dict()


# New Version From Ran
def extract_performance_from_log(performance_log):
    performance = []
    for entry in performance_log:
        json_entry = json.loads(entry['message'])
        performance.append({'timestamp': entry['timestamp'],
                            'message': json_entry['message'],
                            'level': entry['level']})
    return performance


def handle_performance(driver, performance_path):
    performance_log = driver.get_log('performance')
    performance = extract_performance_from_log(performance_log)
    # write performance to file
    performance_json = json.dumps(performance, indent=4, ensure_ascii=False)
    performance_file = open(performance_path, 'wb')
    performance_file.write(performance_json.encode('utf8'))
    performance_file.close()


def get_driver(browser_name):
    print("[+] Starting %s" % browser_name)
    if browser_name == 'ff':
        profile = webdriver.FirefoxProfile()
        # profile.set_preference("browser.privatebrowsing.autostart", True)
        # profile.set_proxy(proxy.selenium_proxy())
        options = webdriver.firefox.options.Options()
        options.add_argument('-private')
        des_cap = DesiredCapabilities.FIREFOX
        des_cap['loggingPrefs'] = {'performance': 'ALL'}
        return webdriver.Firefox(executable_path="../Drivers/geckodriver", firefox_profile=profile, options=options,
                                 desired_capabilities=des_cap)

    elif browser_name == 'chrome':
        chrome_options = webdriver.ChromeOptions()
        # chrome_options.binary_location = "/snap/bin/chromium"
        # chrome_options.binary_location = "/usr/bin/google-chrome"
        chrome_options.binary_location = "/opt/brave.com/brave/brave-browser"
        # chrome_options = Options()
        # chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument("auto-open-devtools-for-tabs")

        chrome_options.add_argument("--remote-debugging-port=9222")  # kingdoms rise and fall on this

        chrome_options.add_argument("--enable-http2")
        # chrome_options.add_argument("--disable-http2")
        chrome_options.add_argument("--incognito")
        chrome_options.add_experimental_option('w3c', False)

        # chrome_options.add_argument(chrome_default_user_path)
        des_cap = DesiredCapabilities.CHROME
        des_cap['loggingPrefs'] = {'performance': 'ALL'}
        return webdriver.Chrome(executable_path="../Drivers/chromedriver", desired_capabilities=des_cap,
                                options=chrome_options)


#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~# MISC #~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#
def get_iface_ip(args):
    ni.ifaddresses(args.interface)
    ip = ni.ifaddresses(args.interface)[ni.AF_INET][0]['addr']
    return ip


#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~# MAIN #~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#
def main():
    args = get_args()

    experiment_id = str(uuid4())

    verbose = args.verbose

    create_netem(args.interface)
    # get IP for interface for sniffing filter
    ip = get_iface_ip(args)
    print(f'[+] Sniffing Sniffing On Interface {args.interface}, Filtering by host: {ip}')

    print('[+] Getting Url List')
    urls, checked_urls = get_urls(args)

    browser_name = 'chrome'
    ch_browser = get_driver(browser_name)

    try:
        for loss_p in gen_loss():
            for delay in gen_latency():
                for index, url in enumerate(urls):
                    try:
                        preform_experiment(ch_browser, delay, index, ip, loss_p, url, experiment_id , verbose)
                    except Exception:
                        print_exc()
                ch_browser.delete_all_cookies()


    except KeyboardInterrupt:
        print('\n')
        print("[+] Ended By User")

    print('[+] Closing Chromium')
    ch_browser.quit()

    print('[+] Exporting to CSV File')
    write_results_to_csv(args)

    print('[+] Reverting Network Conditions To Default')
    restore_network_conditions()

    print("[+] Goodbye..")


if __name__ == '__main__':
    main()
