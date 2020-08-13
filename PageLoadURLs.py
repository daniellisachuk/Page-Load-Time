#!/bin/env/python3

import pandas, argparse, json
import netifaces as ni
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities


df_dict = {
    'url': [],
    'timestamp': [],
    'message': [],
    'level': []
}


def log_results_to_dict(url, perf_log):
    df_dict['url'].append(url)
    timestamps = []
    messages = []
    levels = []

    for entry in perf_log:
        timestamps.append(entry['timestamp'])
        messages.append(entry['message'])
        levels.append(entry['level'])

    df_dict['timestamp'].append(timestamps)
    df_dict['message'].append(messages)
    df_dict['level'].append(levels)


# New From Ran
def extract_performance_from_log(performance_log):
    performance = []
    for entry in performance_log:
        json_entry = json.loads(entry['message'])
        performance.append({'timestamp': entry['timestamp'],
                            'message': json_entry['message'],
                            'level': entry['level']})
    return performance


def get_driver(args):
    caps = DesiredCapabilities.FIREFOX
    caps['loggingPrefs'] = {'performance': 'ALL'}
    if args.headless or args.chromium:

        from selenium.webdriver.chrome.options import Options as CH_OPT
        ch_opts = CH_OPT()

        if args.headless:
            print('[+] Starting Chromium in Headless Mode')
            # Open Chromium In Background (headless)
            ch_opts.add_argument('--headless')

        if args.chromium:
            # Open Chromium
            print('[+] Starting Chromium')
            ch_opts.binary_location = '/usr/bin/chromium-browser'

        ch_browser = webdriver.Chrome(executable_path="./chromedriver", chrome_options=ch_opts,
                                      desired_capabilities=caps)

    else:  # if no args provided
        # Open Chrome
        print('[+] Starting Chrome')
        ch_browser = webdriver.Chrome(executable_path="./chromedriver", desired_capabilities=caps)
    return ch_browser


def get_args():
    parser = argparse.ArgumentParser(
        prog='sudo python3 PageLoadURLs.py [Options]',
        description='A Research Program That Opens URLs (Given in a CSV File),'
                    ' Calculates and Stores the Timing Values in a CSV file',
        epilog='Created by Daniel Lisachuk for FlashNetworks QoE Project'
    )

    parser.add_argument('-i', '--interface',
                        dest='interface',
                        default='wlan0',
                        help='Interface To capture if [-p] is flaged \n(Default: "wlan0")')

    parser.add_argument('-r', '--read-from',
                        dest='input_file',
                        default='./Data/top10milliondomains.csv',
                        help="Input CSV File. MUST Contain 'url' Field, \n(Default: POC/Data/top10milliondomains.csv)")

    parser.add_argument('-f', '--feature',
                        dest='feature',
                        default='Domain',
                        help="Name of Feature that Contains the URL in Input CSV File,"
                             "\n(Default: domain)")

    parser.add_argument('-w', '--write-to',
                        dest='output_file',
                        default='./Results/Page_load_DF.csv',
                        help="Output CSV File. \n(Default: POC/Results/page_load_df.csv)")

    parser.add_argument('-p', '--pcap',
                        dest='pcap',
                        action='store_true',
                        help="Record Pcaps for Each URL in Each Browser")

    parser.add_argument('--headless',
                        dest='headless',
                        action='store_true',
                        help="Start Browser in Headless Mode (Invisible)")

    parser.add_argument('--chromium',
                        dest='chromium',
                        action='store_true',
                        help="Use Chromium Instead of Chrome")

    return parser.parse_args()


# to be constructed into a dict->pandas.DataFrame->to_csv
def write_results_to_csv(args):
    try:
        frames = [pandas.read_csv(args.output_file), pandas.DataFrame(df_dict)]
        pandas.concat(frames, ignore_index=True).to_csv('page_load_df.csv', index=False)
    except FileNotFoundError:
        pandas.DataFrame(df_dict).to_csv(args.output_file, index=False)


def get_urls(args):
    url_dataset = pandas.read_csv(args.input_file)
    try:
        checked_urls = pandas.read_csv(args.output_file)['url'].values
        print('[+] DF Loaded')
    except FileNotFoundError:
        print('[!] Could Not Find DF, Will Create New One')
        checked_urls = []
    return url_dataset['Domain'].values, checked_urls


def main():

    args = get_args()

    # if recording, get IP for interface for sniffing filter
    rec = args.pcap
    if rec:
        # ni -> netinterfaces
        ni.ifaddresses(args.interface)
        ip = ni.ifaddresses(args.interface)[ni.AF_INET][0]['addr']
        print('[+] Sniffing Turned On.\n[+]     Sniffing On Interface {}, Filtering by host: {}'.format(args.interface, ip))
    else:
        ip = ''

    print('[+] Getting Url List')
    urls, checked_urls = get_urls(args)

    ch_browser = get_driver(args)

    try:
        for index, url in enumerate(urls):
            try:
                if url not in checked_urls:
                    print('[+] {} : Sending URL {} NO. {} for page load timing'.format(datetime.now(), url, index))

                    # Recording will be saved with name of format "ch.{URL}.pcap" / "ff.{URL}.pcap"
                    if rec:
                        import subprocess as sub
                        # Start TCPDUMP
                        p = sub.Popen(('sudo', 'tcpdump', '-w', './pcaps/v2/ch.{}.pcap'.format(url), 'host', ip), shell=True)

                    print('\t[>] Chromium Start...')
                    ch_browser.get('https://' + url)
                    print('\t[>] Chromium Done! Calculating & Logging Performance')

                    if rec:
                        # Stop TCPDUMP
                        p.kill()

                    log_results_to_dict(url, ch_browser.get_log('performance'))

                else:
                    print('[!] URL {} NO. {} Already Exists, Skipping...'.format(url, index))

            except Exception as k:
                print(k)

    except KeyboardInterrupt:
        print('\n')
        print("[+] Ended By User")

    print('[+] Closing Chromium')
    ch_browser.quit()

    print('[+] Exporting to CSV File')
    write_results_to_csv(args)

    print("[+] Goodbye..")


if __name__ == '__main__':
    main()
