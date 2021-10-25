#!/bin/env/python3

import pandas, argparse
from datetime import datetime
from selenium import webdriver
import netifaces as ni


def get_args():
    parser = argparse.ArgumentParser(
        prog='sudo python3 PageLoadURLs.py',
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
                             "\n(Default: POC/Data/top10milliondomains.csv)")

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
                        help="Start Browsers in Headless Mode (Invisible)")

    parser.add_argument('--chromium',
                        dest='chromium',
                        action='store_true',
                        help="Use Chromium Instead of Chrome")

    return parser.parse_args()


'''
    Timing Obj. Looks Like (by API order):
    window.performance.timing = {
        'navigationStart': 1591724245777,
        'redirectStart': 0,
        'redirectEnd': 0,
        'fetchStart': 1591724245778,
        'domainLookupStart': 1591724245822,
        'domainLookupEnd': 1591724250962,
        'connectStart': 1591724250962,
        'secureConnectionStart': 1591724251044,
        'connectEnd': 1591724253164,
        'requestStart': 1591724253164,
        'responseStart': 1591724253317,
        'unloadEventStart': 0,
        'unloadEventEnd': 0,
        'responseEnd': 1591724253317,
        'domLoading': 1591724253326,
        'domInteractive': 1591724253494,
        'domContentLoadedEventStart': 1591724253506,
        'domContentLoadedEventEnd': 1591724253522,
        'domComplete': 1591724265131,
        'loadEventStart': 1591724265131,
        'loadEventEnd': 1591724265140
    }
    
    Descriptive Image for help : https://i.stack.imgur.com/qBvJL.png
    '''
df_dict = {
    'url': [],

    # firefox
    'ff_navigationStart': [],
    'ff_redirectStart': [],
    'ff_redirectEnd': [],
    'ff_fetchStart': [],
    'ff_domainLookupStart': [],
    'ff_domainLookupEnd': [],
    'ff_connectStart': [],
    'ff_secureConnectionStart': [],
    'ff_connectEnd': [],
    'ff_requestStart': [],
    'ff_responseStart': [],
    'ff_unloadEventStart': [],
    'ff_unloadEventEnd': [],
    'ff_responseEnd': [],
    'ff_domLoading': [],
    'ff_domInteractive': [],
    'ff_domContentLoadedEventStart': [],
    'ff_domContentLoadedEventEnd': [],
    'ff_domComplete': [],
    'ff_loadEventStart': [],
    'ff_loadEventEnd': [],

    # chrome
    'ch_navigationStart': [],
    'ch_redirectStart': [],
    'ch_redirectEnd': [],
    'ch_fetchStart': [],
    'ch_domainLookupStart': [],
    'ch_domainLookupEnd': [],
    'ch_connectStart': [],
    'ch_secureConnectionStart': [],
    'ch_connectEnd': [],
    'ch_requestStart': [],
    'ch_responseStart': [],
    'ch_unloadEventStart': [],
    'ch_unloadEventEnd': [],
    'ch_responseEnd': [],
    'ch_domLoading': [],
    'ch_domInteractive': [],
    'ch_domContentLoadedEventStart': [],
    'ch_domContentLoadedEventEnd': [],
    'ch_domComplete': [],
    'ch_loadEventStart': [],
    'ch_loadEventEnd': []
}


def log_results_to_dict(url, ff_browser, ch_browser):

    # Extraction
    ff_timing_obj = ff_browser.execute_script("return window.performance.timing")
    ch_timing_obj = ch_browser.execute_script("return window.performance.timing")

    df_dict['url'].append(url)

    for event, time in dict(ff_timing_obj).items():
        df_dict['ff_{}'.format(event)].append(time)

    for event, time in dict(ch_timing_obj).items():
        df_dict['ch_{}'.format(event)].append(time)


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

    rec = args.pcap
    if rec:
        ni.ifaddresses(args.interface)
        ip = ni.ifaddresses(args.interface)[ni.AF_INET][0]['addr']
        print('[+] Sniffing Turned On.\n[+]     Sniffing On Interface {}, Filtering by host: {}'.format(args.interface, ip))
    else:
        ip = None



    print('[+] Getting Url List')
    urls, checked_urls = get_urls(args)

    if args.headless:
        # Open Firefox In Background (headless)
        print('[+] Starting Firefox in Headless Mode')
        from selenium.webdriver.firefox.options import Options as FF_OPT
        ff_opts = FF_OPT()
        ff_opts.headless = True
        ff_browser = webdriver.Firefox(executable_path="./geckodriver", options=ff_opts)
    else:
        # Open Firefox
        print('[+] Starting Firefox')
        ff_browser = webdriver.Firefox(executable_path="./geckodriver")

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

        ch_browser = webdriver.Chrome(executable_path="./chromedriver", chrome_options=ch_opts)
    else:
        # Open Chrome
        print('[+] Starting Chrome')
        ch_browser = webdriver.Chrome(executable_path="./chromedriver")

    try:
        for index, url in enumerate(urls):
            try:
                if url not in checked_urls:
                    print('[+] {} : Sending URL {} NO. {} for page load timing'.format(datetime.now(), url, index))
                    # Recording will be saved with name of format "ch.{URL}.pcap" / "ff.{URL}.pcap"
                    # TODO Add TCPDUMP Start
                    if rec:
                        # Start TCPDUMP
                        import subprocess as sub
                        p = sub.Popen(('sudo', 'tcpdump', '-w', './pcaps/ff.{}.pcap'.format(url), 'host', ip))

                    print('\t[>] FireFox Start...')
                    ff_browser.get('https://' + url)
                    print('\t[>] FireFox Done! Calculating & Logging Performance')

                    if rec:
                        # Stop TCPDUMP
                        p.kill()
                        # Start TCPDUMP
                        p = sub.Popen(('sudo', 'tcpdump', '-w', './pcaps/ch.{}.pcap'.format(url), 'host', ip))

                    print('\t[>] Chromium Start...')
                    ch_browser.get('https://' + url)
                    print('\t[>] Chromium Done! Calculating & Logging Performance')

                    # TODO Add TCPDUMP End
                    if rec:
                        # Stop TCPDUMP
                        p.kill()

                    log_results_to_dict(url, ff_browser, ch_browser)

                else:
                    print('[!] URL {} NO. {} Already Exists, Skipping...'.format(url, index))

            except Exception as k:
                print(k)

    except KeyboardInterrupt:
        print('\n')
        print("[+] Ended By User")

    print('[+] Closing Headless FireFox')
    ff_browser.quit()

    print('[+] Closing Headless Chromium')
    ch_browser.quit()

    print('[+] Exporting to CSV File')
    write_results_to_csv(args)

    print("[+] Goodbye..")


if __name__ == '__main__':
    main()
