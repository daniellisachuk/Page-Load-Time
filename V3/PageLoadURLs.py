#!usr/bin/python3


'''
    version 3 of PageLoadURLs will be dedicated only to writing pcap file on which we could run later
    as we parse the experiment
'''


#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~# IMPORTS #~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#
import pandas, argparse, netifaces as ni, time
from subprocess import call, Popen, PIPE, DEVNULL
from threading import RLock
from datetime import datetime
from traceback import print_exc
from uuid import uuid4
from os import rename

# selenium imports
from colorama import init, Fore
from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

# in-project imports
from network_condition import gen_latency, gen_loss, create_netem, restore_network_conditions, set_manual_loss_delay


#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~# GLOBALS #~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#
version = 3

init()
RED = Fore.RED
CYAN = Fore.CYAN
GREEN = Fore.GREEN
BLUE = Fore.BLUE
RESET = Fore.RESET


# Globals for Selenium Maintenance
running = False
ch_browser = None

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
                        default='domain',
                        help="Name of Feature that Contains the URL in Input CSV File,"
                             "\n(Default: domain)")

    parser.add_argument('-w', '--write-to',
                        dest='output_file',
                        default='../Results/Page_load_DF.csv',
                        help="Output CSV File. \n(Default: POC/Results/page_load_df.csv)")

    parser.add_argument('-l', '--loss',
                        dest='n_loss',
                        default=None,
                        type=int,
                        choices=[0, 2, 5, 7, 10],
                        help="Manually Set Loss Value (MUST be Used with `-d`(/`--delay) option)")

    parser.add_argument('-d', '--delay',
                        dest='n_delay',
                        default=None,
                        type=int,
                        choices=[0, 20, 50, 100],
                        help="Manually Set Delay Value (MUST be Used with `-l`(/`--loss) option)")

    parser.add_argument('-v', '--verbose',
                        dest='verbose',
                        action='store_true',
                        help="Print Runtime Reports (Run in Verbose Mode)")

    parser.add_argument('-V', '--very-verbose',
                        dest='v_verbose',
                        action='store_true',
                        help="Print Analysis Reports (Run in Very Verbose Mode). " \
                             "NOTE: if this option is selected, the option `-v` will automatically be applied")

    parser.add_argument('--headless',
                        dest='headless',
                        action='store_true',
                        help="Start Browser in Headless Mode (Invisible)")

    parser.add_argument('--chromium',
                        dest='chromium',
                        action='store_true',
                        help="Use Chromium Instead of Chrome")

    parser.add_argument('--ndbg',
                        dest='dbg',
                        action='store_true',
                        help="Debug Program")

    return parser.parse_args()


def get_verbosity(args):
    verbose = args.verbose
    v_verbose = args.v_verbose

    # logical or with very verbose ------->  (very_verbose -> verbose)
    verbose ^= v_verbose

    return v_verbose, verbose

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


#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~# SELENIUM #~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#
def run_on_all_urls(args, browser_name, delay, experiment_id, ip, loss_p, urls, verbose, v_verbose):
    global ch_browser, running
    ch_browser = get_driver(browser_name)
    running = True
    for index, url in enumerate(urls):
        try:
            preform_experiment(ch_browser, delay, index, ip, loss_p, url, experiment_id, verbose, v_verbose)
            if args.dbg:
                raise KeyboardInterrupt
        except TimeoutException as e:
            print(e)
            call(['sudo', 'killall', 'tcpdump'])

            ch_browser.quit()
            call(['sudo', 'killall', 'brave'])
            time.sleep(2)

            ch_browser = get_driver(browser_name)
        except Exception:
            print_exc()
            call(['sudo', 'killall', 'tcpdump'])

    ch_browser.quit()
    running = False
    # write_results_to_csv(args)



    # log_results_to_dict()


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
        return webdriver.Firefox(executable_path="./Drivers/geckodriver", firefox_profile=profile, options=options,
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
        return webdriver.Chrome(executable_path="./Drivers/chromedriver", desired_capabilities=des_cap,
                                options=chrome_options)


#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#  EXPERIMENT #~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~# 
def run_automatic(args, browser_name, experiment_id, ip, urls, verbose, v_verbose):
    for n_loss in gen_loss():
        for n_delay in gen_latency():
            run_on_all_urls(args=args,
                            browser_name=browser_name,
                            delay=n_delay,
                            experiment_id=experiment_id,
                            ip=ip,
                            loss_p=n_loss,
                            urls=urls,
                            verbose=verbose,
                            v_verbose=v_verbose)


def run_manual(args, browser_name, experiment_id, ip, urls, verbose, v_verbose):
    n_loss = args.n_loss
    n_delay = args.n_delay

    # TODO func in `net_cond.py` to manually add loss & delay
    set_manual_loss_delay(loss=n_loss, delay=n_delay)

    run_on_all_urls(args=args,
                    browser_name=browser_name,
                    delay=n_delay,
                    experiment_id=experiment_id,
                    ip=ip,
                    loss_p=n_loss,
                    urls=urls,
                    verbose=verbose,
                    v_verbose=v_verbose)

def preform_experiment(browser, delay, index, ip, loss_p, url, eid, verbose=False, v_verbose=False):
    '''
        experiment:
        starts tcpdump, calls a url through SELENIUM, waits for 5 seconds and closes tcpdump.
    '''
    print(f'[+] {GREEN}{datetime.now()}{RESET} : Sending URL {GREEN}{url}{RESET} NO. {index} for page load timing')
    print(f'[+] Current Conditions : {GREEN}Loss{RESET} : {CYAN}{loss_p}%{RESET}, {GREEN}Delay{RESET} : {CYAN}{delay}ms{RESET}')

    # Recording will initially be saved with name of format "ch.{URL}.pcap" / "ff.{URL}.pcap"
    primary_pcap_name = f'./pcaps/v{version}/{eid}.Delay{delay}.Loss{loss_p}.{url}.pcap'

    # Start TCPDUMP
    if verbose:
        print('\t[>] Recording Start...')

    tcpdump = Popen(['sudo', 'tcpdump', '-w', primary_pcap_name, 'host', ip], stdout=PIPE if verbose else DEVNULL, stderr=PIPE)

    if verbose:
        print('\t[>] Chromium Start...')
    browser.get('https://' + url)
    if verbose:
        print('\t[>] Chromium Done!')

    time.sleep(0.5)

    # get browser's point of view of timings
    if verbose:
        print('\t[>] Getting Browser Times...')
    b_strat = browser.execute_script('return window.performance.timing.domainLookupStart')
    b_end = browser.execute_script('return window.performance.timing.loadEventEnd')
    b_onload = (b_end - b_strat) / 1000  # calc onload time in ms and convert to sec (for label)

    # wait for tcpdump to capture some packets
    time.sleep(5)

    # Stop TCPDUMP
    # tcpdump.send_signal(2)  # sig 2 - SIGINT || DOESN'T WORK - permissions
    call(['sudo', 'killall', 'tcpdump'])
    if verbose:
        tcp_output = tcpdump.communicate()[0]
        try:
            pkt_n = tcp_output.split(b"\n")[-3].split()[0].decode("utf-8")
        except Exception:
            print(f'\t[>] Recording Stop...')
        else:
            print(f'\t[>] Recording Stop... {pkt_n} Packets Were Captured')

    final_pcap_name = f'./pcaps/v{version}/{eid}.Delay{delay}.Loss{loss_p}.onLoad{b_onload}.{url}.pcap'

    rename(primary_pcap_name, final_pcap_name)


#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~# MISC #~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#
def get_interface_ip(args):
    try:
        ip = ni.ifaddresses(args.interface)[ni.AF_INET][0]['addr']
    except KeyError:
        print(f'{RED}PRE-RUN ERROR{RESET}: Interface {args.interface} Has No IP Address')
        exit(-1)
    else:
        return ip


def is_auto(args):
    if args.n_loss is None and args.n_delay is None:
        return True
    elif args.n_loss is not None and args.n_delay is not None:
        return False
    else:
        print(f'{RED}PRE-RUN ERROR{RESET}: Loss & Delay Values Must be Provided Together or Not At All')
        exit(-1)



#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~# MAIN #~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#
def main():
    # get cmd-line arguments
    args = get_args()

    auto = is_auto(args)

    # gen unique experiment id - used to distinguish between runs
    experiment_id = str(uuid4())

    v_verbose, verbose = get_verbosity(args)

    # create NetEmulator (for TrafficControl QueueDiscipline) on given iFace
    print(f'[+] Creating Net Emulator on Interface {args.interface}')
    create_netem(args.interface)

    # get IP for interface for sniffing filter
    # will print error & exit if wrong iface
    ip = get_interface_ip(args)
    print(f'[+] Sniffing Set On Interface {args.interface}, Filtering by host: {ip}')

    print('[+] Getting Url List')
    urls, checked_urls = get_urls(args)

    browser_name = 'chrome'
    running = False

    try:
        if auto:
            print(f'[+] Running In {CYAN}Automatic{RESET} Mode')
            run_automatic(args, browser_name, experiment_id, ip, urls, verbose, v_verbose)
        else:
            print(f'[+] Running In {CYAN}Manual{RESET} Mode')
            run_manual(args, browser_name, experiment_id, ip, urls, verbose, v_verbose)


    except KeyboardInterrupt:
        print('\n')
        print("[+] Ended By User")

    except Exception:
        print('\n')

        print_exc()
        print('\n')

        print("[!] Ended By Fatal Error")

    else:
        print("[+] Ended By Finishing Experiment")


    if running:
        print('[+] Closing Chromium')
        ch_browser.quit()

    # print('[+] Exporting to CSV File')
    # write_results_to_csv(args)

    print('[+] Reverting Network Conditions To Default')
    restore_network_conditions()

    print("[+] Goodbye..")


if __name__ == '__main__':
    main()
