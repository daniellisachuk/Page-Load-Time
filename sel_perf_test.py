from datetime import time

from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.chrome.options import Options as CH_OPT
import json






# New From Ran
def extract_performance_from_log(performance_log):
    performance = []
    for entry in performance_log:
        json_entry = json.loads(entry['message'])
        performance.append({'timestamp': entry['timestamp'],
                            'message': json_entry['message'],
                            'level': entry['level']})
    return performance


ch_opts = CH_OPT()
ch_opts.binary_location = '/usr/bin/chromium-browser'



# New From Ran
caps = DesiredCapabilities.FIREFOX
# caps['loggingPrefs'] = {'browser': 'ALL'}
caps['loggingPrefs'] = {'performance': 'ALL'}

ch_browser = webdriver.Chrome(executable_path="../Drivers/chromedriver", options=ch_opts, desired_capabilities=caps)

ch_browser.get("https://www.amazon.com")


# TODO pref log of driver from Dr. Ran
# New From Ran
performance_log = ch_browser.get_log('performance')
# print(ch_browser.log_types)
with open('test_perf3.json', 'w+') as jsonfile:
    perf = extract_performance_from_log(performance_log)
    jsonfile.write(json.dumps(perf, indent=4, sort_keys=True))

ch_browser.quit()

