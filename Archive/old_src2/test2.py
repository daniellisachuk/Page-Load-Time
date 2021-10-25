import json
import os

from selenium import webdriver
from selenium.webdriver import DesiredCapabilities


def get_webdriver_for_test(browser_name, proxy):
    print("starting %s" % browser_name)
    if browser_name == 'ff':
        print("shouldn't work")
        profile = webdriver.FirefoxProfile()
        # profile.set_preference("browser.privatebrowsing.autostart", True)
        # profile.set_proxy(proxy.selenium_proxy())
        options = webdriver.firefox.options.Options()
        options.add_argument('-private')
        des_cap = DesiredCapabilities.FIREFOX
        des_cap['loggingPrefs'] = {'performance': 'ALL'}
        return webdriver.Firefox(executable_path="../Drivers/geckodriver", firefox_profile=profile, options=options, desired_capabilities=des_cap)

    elif browser_name == 'chrome':
        print("should work")
        chrome_options = webdriver.ChromeOptions()
        # chrome_options.binary_location = "/snap/bin/chromium"
        chrome_options.binary_location = "/opt/brave.com/brave/brave-browser"
        # chrome_options = Options()
        chrome_options.add_argument("auto-open-devtools-for-tabs")

        chrome_options.add_argument("--remote-debugging-port=9222")  # this

        chrome_options.add_argument("--enable-http2")
        # chrome_options.add_argument("--disable-http2")
        chrome_options.add_argument("--incognito")
        chrome_options.add_experimental_option('w3c', False)

        # chrome_options.add_argument(chrome_default_user_path)
        des_cap = DesiredCapabilities.CHROME
        des_cap['loggingPrefs'] = {'performance': 'ALL'}
        return webdriver.Chrome(executable_path="../Drivers/chromedriver", desired_capabilities=des_cap, options=chrome_options)


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


def main():
    browser_name = 'chrome'
    # browser_name = 'ff'
    output_path = '/home/daniel/Desktop'
    file_name_format = 'test6'
    # start web driver
    driver = get_webdriver_for_test(browser_name, proxy='')
    driver.get("http://www.geektime.co.il")
    performance_path = os.path.join(output_path, file_name_format + '.json')
    handle_performance(driver, performance_path)
    driver.quit()


if __name__ == '__main__':
    main()

