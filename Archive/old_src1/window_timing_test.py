from selenium import webdriver

df_dict = {
    'url': [],
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
}

for _ in range(2):
    ff_browser = webdriver.Firefox(executable_path="./geckodriver")
    ff_browser.get("https://www.google.com")

    timing_obj= ff_browser.execute_script("return window.performance.timing")

    '''
        'domComplete': 1591724265131, 
        'responseStart': 1591724253317, 
        'fetchStart': 1591724245778, 
        'navigationStart': 1591724245777, 
        'domLoading': 1591724253326, 
        'redirectEnd': 0, 
        'redirectStart': 0, 
        'loadEventStart': 1591724265131, 
        'loadEventEnd': 1591724265140, 
        'connectEnd': 1591724253164, 
        'secureConnectionStart': 1591724251044, 
        'domainLookupStart': 1591724245822, 
        'domInteractive': 1591724253494, 
        'connectStart': 1591724250962, 
        'unloadEventStart': 0, 
        'unloadEventEnd': 0, 
        'domContentLoadedEventEnd': 1591724253522, 
        'domContentLoadedEventStart': 1591724253506, 
        'domainLookupEnd': 1591724250962, 
        'responseEnd': 1591724253317,
        'requestStart': 1591724253164
    '''

    ff_browser.quit()
        
    for i, j in dict(timing_obj).items():
        df_dict['ff_{}'.format(i)].append(j)

    for i, j in df_dict.items():
        print(i, j)
