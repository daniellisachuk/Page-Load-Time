import json
import re

# TODO Time To First Byte
#      Time To X Bytes
#      Time To Last Packet
#      Page Load Time (last sub-domain disconnected)

# TODO Subdomains


# Selenium Performance Log Parser
class PerfLogParser:
    def __init__(self, raw_selenium_perf_log: dict):
        self.raw_log = raw_selenium_perf_log
        self.interactions = {}
        # self.avg_data_size = -1
        # self.total_data_size = -1
        # self.avg_encoded_data_size = -1
        # self.total_encoded_data_size = -1
        # self.avg_rtt = -1
        # self.time_elapsed = -1
        # self.served_from_cache = []
        self.page_entries = []  # all entries starting with "Page.*"
        # self.main_remote_addr = None  # TODO
        self.subdomains = set([])

        # Request File Types
        self.doc = None
        self.images = []
        self.style_sheets = []
        self.scripts = []
        self.fonts = []
        self.xhrs = []
        self.others = []
        self.none_types = []

        self.parse_log()

        self.calc_total_metrics()

    def parse_log(self):
        for raw_entry in self.raw_log:
            entry = Entry(raw_entry['message'], raw_entry['timestamp'])

            # if page related entry (frame details)
            if entry.method_family == 'Page':
                self.page_entries.append(entry)

            elif entry.method_family == 'Network':
                # get request id as key
                key = entry.message['params']['requestId']

                # if first packet in interaction
                if key not in self.interactions:
                    self.interactions[key] = Interaction(key, self)

                self.interactions[key].add_entry(entry)

            else:
                # TODO del after debug
                print(entry.method_family)

    def calc_total_metrics(self):
        # TODO
        for ID, conn in self.interactions.items():
            # fill subdomains
            self.subdomains.add(conn.subdomain)

            # fill types

        if conn.type == 'Document':
            self.doc = ID
        elif conn.type == 'Stylesheet':
            self.style_sheets.append(ID)
        elif conn.type == 'Image':
            self.images.append(ID)
        elif conn.type == 'Font':
            self.images.append(ID)
        elif conn.type == 'XHR':
            self.xhrs.append(ID)
        elif conn.type == 'Script':
            self.scripts.append(ID)
        elif conn.type == 'Other':
            self.others.append(ID)
        elif conn.type is None:
            self.none_types.append(ID)
        else:
            if isfloat(ID):
                raise ValueError("Interaction %s has unknown type - %s" % (ID, conn.type))

        pass

    def get_interactions_size(self):
        return len(self.interactions)

    def get_avg_data_size(self):
        pass

    def get_total_data_size(self):
        pass

    def get_avg_rtt(self):
        pass

    def get_total_elapsed_time(self):
        pass

    def get_avg_dns_time(self):
        pass

    def get_num_of_redirects(self):
        pass

    def get_redirects(self):
        pass

    def get_request_ids(self):
        pass

    def get_num_of_cache_hits(self):
        pass

    def get_cache_hits(self):
        pass


# Info on Req-Res
'''
    Object to store and parse entries of any domain or sub-domain called in the process of page load
'''


class Interaction:
    def __init__(self, interaction_id: str, log_parser: "PerfLogParser"):
        # Key -> interaction ID (== requestId)
        self.ID = interaction_id
        self.handler = log_parser

        # Entries
        self.req = None  # entry
        self.req_extra = []
        self.res = None  # entry
        self.res_extra = []
        self.redirect = []
        self.subdomain = None  # str
        self.data = []
        self.info = []
        self.fails = []
        self.complete = None  # entry
        self.canceled = [False,  {'reason': []}]
        self.from_cache = False

        # Stats
        self.proto = None
        self.type = None
        self.remote_addr = None
        self.data_size = 0  # what's the difference TODO
        self.encoded_data_size = 0  # what's the difference TODO
        self.dns_time = -1  # -1 means none (eg: served from cache or in Ideas domain)
        self.time_elapsed = 0
        self.packet_count = 0

        # Metrics
        self.avg_data_size = 0
        self.avg_encoded_data_size = 0
        self.avg_rtt = 0

    def add_entry(self, entry: "Entry"):
        method = entry.method_type
        # TODO del after debug
        print(self.ID)

        if method == 'requestWillBeSent':
            # if interaction opener
            if self.req is None:
                self.req = entry
                self.type = self.req.message['params']['type']

                self.type = entry.message['params']['type']
                # TODO del after debug
                print("Interaction %s is of type %s" % (self.ID, self.type))

            else:
                # check if redirect
                if "redirectResponse" in entry.message['params']:
                    # print("interaction %s got redirect" % self.ID)
                    self.redirect.append(entry)
                    # TODO del after debug
                    print(self.redirect)
                else:
                    raise ValueError("Value Req in Interaction %s is already assigned" % self.ID)

        elif method == 'responseReceived':
            if not self.req:
                if isfloat(self.ID):
                    raise ValueError("Value Res in Interaction %s Was Not Requested" % self.ID)
                else:
                    return

            if self.res is None:
                self.res = entry

                self.calc_rtt()
                self.calc_dns()

                # if remote address is present
                self.get_remote_ip_reg()
            else:
                raise ValueError("Value Res in Interaction %s is already assigned" % self.ID)

        elif method == 'requestWillBeSentExtraInfo':
            self.req_extra.append(entry)

        elif method == 'responseReceivedExtraInfo':
            self.res_extra.append(entry)

        elif method == 'requestServedFromCache':
            # TODO CACHE OF DNS OR HTTP?
            #     probably dns - not confirmed
            self.from_cache = True
            self.dns_time = -1

        elif method == 'dataReceived':
            self.data.append(entry)

        elif method == "loadingFinished":
            if self.complete is None:
                # print(entry.message['params']['requestId'])
                self.complete = entry
                self.eval_stats_and_metrics()
            else:
                raise ValueError("Value Complete in Interaction %s is already assigned" % self.ID)

            # TODO CALC REMAINING METRICS

        elif method == 'loadingFailed':
            self.fails.append(entry)
            self.canceled[0] = entry.message['params']['canceled']
            self.canceled[1]['reason'].append(entry.message['params']['errorText'])
            # TODO TIME_ELAPSED

        elif method == 'resourceChangedPriority':
            # TODO LEARN WHAT THIS MEANS AND HOW TO FURTHER PARSE IT
            self.info.append(entry)

        else:
            # TODO del after debug
            print(method)

        # increase packet count in interaction with every call to `add_entry`
        self.packet_count += 1

    def get_remote_ip_reg(self):
        # res -> response -> remoteIPAddress
        if 'remoteIPAddress' in self.res.message['params']['response']:
            self.remote_addr = self.res.message['params']['response']['remoteIPAddress']

        # if remote address is not present -> get remote address from dns??
        else:
            # TODO LEARN HOW TO EXTRACT REMOTE ADDRESS FROM THINGS LIKE SVG
            #     MAYBE SEND DNS? IN CALC_METRICS?
            self.remote_addr = None

    def calc_rtt(self):
        if self.from_cache:
            self.avg_rtt = self.res.message['params']['timestamp'] - self.req.message['params']['timestamp']
            # TODO del after debug
            print(self.avg_rtt)
            print()
            return

        response_times = []
        # req -> wallTime  ## wallTime (seems) more accurate
        req_t = self.req.message['params']['wallTime'] * 1000
        if self.redirect:
            # entry -> redirectResponse -> responseTime
            for entry in self.redirect:
                response_times.append(entry.message['params']['redirectResponse']['responseTime'] - req_t)
                req_t = entry.message['params']['wallTime'] * 1000
        # res -> response -> responseTime
        response_times.append(self.res.message['params']['response']['responseTime'] - req_t)

        avg = 0
        for rtt in response_times:
            avg += rtt

        self.avg_rtt = avg/len(response_times)
        # TODO del after debug
        print(response_times)
        print(self.avg_rtt)
        print()

    def calc_dns(self):
        # TODO del after debug
        print("dns for %s" % self.ID)
        if self.from_cache:
            # TODO del after debug
            print("dns time: %s" % self.dns_time)
            return

        if self.redirect:
            timing_entry = self.redirect[0].message['params']['redirectResponse']
        else:
            timing_entry = self.res.message['params']['response']

        dns_s = timing_entry['timing']['dnsStart']
        dns_e = timing_entry['timing']['dnsEnd']

        if dns_s != -1:
            self.dns_time = dns_e - dns_s

        # TODO del after debug
        print("dns time: %s" % self.dns_time)

    '''gets called after "loadingFinished" pkt is associated with the interaction'''
    def eval_stats_and_metrics(self):
        # AVG_DATA_SIZE
        for entry in self.data:
            self.data_size += int(entry.message['params']['dataLength'])
            self.encoded_data_size += int(entry.message['params']['encodedDataLength'])

        # TODO del after debug
        # print(self.data_size)

        if self.data_size != 0 or self.encoded_data_size != 0:
            if self.encoded_data_size != 0:
                self.avg_encoded_data_size = self.encoded_data_size/len(self.data)
            if self.data_size != 0:
                self.avg_data_size = self.data_size/len(self.data)
        else:
            if isfloat(self.ID):
                raise ValueError("loadingFinished Recieved But No Data Received error - Interaction %s" % self.ID)
            else:
                # TODO del after debug
                # print("%s has returned" % self.ID)
                return

        # Time Elapsed
        if self.req is not None:
            self.time_elapsed = self.complete.timestamp - self.req.timestamp
        else:
            if isfloat(self.ID):
                raise ValueError("loadingFinished Recieved But No Request error - Interaction %s" % self.ID)

        # Get URL (And IP if Nedded)
        subdomains = url(self.res.message['params']['response']['url'])
        if subdomains:
            self.subdomain = subdomains[0]
            # url() returns list of urls in given string.
            # if list is not empty, set index 0 to be subdomain

            # TODO del after debug
            print("%s" % self.subdomain)
            if isfloat(self.ID):
                self.remote_addr = "MAIN"
                # raise ValueError("loadingFinished Recieved But No Subdomain error - Interaction %s" % self.ID)

    def get_obj_type(self):
        return self.type

    def get_data_size(self):
        return self.data_size

    def get_enc_data_size(self):
        return self.encoded_data_size

    def get_avg_data_packet_size(self):
        return self.avg_data_size

    def get_avg_enc_data_packet_size(self):
        return self.avg_encoded_data_size

    def get_elapsed_time(self):
        return self.time_elapsed

    def get_avg_rtt(self):
        return self.avg_rtt

    def get_dns_time(self):
        return self.dns_time

    def get_response_time(self):
        return (self.res.message['params']['response']['timestamp'] - self.res.message['params']['response']['timing']['requestTime']) * 1000


# Container for log entries
class Entry:
    def __init__(self, message: dict, timestamp: int):
        self.message = message
        self.timestamp = timestamp

        m_family, m_type = self.message['method'].split('.')

        self.method_family = m_family
        self.method_type = m_type


def url(str):
    # findall() has been used
    # with valid conditions for urls in string
    ur = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\), ]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', str)
    return ur


def isfloat(str):
    try:
        float(str)
        return True
    except ValueError:
        return False

if __name__ == "__main__":
    import sys
    with open('/home/daniel/Desktop/test{}.json'.format(sys.argv[1]), 'r') as jsonfile:
        log = json.loads(jsonfile.read())

    parser = PerfLogParser(log)
    # str = "data:image/svg+xml;utf8,<svg width=\"24\" height=\"24\" viewBox=\"0 0 512 512\" xmlns=\"http://www.w3.org/2000/svg\"><path fill=\"rgb(1,1,1)\" d=\"M0 256Q0 150 75 75T256 0t181 75 75 181-75 181-181 75-181-75T0 256zm42 0q0 88 63 150.5T256 469t150.5-62.5T469 256t-62.5-151T256 42t-151 63-63 151zm122-59q0-42 24.5-66.5T254 106q39 0 66 22t27 60q0 26-11 43t-24 23-24 13.5-11 16.5v30h-42v-30q0-23 10.5-37t23.5-18.5 23.5-14.5 10.5-26q0-40-47-40t-47 49h-45zm62 177q0-13 8.5-21.5T256 344t22 8.5 9 21.5-9 22-22 9-21.5-9-8.5-22z\" /></svg>"
    # print("Url is :: ", url(str))
    print("Subdomains: %s" % parser.subdomains)
    print("Interactions: %d" % len(parser.interactions))

    exit(0)





    #
    #
    # interaction = Interaction("ABCD")
    # entry = Entry(message=
    #               {"method": "Network.loadingFinished",
    #                "params": {
    #                    "encodedDataLength": 0,
    #                    "requestId": "65546EF0DDE876A37C8CC1EC9D1C69F4",
    #                    "shouldReportCorbBlocking": False,
    #                    "timestamp": 27315.794862
    #                }
    #                },
    #               timestamp=12345)
    # interaction.add_entry(entry)
    #
    # interaction2 = Interaction(interaction_id="1000017222.7")
    #
    # entry2 = Entry(message= {
    #             "method": "Network.requestWillBeSent",
    #             "params": {
    #                 "documentURL": "https://www.jsonquerytool.com/",
    #                 "frameId": "8C995C19C7A63A74CB00136C9D90357E",
    #                 "hasUserGesture": False,
    #                 "initiator": {
    #                     "lineNumber": 54,
    #                     "type": "parser",
    #                     "url": "https://www.jsonquerytool.com/"
    #                 },
    #                 "loaderId": "0FD8CC1F5296403284705AE7B67870FC",
    #                 "request": {
    #                     "headers": {
    #                         "Referer": "https://www.jsonquerytool.com/",
    #                         "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/74.0.3729.169 Chrome/74.0.3729.169 Safari/537.36"
    #                     },
    #                     "initialPriority": "High",
    #                     "method": "GET",
    #                     "mixedContentType": "none",
    #                     "referrerPolicy": "no-referrer-when-downgrade",
    #                     "url": "https://www.jsonquerytool.com/app.60088e6d45d7917d39fd.js"
    #                 },
    #                 "requestId": "1000017222.7",
    #                 "timestamp": 28545.689487,
    #                 "type": "Script",
    #                 "wallTime": 1594046643.22055
    #             }
    #         }, timestamp=1594046643232)
    #
    # # Add Request Will Be Sent
    # interaction2.add_entry(entry2)
    #
    # entry2 = Entry(message={
    #             "method": "Network.responseReceived",
    #             "params": {
    #                 "frameId": "8C995C19C7A63A74CB00136C9D90357E",
    #                 "loaderId": "0FD8CC1F5296403284705AE7B67870FC",
    #                 "requestId": "1000017222.7",
    #                 "response": {
    #                     "connectionId": 36,
    #                     "connectionReused": True,
    #                     "encodedDataLength": 352,
    #                     "fromDiskCache": False,
    #                     "fromServiceWorker": False,
    #                     "headers": {
    #                         "Accept-Ranges": "bytes",
    #                         "Cache-Control": "max-age=86400,public",
    #                         "Content-Encoding": "gzip",
    #                         "Content-Type": "application/x-javascript",
    #                         "Date": "Mon, 06 Jul 2020 14:44:03 GMT",
    #                         "ETag": "\"0dcff4bf29d51:0\"",
    #                         "Last-Modified": "Sun, 23 Jun 2019 12:34:10 GMT",
    #                         "Server": "Microsoft-IIS/10.0",
    #                         "Transfer-Encoding": "chunked",
    #                         "Vary": "Accept-Encoding",
    #                         "X-Powered-By": "ASP.NET"
    #                     },
    #                     "mimeType": "application/x-javascript",
    #                     "protocol": "http/1.1",
    #                     "remoteIPAddress": "104.40.129.89",
    #                     "remotePort": 443,
    #                     "securityDetails": {
    #                         "certificateId": 0,
    #                         "certificateTransparencyCompliance": "unknown",
    #                         "cipher": "AES_256_GCM",
    #                         "issuer": "Microsoft IT TLS CA 5",
    #                         "keyExchange": "ECDHE_RSA",
    #                         "keyExchangeGroup": "P-256",
    #                         "protocol": "TLS 1.2",
    #                         "sanList": [
    #                             "*.azurewebsites.net",
    #                             "*.scm.azurewebsites.net",
    #                             "*.azure-mobile.net",
    #                             "*.scm.azure-mobile.net",
    #                             "*.sso.azurewebsites.net"
    #                         ],
    #                         "signedCertificateTimestampList": [],
    #                         "subjectName": "*.azurewebsites.net",
    #                         "validFrom": 1569291536,
    #                         "validTo": 1632449936
    #                     },
    #                     "securityState": "insecure",
    #                     "status": 200,
    #                     "statusText": "OK",
    #                     "timing": {
    #                         "connectEnd": -1,
    #                         "connectStart": -1,
    #                         "dnsEnd": -1,
    #                         "dnsStart": -1,
    #                         "proxyEnd": -1,
    #                         "proxyStart": -1,
    #                         "pushEnd": 0,
    #                         "pushStart": 0,
    #                         "receiveHeadersEnd": 472.26,
    #                         "requestTime": 28545.692222,
    #                         "sendEnd": 2.09,
    #                         "sendStart": 2.024,
    #                         "sslEnd": -1,
    #                         "sslStart": -1,
    #                         "workerReady": -1,
    #                         "workerStart": -1
    #                     },
    #                     "url": "https://www.jsonquerytool.com/app.60088e6d45d7917d39fd.js"
    #                 },
    #                 "timestamp": 28546.165602,
    #                 "type": "Script"
    #             }
    #         }, timestamp= 1594046643701)
    #
    # # Add Response Received
    # interaction2.add_entry(entry2)
    #
    # entry2 = Entry(message={
    #             "method": "Network.dataReceived",
    #             "params": {
    #                 "dataLength": 2508,
    #                 "encodedDataLength": 0,
    #                 "requestId": "1000017222.7",
    #                 "timestamp": 28546.165782
    #             }
    #         }, timestamp=1594046643701)
    #
    # # Add Data Sample
    # interaction2.add_entry(entry2)
    #
    # entry2 = Entry(message={
    #             "method": "Network.loadingFinished",
    #             "params": {
    #                 "encodedDataLength": 228932,
    #                 "requestId": "1000017222.7",
    #                 "shouldReportCorbBlocking": False,
    #                 "timestamp": 28546.956789
    #             }
    #         }, timestamp=1594046644488)
    #
    # # Add Loading Finished
    # interaction2.add_entry(entry2)
