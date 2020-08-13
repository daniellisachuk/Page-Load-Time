
# Selenium Performance Log Parser
class PerfLogParser():
    def __init__(self, raw_selenium_perf_log: dict):
        self.raw_log = raw_selenium_perf_log
        self.interactions = {}
        self.avg_data_size = -1
        self.total_data_size = -1
        self.avg_rtt = -1
        self.time_elepsed = -1
        self.served_from_cache = []
        self.page_entries = []

        self.doc = None
        self.images = []
        self.style_sheets = []
        self.xhrs =  []

    def get_interactions_size(self):
        return len(self.interactions)

    def get_avg_data_size(self):
        pass

    def get_total_data_size(self):
        pass

    def get_avg_rtt(self):
        pass

    def get_total_elepsed_time(self):
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
class Interaction:
    def __init__(self, interaction_id: int):
        # Key -> interaction ID (== requestId)
        self.ID = interaction_id

        # Entries
        self.req = None
        self.res = None
        self.redirect = None
        self.data = []
        self.complete = None

        # Stats
        self.type = None
        self.remote_addr = None
        self.time_elepsed = -1
        self.dns_times = -1
        self.data_size = None
        self.avg_rtt = -1

    def def_get_obj_type(self):
        pass

    def get_data_size(self):
        pass

    def get_avg_data_packet_size(self):
        pass

    def get_elapsed_time(self):
        pass

    def get_avg_rtt(self):
        pass

    def get_dns_time(self):
        pass

    def get_response_time(self):
        pass


# Container for log entries
class Entry:
    def __init__(self, message: dict, timestamp: int):
        self.message = message
        self.timestamp = timestamp
