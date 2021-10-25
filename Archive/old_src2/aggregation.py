#!usr/bin/env python3.8
# aggregation.py
from typing import List
from colorama import Fore

RED = Fore.RED
BLUE = Fore.BLUE
GREEN = Fore.GREEN
RESET = Fore.RESET


# dns_threshold = 3  # time before dns isn't considered relevant
syn_threshold = 2  # first try -> split to two phases: early and late (turn to late after X secs)
                   # maby more phases later
rst_threshold = 5  # consecutive 'reset' pkts before flow considered closed


class Aggregation:

    def __init__(self, core_domain, disconnect_threshold, verbose=False):
        self.verbose = verbose
        self.dc_threshold = disconnect_threshold  # chosen n

        self.core = core_domain
        self.dns_time = None

        self.core_dns_q_pkt = None
        self.core_dns_q_pkt_id = 0

        self.reccurring_dns_q_str = None
        self.reccurring_dns_q_pkt_id = 0
        self.reccurring_core_ips = None

        self.core_ips = None
        self.subdoms = []

        self.expected_ip_syns = {}
        self.got_ip_syns = {}
        self.matching_ip_syns = []
        self.matched_all = False

        # for data [{'subdom': '','local_port': 0, 'remote_port': '', 'remote_ip': '', 'total_data': 0, 'last_arrived_t': None, 'idle_time': 0, 'assume_still_open': {'connrcted': True, 'explicit': True, 'reset': False}, 'resets': 0}, {...}, ...]
        self.connected = []
        self.closed_conns = []
        self.late_connects = []
        self.milestones = []

        self.finished = False
        self.first_finish = 0
        self.estimated_time = 0

        self.last_rec_data_t = None
        self.last_rec_data_conn = None
        self.useful_byes = 0

        self.last_rec_idle_t = None
        self.viseted_while_idle = 0
        self.current_idle_t = 0
        self.idle_times = []  # [{'idle_conn': conn, 'idle_time': 0}, {...}, ...]

    '''
        expected is an IP sniffed during SYN sniffing period of time 
        of async sniffer During entire time
    '''

    def add_actual_syn(self, local_port: int, ip: str, remote_port: int, timestamp: float):
        if self.verbose:
            print(f'add_actual : {ip} : {local_port}')

        subdom = self.is_expected(ip)

        if not subdom:
            if self.verbose:
                print(f"{RED}Syn Not Expected : {ip} (We wont care about it){RESET}")
            return

        conn = {'subdom': subdom,
                'local_port': local_port,
                'remote_port': remote_port,
                'remote_ip': ip,
                'total_data': 0,
                'last_arrived_t': timestamp,
                'idle_time': 0,
                'assume_still_open': {'connected': True, 'explicit': False, 'reset': False},
                'resets': 0
                }

        flag1 = False
        if self.dns_time:
            if (timestamp - self.dns_time) > syn_threshold:
                self.late_connects.append(conn)
                flag1 = True
        if not flag1:
            self.connected.append(conn)

        if self.last_rec_data_t is None:
            self.last_rec_data_t = timestamp

        # TODO Check if mached all - maybe not needed

    def is_expected(self, ip: str):
        flag = None
        # search if this syn was expected
        for subdom in self.expected_ip_syns:
            entry = self.expected_ip_syns[subdom]
            # if was expected
            if ip in entry:
                flag = subdom
                break
        return flag

    '''
        expected is a list(?) of DNS records (of IPs) sniffed during DNS sniffing period of time 
        of async sniffer AFTER DNS to core domain.
    '''

    def add_expected_syn(self, subdom: str, ips: List[str]):
        if self.verbose:
            print(f'add_expected - {subdom} - {ips}')
        self.subdoms.append(subdom)
        self.expected_ip_syns[subdom] = set(ips)

    def add_core_ans(self, ips: List[str]):
        if self.verbose:
            print(f'add_core_ans - {ips}')
        self.core_ips = ips
        self.expected_ip_syns[self.core] = set(ips)

    def add_reccurring(self, ips: List[str]):
        self.reccurring_core_ips = ips
        self.expected_ip_syns[self.reccurring_dns_q_str] = set(ips)

    def add_data(self, remote_addr:str, local_port: int, data_size:int, timestamp:float):
        # check if relevant
        for n, conn in enumerate(self.connected):
            if conn['assume_still_open']['connected']:
                # if data to one of conections
                if remote_addr == conn['remote_ip'] and local_port == conn['local_port']:
                    # if self.verbose: print(f'data ({data_size}b) in {conn["local_port"]} {conn["remote_ip"]} <- {timestamp}')
                    last_idol = timestamp - self.last_rec_data_t
                    # save idle time
                    self.idle_times.append({'idle_conn': self.last_rec_data_conn, 'idle_time': last_idol})

                    # add data and finalize
                    conn['idle_time'] = 0
                    conn['total_data'] += data_size
                    conn['last_arrived_t'] = self.last_rec_data_t = timestamp

                    self.useful_byes += data_size
                    self.current_idle_t = 0
                    self.last_rec_data_conn = conn
                    self.last_rec_idle_t = last_idol

                # else update idle times
                else:
                    self.check_idle(conn, timestamp)
            else:
                if self.verbose:
                    print(f'{BLUE}---> DATA RECIEVED FOR CONN THAT IS ASSUMED CLOASED ({conn["remote_ip"]} -> {conn["local_port"]}) <---{RESET}')
        # update total idle time
        if self.last_rec_data_t is None:
            return
        self.current_idle_t = timestamp - self.last_rec_data_t

    def check_idle(self, conn, timestamp):
        conn['idle_time'] = timestamp - conn['last_arrived_t']
        # if idle time of some connection exceeds some threshold
        if conn['idle_time'] > self.dc_threshold:
            if self.verbose:
                print(
                f"{RED} Conn :{conn['local_port']} -> {conn['remote_ip']}:{conn['remote_port']} is idling for {conn['idle_time']} milliseconds(<- ?)\n This Conn is Now Assumed Closed{RESET}")
            conn['assume_still_open']['connected'] = False
            self.closed_conns.append(conn)
            self.connected.remove(conn)
            # check if finnished (all connections assumed closed)
            if len(self.connected) == 0:
                if not self.finished:
                    self.finished = True
                    self.first_finish = timestamp
                    self.estimated_time = self.last_rec_data_t - self.dns_time
                self.milestones.append(timestamp - self.dns_time)
                if self.verbose:
                    print(f'{timestamp}{GREEN}Aggregation Assumed Finnish! -> Astimated Time = {self.estimated_time}{RESET}')

    def add_explicit_fin(self, local_port: int, remote_addr: str, timestamp: float):
        # search for it in connected
        for conn in self.connected:
            if remote_addr == conn['remote_ip'] and local_port == conn['local_port']:
                if self.verbose:
                    print(f'explicit fin {local_port} -> {remote_addr}')
                conn['assume_still_open']['connected'] = False
                conn['assume_still_open']['explicit'] = True
                self.closed_conns.append(conn)
                self.connected.remove(conn)
                return
            else:
                self.check_idle(conn, timestamp)

        # search for it in disconnected
        for conn in self.closed_conns:
            if remote_addr == conn['remote_ip'] and local_port == conn['local_port']:
                if self.verbose:
                    print(f'explicit fin {local_port} -> {remote_addr}')
                conn['assume_still_open']['explicit'] = True
                return

    def add_rst(self, local_port: int, remote_addr: str, timestamp: float):
        for conn in self.connected:
            if remote_addr == conn['remote_ip'] and local_port == conn['local_port']:
                conn['resets'] += 1
                if conn['resets'] > rst_threshold:
                    conn['assume_still_open']['connected'] = False
                    conn['assume_still_open']['reset'] = True
                    self.closed_conns.append(conn)
                    self.connected.remove(conn)
                    return
            else:
                self.check_idle(conn, timestamp)


class AggregationReturnContainer:
    def __init__(self,
                 aggregation: Aggregation,
                 throughput: float,
                 bytes_sent: int,
                 bytes_received: int,
                 raw_data_bytes: int):

        self.agg = aggregation
        self.tp = throughput
        self.bytes_s = bytes_sent
        self.bytes_r = bytes_received
        self.data_b = raw_data_bytes




