#!usr/bin/env python3.8
# sniff.py


from scapy.all import sniff, AsyncSniffer, TCP, IP, DNS, ls as pkt_ls
from ipaddress import ip_address
from datetime import datetime
from time import sleep

from aggregation import Aggregation
from utils import local_dns, RED, GREEN, RESET, BLUE, CYAN

############################################################################################
# dict -> {'core_domain': 'ip_address', ...}
from utils import core_domains, aggregations

src_dst_set = set([])


############################################################################################


class CoreDomainSniffHandler:
    def __init__(self, domains_of_interest: list):
        if domains_of_interest is None:
            domains_of_interest = ['ynet.co.il', 'sissoiiisooos.com', 'ami']
        self.doi = domains_of_interest
        self.last_found = None
        self.spawned_sniffers = []
        sniff(prn=self.callback,
              # iface='wlp2s0',
              timeout=20,
              started_callback=lambda: print("Main Sniffer Started"),
              #TODO del after debug
              offline='/home/daniel/Studies/Third_year/QoEProject/Page_Load_POC/pcaps/ynet.pcapng')
              # )

    def callback(self, pkt):
        # if dns req to core:
        #     if not prev req
        #         new aggregation
        #           set dns timer
        #     else
        #         reset timer on aggregation
        if pkt.haslayer(TCP):
            if pkt[TCP].flags == 'S':
                src_dst = f"{pkt[IP].src} -> {pkt[IP].dst}"
                if src_dst not in src_dst_set:
                    src_dst_set.add(src_dst)
                    print(f"{BLUE}{src_dst}{RESET}")
            #
            #
            #     # check if core domain
            #     if pkt.src in core_domains.values():
            #         pass
            #         print(src_dst)
            #         # if yes - new listening
            #         # approach - count time instead of async
            #         #   - add new entry to global dict of {time:(core_d, [<SUB_DOMS>])}
            #         #       - later,
            #     # if not core domanin
            #     else:
            #         pass
            #         # if no - associate and aggregate with core domain

        elif pkt.haslayer(DNS):
            try:
                # if of type A
                if pkt[DNS].qd.qtype == 1:
                    # if query
                    if pkt[DNS].ancount == 0:
                        q_str = pkt[DNS].qd.qname.decode('utf-8').lower()
                        pkt_iface = pkt.sniffed_on
                        print(pkt.time)
                        if self.is_core_domain(q_str):
                            if q_str in [self.last_found, f"www.{self.last_found}"]:
                                print(f"{GREEN}{self.last_found} -> {q_str}{RESET}")
                            else:
                                sniff = SubDomainSniffHandler(pkt_iface, pkt, core_domain=q_str)
                                sniff.sniff()
                                self.spawned_sniffers.append(sniff)
                            self.last_found = q_str

                        elif 'local' in q_str or 'connectivity' in q_str:
                            print(f"{q_str} {RED}was dropped{RESET}")

                    # if answer
                    elif pkt[DNS].ancount != 0:
                        potential_syns = []
                        # for each answer
                        for i in range(pkt[DNS].ancount):
                            ans = str(pkt[DNS].an[i].rdata)
                            # check if valid ip
                            if self.is_valid_ip(ans):
                                # store it
                                potential_syns.append(ans)

                        # if core answer
                        if pkt[DNS].id == self.core_dns_req_pkt[DNS].id:
                            self.core_dns_res_pkt = pkt
                            # update aggregation
                            self.aggregation.add_core_ans(potential_syns)
                        else:
                            # update aggregation
                            self.aggregation.add_expected(subdom=pkt[DNS].qd.qname.decode('utf-8').lower(),
                                                          ips=potential_syns)

            except AttributeError:
                pass

    def is_core_domain(self, dns_q):
        # check 2 formats:
        #     'amitdvir.com.'       -#> no 'www'
        #     'www.amitdvir.com.'   -#> with 'www'
        for domain in self.doi:
            if dns_q in f"{domain}." or dns_q in f"www.{domain}.":
                return True
        return False

    def is_valid_ip(self, ans):
        try:
            ip_address(ans)
            return True
        except ValueError:
            return False


############################################################################################


class SubDomainSniffHandler:
    def __init__(self,
                 iface,
                 core_dns_req_pkt,
                 on_start=lambda: print(f"[+] TCP Sniffer Started"),
                 core_domain=None,
                 idletime=6,
                 dns_time=2):

        # AGGREGATION
        self.aggregation = Aggregation(creation_time=datetime.now(), core_domain=core_domain)

        # CORE DNS RECORDS
        self.core_dns_req_pkt = core_dns_req_pkt
        self.core_dns_res_pkt = None

        # SNIFFER FUNCS
        self.onstart = on_start
        self.core = core_domain

        # HARDWARE INFO
        self.iface = iface

        # FILTERS
        self.tcp_filter = f"tcp and host {self.core_dns_req_pkt[IP].src}"
        self.dns_filter = f"udp port 53 and host {local_dns} and host {self.core_dns_req_pkt[IP].src}"

        # STATUSES
        self.sniffing = False
        self.stopped = True  # legit stop (last session idle fot dt time), non-legit TBI
        self.dns_period = True  # still sniffing requests

        # SNIFFERS
        self.sniffer = AsyncSniffer(prn=self.callback_f,  # got_pkt()
                                    filter=f"{self.tcp_filter} or {self.dns_filter}",  # BFG filter
                                    iface=self.iface,
                                    started_callback=self.onstart,  # on_ready()
                                    # TODO del after debug
                                    # offline='/home/daniel/Studies/Third_year/QoEProject/Page_Load_POC/pcaps/ynet.pcapng'
                                    )
        # TODO Set Timer for stopping collection of DNS records

        # TIMERS
        self.dns_timer = None
        self.idle_timer = None

    def sniff(self):
        if not self.sniffing:
            self.sniffer.start()
            self.sniffing = True
        else:
            raise RuntimeError("[!] Sniffer Started More Then Once")

    def stop(self):
        if self.sniffing:
            self.sniffer.stop()
            self.sniffing = False
        else:
            raise RuntimeError("[!] Sniffer Stopped But Not Started")

    def stop_dns(self):
        self.dns_period = False

    def callback_f(self, pkt):
        '''callback to open core session sniffer'''






if __name__ == "__main__":
    pass

