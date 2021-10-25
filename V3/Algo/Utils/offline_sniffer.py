#!/usr/bin/env python3

from scapy.all import Ether, RawPcapReader, IP, TCP, UDP, DNS
from parse import parse

from Utils.Containers.packet_containers import PacketInfo, PacketWindow
from Utils.Exceptions import PcapNotProvidedError, PcapAlreadyProvidedError, DnsNotFoundError, PcapNameNotSuitableError


class PcapAnalyser:

    def __init__(self, window_size: float, pcap_file_name: str = None):

        self.ready = True if pcap_file_name else False  # object ready for use
        self.__dns_found = False  # for window safety
        self.__window_time_start = None  # for window safety

        self.window_size = window_size  # `-t` arg

        self.n_last_requested_window = 0  # window numbering will start at 1

        self.__last_window_append_failed: PacketInfo = None  # for when windows reject packet on the count of being full

        if self.ready:
            self.__setup(pcap_file_name)

    def __setup(self, pcap_file_name):
        pcap_name_format = '{exp_id}.Delay{delay}.Loss{loss}.onLoad{:f}.{url}.pcap'

        # try to parse the pcap file name
        # (valid pcap will contain experiment id, url, loss%, delay and reported browser time)
        pcap_info = parse(pcap_name_format, pcap_file_name)

        # if parse was not successful
        if pcap_info is None:
            raise PcapNameNotSuitableError

        # extract info from file name
        self.pcap = pcap_file_name
        self.exp_id = pcap_info['exp_id']
        self.url = pcap_info['url']
        self.loss: int = pcap_info['loss']
        self.delay: int = pcap_info['delay']
        self.browser_time = pcap_info[0]

        # num of window that gets the label '1' (in this case signifies "the download has stopped")
        self.n_label_window = self.calc_window_num(self.browser_time, self.window_size)

        # read all packets
        self.packets = RawPcapReader(self.pcap)

        # init generator to produce 1 relevant packet at a time
        self.gen = self._generator()
        self.pcap_done = False

    def from_pcap(self, name: str):
        if self.ready:
            raise PcapAlreadyProvidedError

        self.ready = True
        self.__setup(name)
        return self

    def _generator(self):
        '''
        returns a single relevant packet at each call to `next()`
        '''
        # iteration on RawPcapReader will return tuple of packetData, packetMeta
        for data, meta in self.packets:
            pkt = Ether(data)  # turn from bytes to scapy object
            pkt_time = float(f'{meta.sec}.{meta.usec}')  # format pkt_time
            pkt_len = meta.wirelen

            # reasons to discard pkt:
            # if not ip packet
            if not pkt.haslayer(IP):
                continue

            ip_d = pkt[IP].dst
            ip_s = pkt[IP].src

            # check if incoming
            incoming = True if any(ip_d.startswith(x) for x in ['10.', '192.168.']) else False

            additional = None

            # determine flow protocol
            if pkt.haslayer(UDP):
                proto = 'UDP'
                port_s = pkt[UDP].sport
                port_d = pkt[UDP].dport

                if pkt.haslayer(DNS):
                    additional = self.handle_dns(pkt)

            elif pkt.haslayer(TCP):
                proto = 'TCP'
                port_s = pkt[TCP].sport
                port_d = pkt[TCP].dport

            # TBA

            else: proto = 'OTHER'

            yield PacketInfo(timestamp=pkt_time, size=pkt_len, incoming=incoming, ip_s=ip_s, ip_d=ip_d, port_s=port_s, port_d=port_d, proto=proto, additional=additional)

    @staticmethod
    def handle_dns(pkt):
        # print(pkt[DNS].show())
        # if A type query
        if pkt[DNS].qd.qtype == 1:
            q_str = pkt[DNS].qd.qname.decode('utf-8').lower()

            # # cleanup rule
            if any(x in q_str for x in ['local', 'connectivity', 'brave', 'linux', 'ubuntu', 'mint']):
                return None

            answers = None
            ans_count = 0
            # if contains answers as well
            if pkt[DNS].an:
                answers = []
                ans_count = pkt[DNS].ancount
                for i in range(ans_count):
                    # if A type answer
                    if pkt[DNS].an[i].type == 1:
                        ip_ans = pkt[DNS].an[i].rdata
                        print(f"{q_str} - > {str(ip_ans)}")
                        answers.append(ip_ans)
            # add to additional info
            additional = {'inner': 'DNS',
                          'query': q_str,
                          'ancount': ans_count,
                          'answers': answers}
            return additional
        return None

    def next_pkt(self) -> PacketInfo:
        '''
            Wrap function for packet generator.
            Will not call generator if window rejected packet during last try.
            Instead, returns the rejected packet
        '''
        if not self.ready:
            raise PcapNotProvidedError

        if self.__last_window_append_failed:
            ret = self.__last_window_append_failed
            self.__last_window_append_failed = None
        else:
            try:
                ret = next(self.gen)
            except StopIteration:
                self.pcap_done = True
                ret = None
        return ret

    def next_window(self) -> PacketWindow:
        '''
            Creates a Window of specified size `t` and fills it.
            If `next_pkt` returned `None`, window filling will stop and partial window returned as the pcap is now empty.
        '''
        if not self.__dns_found:
            raise DnsNotFoundError

        self.n_last_requested_window += 1
        label = True if self.n_last_requested_window == self.n_label_window else False

        window = PacketWindow(size=self.window_size, serial_num=self.n_last_requested_window, label=label)
        while window.append(None):
            # TODO
            #     change append to read packet
            #     determine what to do if append is successful
            pass

    def dns_found(self, timestamp: float):
        if self.__dns_found:
            # raise ValueError("DNS flagged as Found More Then Once")
            pass
        else:
            self.__dns_found = True
            self.__window_time_start = timestamp

    def reset_generator(self):
        if self.gen:
            del self.gen
            self.gen = self._generator()
        else:
            raise PcapNotProvidedError

    @staticmethod
    def calc_window_num(browser_t: float, delta_t: float) -> int:
        r_f = round(browser_t / delta_t)

        if r_f * delta_t < browser_t:
            r_f += 1

        return r_f


if __name__ == '__main__':
    # TEST
    pcapname = "../../rec7.pcap"
    pcap = PcapAnalyser()
    pcap1 = PcapAnalyser(pcapname)
    pcap2 = PcapAnalyser().from_pcap(pcapname)

    try:
        pcap.next_pkt()
    except ValueError:
        pass
    else:
        print("Empty analyzer succeeded in calling next_pkt!!")

    try:
        pcap1.next_pkt()
    except ValueError:
        print("Normal - Constructor - analyzer did not succeed in calling next_pkt!!")

    try:
        pcap2.next_pkt()
    except ValueError:
        print("Normal - From_Pcap - analyzer did not succeed in calling next_pkt!!")

    while 1:
        try:
            packet = pcap1.next_pkt()
            if packet: pass
            else:
                print("No Packet")
                break

        except KeyboardInterrupt:
            break