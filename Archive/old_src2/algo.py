from typing import Union

from scapy.all import Ether, RawPcapReader, TCP, DNS, IP, Raw, load_layer, ls
from aggregation import Aggregation, AggregationReturnContainer
from datetime import datetime
from ipaddress import ip_address
from colorama import init, Fore

init()
RED = Fore.RED
CYAN = Fore.CYAN
GREEN = Fore.GREEN
BLUE = Fore.BLUE
RESET = Fore.RESET

last_found_pkt = None
last_found_str = ''


def analyze_pcap(pcap_name: str, core_domain: str, disconnect_threshold: float, verbose: bool = False) -> AggregationReturnContainer:
    global last_found_pkt
    global last_found_str

    first_pkt_t = None  # first timestamp in pcap (recording start time)

    total_bytes = 0
    bytes_sent = 0
    bytes_received = 0

    # Answers
    throughput = 0  # bytes/sec
    aggregation = Aggregation(core_domain, disconnect_threshold, verbose=verbose)

    pcap = RawPcapReader(pcap_name)
    for data, meta in pcap:
        pkt = Ether(data)  # turn from bytes to scapy object
        pkt_time = float(f'{meta.sec}.{meta.usec}')  # format pkt_time
        pkt_len = meta.wirelen

        #~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~# THROUGHPUT #~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#
        # update total bytes
        total_bytes += pkt_len

        # update throughput
        if not first_pkt_t:
            first_pkt_t = pkt_time
        else:
            throughput = total_bytes / (pkt_time - first_pkt_t)

        # update total sent
        if pkt.haslayer(IP):
            if any(x in pkt[IP].src for x in ['10.', '192.168.']):
                bytes_sent += pkt_len
            else:  # total received
                bytes_received += pkt_len



        #~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~# TCP #~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#
        if pkt.haslayer(TCP):
            load_layer("tls")
            # if we are into the core domain
            if not aggregation.dns_time:
                continue

            # if is syn packet (connection initiation)
            if pkt[TCP].flags == 'S':
                if pkt.haslayer(Raw):
                    if verbose:
                        print(f'{RED} PKT {pkt.show()} HAS SYN FLAG AND RAW LOAD!!{RESET}')
                    exit(-1)
                dst = pkt[IP].dst
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport

                if verbose:
                    print(f'{CYAN}Syn Was Detected : {dst}{RESET}')
                aggregation.add_actual_syn(sport, dst, dport, pkt_time)

            # if explicit fin
            elif 'F' in pkt[TCP].flags:
                if pkt[IP].src.startswith('192.168.') or pkt[IP].src.startswith('10.0.'):
                    aggregation.add_explicit_fin(local_port=pkt[TCP].sport, remote_addr=pkt[IP].dst, timestamp=pkt_time)
                else:
                    aggregation.add_explicit_fin(local_port=pkt[TCP].dport, remote_addr=pkt[IP].src, timestamp=pkt_time)

            # if resets
            elif 'R' in pkt[TCP].flags:
                if pkt[IP].src.startswith('192.168.') or pkt[IP].src.startswith('10.0.'):
                    aggregation.add_rst(local_port=pkt[TCP].sport, remote_addr=pkt[IP].dst, timestamp=pkt_time)
                else:
                    aggregation.add_rst(local_port=pkt[TCP].dport, remote_addr=pkt[IP].src, timestamp=pkt_time)



            # if is data pkt
            elif pkt.haslayer(Raw):
                # print(f'{CYAN}DATA ON {GREEN}{pkt_time}{CYAN} FROM {pkt[IP].src}:{pkt[TCP].sport} to port {pkt[TCP].dport}{RESET} -> {len(pkt[Raw].load)} -> {                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      pkt[Raw].load}')
                remote_addr = pkt[IP].src
                local_port = pkt[TCP].dport
                aggregation.add_data(remote_addr=remote_addr, local_port=local_port, data_size=len(pkt[Raw].load), timestamp=pkt_time)


        #~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~# DNS #~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#
        elif pkt.haslayer(DNS):
            try:
                # if of type A
                if pkt[DNS].qd.qtype == 1:
                    # QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ #
                    # if query
                    q_str = pkt[DNS].qd.qname.decode('utf-8').lower()
                    if pkt[DNS].ancount == 0:
                        # query string
                        if verbose:
                            print(q_str)
                            print(pkt_time)

                        # if recurring dns (like querying "www.godaddy.com" right after "godaddy.com")
                        # check first so no mix-ups
                        if q_str in [last_found_str, f"www.{last_found_str}"]:
                            # answers will make more potential core ips (or separate?)
                            if verbose:
                                print(f"{GREEN}{last_found_str} -> {q_str}{RESET}")
                            aggregation.reccurring_dns_q_str = q_str
                            aggregation.reccurring_dns_q_pkt_id = pkt[DNS].id

                        # if is core domain query
                        elif q_str in [f'{core_domain}.', f'www.{core_domain}.']:
                            # save core dns pkt itself
                            aggregation.core_dns_q_pkt = pkt
                            aggregation.core_dns_q_pkt_id = pkt[DNS].id
                            aggregation.dns_time = pkt_time
                            if verbose:
                                print(f'{GREEN}Found Core DNS - Added Core Domain : {CYAN}{q_str}{RESET}')

                        # if OS or browser noise
                        elif 'local' in q_str or 'connectivity' in q_str or 'brave' in q_str:
                            # see if still relevant
                            if verbose:
                                print(f"{q_str} {RED}was dropped{RESET}")

                        # if subdom
                        else:
                            pass
                        last_found_pkt = pkt
                        last_found_str = q_str

                    # AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA #
                    # if answer
                    elif pkt[DNS].ancount != 0:
                        potential_syns = []
                        # for each answer
                        for i in range(pkt[DNS].ancount):
                            ans = str(pkt[DNS].an[i].rdata)
                            # check if valid ip
                            if is_valid_ip(ans):
                                # store it
                                potential_syns.append(ans)

                        # if core answer
                        if pkt[DNS].id == aggregation.core_dns_q_pkt_id:
                            # core_dns_res_pkt = pkt
                            # update aggregation
                            aggregation.add_core_ans(potential_syns)

                        # if reccurring query answer
                        elif pkt[DNS].id == aggregation.reccurring_dns_q_pkt_id:
                            # create seperate field for this?
                            aggregation.add_reccurring(potential_syns)

                        # if subdom answer
                        else:
                            # if os or browser noise
                            if 'local' in q_str or 'connectivity' in q_str or 'brave' in q_str:
                                # see if still relevant
                                if verbose:
                                    print(f"{q_str} {RED}was dropped{RESET}")

                            # update aggregation
                            elif q_str:
                                aggregation.add_expected_syn(subdom=q_str,
                                                             ips=potential_syns)
                            else:
                                aggregation.add_expected_syn(subdom="None",
                                                             ips=potential_syns)

            except AttributeError as e:
                print(f'{RED}AN ERROR HAS OCCURRED{RESET}:{e}')

    return AggregationReturnContainer(aggregation, throughput, bytes_sent, bytes_received, aggregation.useful_byes)


def is_valid_ip(ans: str) -> bool:
    try:
        ip_address(ans)
        return True
    except ValueError:
        return False


if __name__ == '__main__':
    from sys import argv
    start = datetime.now()
    chosen_n = float(argv[1])


    # agg = analyze_pcap('rec2.pcap', 'yellow.co.il')
    # agg = analyze_pcap('rec3.pcap', 'codecademy.com')
    # agg = analyze_pcap('rec4.pcap', 'amitdvir.com')
    # agg = analyze_pcap('rec5.pcap', 'pickuplimes.com')
    # agg = analyze_pcap('rec6.pcap', 'walla.co.il')
    agg, tp = analyze_pcap('rec7.pcap', 'bbc.com', chosen_n, verbose=True)

    print(f"throughput = {int(tp)/1000}kB/sec")

    print(f'estimated time = {GREEN}{agg.estimated_time}{RESET}')
    print(f'{len(agg.connected)} connections not closed:')
    for conn in agg.connected:
        print(f'\t* {conn["local_port"]} -> {conn["remote_ip"]}{conn["remote_port"]} recorded idle for {conn["idle_time"]}')

    print(f'finnished: {agg.finished}')
    print(f'milestones: {agg.milestones}')

    print(f"analysing time = {str(datetime.now() - start)}")


