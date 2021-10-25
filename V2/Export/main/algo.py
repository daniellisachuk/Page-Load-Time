from io import BytesIO
from typing import Union

from scapy.all import Ether, RawPcapReader, TCP, DNS, IP, Raw, load_layer, ls
from aggregation import Aggregation, AggregationReturnContainer
from datetime import datetime
from ipaddress import ip_address
from colorama import init, Fore
from pandas import DataFrame as DF, read_csv
from subprocess import Popen, PIPE

init()
RED = Fore.RED
CYAN = Fore.CYAN
GREEN = Fore.GREEN
BLUE = Fore.BLUE
RESET = Fore.RESET

last_found_pkt = None
last_found_str = ''


def analyze_pcap(pcap_name: str, core_domain: str, disconnect_threshold: float, v_verbose: bool = False) -> AggregationReturnContainer:
    global last_found_pkt
    global last_found_str

    first_pkt_t = None  # First timestamp in pcap (recording start time)

    # last_outgoing_ack = None
    # last_ingoing_ack = None

    total_bytes = 0
    bytes_sent = 0
    bytes_received = 0

    # Answers
    throughput = 0  # bytes/sec
    aggregation = Aggregation(core_domain, disconnect_threshold, v_verbose=v_verbose)
    packets = 0

    pcap = RawPcapReader(pcap_name)
    for data, meta in pcap:
        pkt = Ether(data)  # turn from bytes to scapy object
        pkt_time = float(f'{meta.sec}.{meta.usec}')  # format pkt_time
        pkt_len = meta.wirelen

        #~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~# THROUGHPUT #~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#~#
        # update total bytes and packets
        total_bytes += pkt_len
        packets += 1

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
            # load_layer("tls")
            # if we are not into the core domain
            if not aggregation.dns_time:
                continue

            # if is syn packet (connection initiation)
            if pkt[TCP].flags == 'S':
                if pkt.haslayer(Raw):
                    if v_verbose:
                        print(f'{RED} PKT {pkt.show()} HAS SYN FLAG AND RAW LOAD!!{RESET}')
                    exit(-1)
                dst = pkt[IP].dst
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport

                if v_verbose:
                    print(f'{CYAN}Syn Was Detected : {dst}{RESET}')
                aggregation.add_actual_syn(sport, dst, dport, pkt_time)


            # will do work only on first syn-ack seen - calc initial rtt
            elif pkt[TCP].flags == 'SA' and aggregation.initial_rtt == 0:
                aggregation.initial_rtt = pkt_time - aggregation.first_syn_time

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
                        if v_verbose:
                            print(q_str)
                            print(pkt_time)

                        # if recurring dns (like querying "www.godaddy.com" right after "godaddy.com")
                        # check first so no mix-ups
                        if q_str in [last_found_str, f"www.{last_found_str}"]:
                            # answers will make more potential core ips (or separate?)
                            if v_verbose:
                                print(f"{GREEN}{last_found_str} -> {q_str}{RESET}")
                            aggregation.reccurring_dns_q_str = q_str
                            aggregation.reccurring_dns_q_pkt_id = pkt[DNS].id

                        # if is core domain query
                        elif q_str in [f'{core_domain}.', f'www.{core_domain}.']:
                            # save core dns pkt itself
                            aggregation.core_dns_q_pkt = pkt
                            aggregation.core_dns_q_pkt_id = pkt[DNS].id
                            aggregation.dns_time = pkt_time
                            if v_verbose:
                                print(f'{GREEN}Found Core DNS - Added Core Domain : {CYAN}{q_str}{RESET}')

                        # if OS or browser noise
                        elif 'local' in q_str or 'connectivity' in q_str or 'brave' in q_str:
                            # see if still relevant
                            if v_verbose:
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
                                if v_verbose:
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

    df = get_tshark_df(pcap_name)
    avg_rtt, std_dev_rtt = calc_rtt(df)
    loss = calc_loss(df)

    return AggregationReturnContainer(aggregation, loss, avg_rtt, std_dev_rtt, throughput, bytes_sent, bytes_received, aggregation.useful_byes)


def is_valid_ip(ans: str) -> bool:
    try:
        ip_address(ans)
        return True
    except ValueError:
        return False


def calc_rtt(df: DF):
    # get all rows in df where column tcp.analysis.ack_rtt is not null
    ack_rtts = df[~df['tcp.analysis.ack_rtt'].isnull()]['tcp.analysis.ack_rtt']
    avg_rtt = ack_rtts.mean()
    rtt_std_dev = ack_rtts.std()
    return avg_rtt, rtt_std_dev


def calc_loss(df: DF):
    # get all rows in df where column tcp.analysis.retransmission is not null
    retransmissions = df[~df['tcp.analysis.retransmission'].isnull()]['tcp.analysis.retransmission']
    return (len(retransmissions) / len(df)) * 100  # return percentage

# TODO add STD_DEVIATION

def get_tshark_df(pcap_name: str):
    cmd = f'tshark -r {pcap_name} -T fields -e frame.number ' \
                                           '-e frame.len ' \
                                           '-e tcp.analysis.duplicate_ack ' \
                                           '-e tcp.analysis.retransmission ' \
                                           '-e tcp.analysis.ack_rtt ' \
                                 '-E header=y -E separator=, -E quote=n -E occurrence=f'.split()

    # run command -> byte sequance of csv string of command results
    tshark = Popen(cmd, stdout=PIPE)
    csv = tshark.communicate()[0]

    # input csv byte seq. into dataframe
    current_df = read_csv(BytesIO(csv))
    return current_df





if __name__ == '__main__':
    from sys import argv
    start = datetime.now()
    chosen_n = float(argv[1])


    # agg = analyze_pcap('rec2.pcap', 'yellow.co.il')
    # agg = analyze_pcap('rec3.pcap', 'codecademy.com')
    # agg = analyze_pcap('rec4.pcap', 'amitdvir.com')
    # agg = analyze_pcap('rec5.pcap', 'pickuplimes.com')
    # agg = analyze_pcap('rec6.pcap', 'walla.co.il')
    agg, tp = analyze_pcap('../Archive/old_src2/rec7.pcap', 'bbc.com', chosen_n, v_verbose=True)

    print(f"throughput = {int(tp)/1000}kB/sec")

    print(f'estimated time = {GREEN}{agg.estimated_time}{RESET}')
    print(f'{len(agg.connected)} connections not closed:')
    for conn in agg.connected:
        print(f'\t* {conn["local_port"]} -> {conn["remote_ip"]}{conn["remote_port"]} recorded idle for {conn["idle_time"]}')

    print(f'finnished: {agg.finished}')
    print(f'milestones: {agg.milestones}')

    print(f"analysing time = {str(datetime.now() - start)}")


