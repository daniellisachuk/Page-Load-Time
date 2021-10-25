#!/usr/bin/env/ python3
from subprocess import call, check_output
import pandas

curr = {'latency': 0, 'loss': 0}
iface = None


def create_netem(interface):
    global iface
    iface = interface
    call(['sudo', 'tc', 'qdisc', 'add', 'dev', f'{iface}', 'root', 'netem'])


def change_net_conditions():
    call(['sudo', 'tc', 'qdisc', 'change', 'dev', f'{iface}', 'root', 'netem', 'delay', f"{curr['latency']}ms", 'loss',
          f"{curr['loss']}%"])


def gen_latency():
    latencies = [0, 20, 50, 100, 150]
    for t in latencies:
        # change latency
        curr['latency'] = t
        change_net_conditions()
        yield t


def gen_loss():
    losses = [0, 2, 5, 7, 10]
    for p in losses:
        # change latency
        curr['loss'] = p
        change_net_conditions()
        yield p


# throughput == bandwidth
# def get_throughput(pcap_name: str):
#     # write pcap info (wireshark-suite) to csv
#     csv = check_output(['capinfos', '-Tm', f'{pcap_name}'])  # >> test.csv
#     with open('test.csv', 'w') as f:
#         f.write(str(csv))
#     # the value we need is (as i understand) either "Data Bit Rate" or "Data Byte Rate"
#
#     csv = pandas.read_csv("test.csv")
#     # csv only has one row
#     bit_rate = csv['Data bit rate (bits/sec)'].values[0]
#     byte_rate = csv['Data byte rate (bytes/sec)'].values[0]
#
#     return bit_rate, byte_rate


def restore_network_conditions():
    call(['sudo', 'tc', 'qdisc', 'del', 'dev', f'{iface}', 'root', 'netem'])

