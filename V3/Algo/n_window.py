#!/usr/bin/env python3

from argparse import ArgumentParser
from Utils.offline_sniffer import PcapAnalyser
from Utils.Containers.packet_containers import *


def get_args():
    parser = ArgumentParser(
        prog='python3 n_window',
        description='A Research Program Search Through pcap Files and Extract ML Features,'
                    ' Calculates and Stores the Results in a CSV file',
        epilog='Created by Daniel Lisachuk for FlashNetworks QoE Project'
    )

    parser.add_argument('-d', '--base-dir',
                        dest='base_dir',
                        metavar='<PCAP_DIR>',
                        default='../pcaps/v3/',
                        help="base Dir to search pcaps from (Default: POC/V3/pcaps/v3/)")

    parser.add_argument('-n',
                        dest='n',
                        metavar='<QUEUE_SIZE>',
                        type=int,
                        required=True,
                        help="Total Window Queue Size (in `-t` sec Windows)")

    parser.add_argument('-t',
                        dest='t',
                        metavar='<WINDOW_SIZE>',
                        type=float,
                        required=True,
                        help="Single Window Size (format: <WINDOW_SIZE> * 1sec)")

    parser.add_argument('-w', '--write-to',
                        dest='output_file',
                        default='../Dataset/V3.csv',
                        help="Output CSV File (Default: POC/V3/Dataset/V3.csv)")

    parser.add_argument('mode',
                        choices=['future', 'history'],
                        required=True,
                        help='Choose Mode to Build Dataset')

    # parser.add_argument('-', '--',
    #                     dest='',
    #                     default='',
    #                     help="")

    return parser.parse_args()

def main():
    args = get_args()

    pcap = PcapAnalyser(pcap_file_name='../rec7.pcap', window_size=args.t)



if __name__ == '__main__':
    main()