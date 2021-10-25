#!usr/bin/env python3.8
# arguments.py

# Imports
import argparse


class ArgParser:
    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-t', '--delta-time',
                            help='delta time in seconds (default = 30)',
                            metavar='<TIME>',
                            type=int,
                            dest='dt',
                            default=30,
                            required=False)
        parser.add_argument('-d', '--domains-of-interest',
                            help='csv file containing domains of interest and thair ips',
                            metavar='<CSV_FILE>',
                            dest='doi',
                            required=True)
        parser.add_argument('-i', '--interface',
                            help='Interface to sniff on',
                            metavar='<IFACE>',
                            type=str,
                            dest='iface',
                            required=True)
        # parser.add_argument()
        args = parser.parse_args()

        # mem. management
        del parser

        # print(args)
        self.dt = args.dt
        self.doi = args.doi
        self.iface = args.iface


if __name__ == "__main__":
    args = ArgParser()
    print(args.dt)
    print(args.doi)
    print(args.iface)

