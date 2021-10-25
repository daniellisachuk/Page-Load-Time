#!usr/bin/env python3.8
# Ideas.py

# External Imports
from time import sleep

# Internal Imports
from arguments import ArgParser
from sniff import CoreDomainSniffHandler, SubDomainSniffHandler

args = ArgParser()
sniff = CoreDomainSniffHandler(domains_of_interest=None)