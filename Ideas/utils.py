#!/usr/bin/env python3.8
# utils.py

from colorama import init, Fore


# dict for core domains and ips
core_domains = {}

# dict for aggregations and opening times
aggregations = {}


# Fore: BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE, RESET.
init()
RED = Fore.RED
CYAN = Fore.CYAN
GREEN = Fore.GREEN
BLUE = Fore.BLUE
RESET = Fore.RESET

# TODO generalize local dns
local_dns = '10.0.0.138'
