#!/usr/bin/env python3

class POCError(Exception):
    def __init__(self):
        pass


class SnifferError(POCError):
    pass


class DnsNotFoundError(SnifferError):
    pass


class PcapAlreadyProvidedError(SnifferError):
    pass


class PcapNotProvidedError(SnifferError):
    pass


class PcapNameNotSuitableError(SnifferError):
    pass


class PcapDoneError(SnifferError):
    pass

