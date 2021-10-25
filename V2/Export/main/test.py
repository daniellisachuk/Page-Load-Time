from subprocess import Popen, PIPE
from pandas import DataFrame as DF
import numpy as np

def test(pcap_name: str):
    cmd = f'tshark -r {pcap_name} -T fields -e frame.number ' \
                                          f'-e frame.len ' \
                                          f'-e tcp.analysis.duplicate_ack ' \
                                          f'-e tcp.analysis.retransmission ' \
                                          f'-e tcp.analysis.ack_rtt ' \
                                f'-E header=y -E separator=, -E quote=n -E occurrence=f'.split()
    tshark = Popen(cmd, stdout=PIPE)
    list = tshark.communicate()[0].split(b'\n')

    # doesn't work with iterator for some reason
    for i in range(len(list)):
        list[i] = list[i].split(b',')

    df = DF(columns=list[0], data=list[1:], dtype=np.float64)

    print(df)

running = False
def test_2():

test('/home/daniel/Studies/Third_year/QoEProject/Page_Load_POC/Archive/old_src2/rec7.pcap')

# cmd1 = f'tshark -r {pcap_name} -T fields -e frame.number ' \
#       f'-e frame.len ' \
#       f'-e tcp.analysis.duplicate_ack ' \
#       f'-e tcp.analysis.retransmission ' \
#       f'-e tcp.analysis.ack_rtt ' \
#       f'-E header=y -E separator=, -E quote=n -E occurrence=f'.split()
#
# cmd1 = f'tshark -r {pcap_name} -T fields '\
#       f'-e tcp.analysis.duplicate_ack ' \
#       f'-e tcp.analysis.retransmission ' \
#       f'-e tcp.analysis.ack_rtt ' \
#       f'-E header=y -E separator=, -E quote=n -E occurrence=f'.split()