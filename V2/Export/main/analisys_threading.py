#!/usr/bin/env python3

from algo import analyze_pcap
import math


def thread_func(pcap_name: str,
                core_dom: str,
                browser_time: float,
                nominal_loss: int,
                nominal_delay: int,
                logger_func,
                verbose: bool = False):
    # run analisys with n ranging from 0.0 to 19.95 seconds
    line = 0
    tp = 0
    # for n in range(20):  # ORIG
    #     for i in range(0, 100, 5):  # ORIG
    # 0.0 sec - 19.95 -> 0.05
    for n in range(2):  # TEST
        for i in range(0, 10, 5):  # TEST
            # run analysis
            current_n = float(f"{n}.{i}")
            aggregation_resault = analyze_pcap(pcap_name, core_dom, current_n, verbose)
            est_timing = aggregation_resault.agg.estimated_time

            # check if tp is OK
            if tp == 0:
                tp = aggregation_resault.tp
            elif aggregation_resault.tp != tp:
                raise ValueError(f"[!] For {core_dom} : first throughput was {tp} and on loop {current_n} got {aggregation_resault.tp}")

            # ratio1 = get_ratioV1(browser_time, est_timing)
            # label1 = get_label(ratio1)

            ratio2 = get_ratioV2(browser_time, est_timing)
            label2 = get_label(ratio2)

            log_results(func=logger_func,
                        core_dom=core_dom,
                        pcap_name=pcap_name,
                        b_time=browser_time,
                        e_time=est_timing,
                        delay=nominal_delay,
                        loss=nominal_loss,
                        tp=tp,
                        n=current_n,
                        # label=label1)
                        label=label2)

            line += 1


def get_ratioV1(browser_time, estimated_time):
    # Ver-1
    ratio = estimated_time / browser_time
    return ratio


def get_ratioV2(browser_time, estimated_time):
    # Ver-2
    diff = math.fabs(estimated_time - browser_time)
    ratio = diff * browser_time * 0.01
    return ratio


def get_label(ratio):
    # Ver-1
    '''gaossal bell function maxing at ~1 (0.997) (tested on desmos)'''
    width_factor = 1
    return 2.5 / (math.sqrt(2 * math.pi) * math.pow(math.e, math.pow(ratio, 2) / width_factor))


def log_results(func, core_dom, pcap_name, b_time, e_time, delay, loss, tp, n, label):
    func(url=core_dom, pcap_name=pcap_name, b_time=b_time, latency=delay, loss=loss, throughput_bytes=tp, est_time=e_time, chosen_n=n, label=label)


if __name__ == "__main__":
    thread_func("rec7.pcap")