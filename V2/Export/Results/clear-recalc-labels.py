#!/usr/bin/env python3

import pandas as pd, argparse
from os.path import expanduser

browser_time_upper_threshold = 100

OLD_columns = ['experiment_id',
               'url',
               'pcap_name',
               'nom_loss',
               'calc_loss',
               'nom_latency',
               'calc_latency',
               'std_dev_rtt',
               'throughput_bytes',
               'd_redirect',
               'd_dns',
               'd_conn',
               'd_req',
               'd_res',
               'browser_onLoad_time',
               'time_delta',
               'label'
               ]

OLD_unwanted_columns = []

NEW_columns = ['experiment_id',
               'url',
               'pcap_name',
               'nom_loss(%)',
               'calc_loss_throughout_pcp(%)',
               'nom_latency(ms)',
               'calc_avg_rtt(ms)',
               'std_dev_rtt(ms)',
               'throughput(bytes)',
               'd_redirect(ms)',
               'd_dns(ms)',
               'd_conn(ms)',
               'TTFB(ms)',
               'd_res(ms)',
               'browser_onLoad_time(sec)',
               'time_delta(sec)',
               'label'
               ]

def calc_window_num(browser_t, delta_t):
    r_f = round(browser_t / delta_t)
    if r_f * delta_t < browser_t:
        r_f += 1
    return r_f
    
def get_args():
    parser = argparse.ArgumentParser(
        prog='sudo python3 clear_calc-labels.py [Options]',
        description='A Research Program That Opens a Given  CSV File' 
                    ', ReCalculates and Stores the Label Values back in the CSV file',
        epilog='Created by Daniel Lisachuk for FlashNetworks QoE Project'
    )

    parser.add_argument('-r', '--read-from',
                        dest='input_file',
                        default='/home/daniel/Studies/Third_year/QoEProject/Page_Load_POC/Export/Results/Master/Page_load_DF.csv',
                        help="Input CSV DataSet File.")

    return parser.parse_args()

def gen_out_name(in_name):
    tokens = in_name.split('/')
    tokens[-1] = 'Recalculated_' + tokens[-1]
    out_name = '/'.join(tokens)
    return out_name


def main():
    args = get_args()
    in_file = expanduser(args.input_file)

    df = pd.read_csv(in_file)
    print(f'whole file shape : {df.shape}')

    nulls = df[df['browser_onLoad_time(sec)'].isnull()]
    print(f'new version nulls shape : {nulls.shape}')

    if 'browser_onLoad_time' in df.columns:
        print('Cannot Continue with Recalc due to old version traces')
        print(f'indexes: {df[df[OLD_columns].notnull()]}')
        exit(0)

    unreasonably_high = df[df['browser_onLoad_time(sec)'] >= browser_time_upper_threshold]
    print(f'values over {browser_time_upper_threshold} shape : {unreasonably_high.shape}')
    df = df.drop(unreasonably_high.index)

    unreasonably_low = df[df['browser_onLoad_time(sec)'] <= 0]
    print(f'values under 0 shape : {unreasonably_low.shape}')
    df = df.drop(unreasonably_low.index)


    temp_count = 0
    limit = 3
    dict2 = {'label':[]}
    # TODO recalc label values
    print(df)
    for index, row in df.iterrows():

        new_label = int(calc_window_num(row['browser_onLoad_time(sec)'], row['time_delta(sec)']))
        # dict2['label'].append(new_label)
        new_val = pd.Series([new_label], name='label', index=[index])
        df.update(new_val)


        temp_count += 1
    # print(f"Dict len: {len(dict2['label'])}")
    # df.update(pd.DataFrame(dict2))
    print(df)

    # todo clean df and run merge on all dfs and import back all new results from machines that ran tests in lab and clean those to
##################################################################################################################

    out_name = gen_out_name(in_file)

    print(f'New Out File Shape : {df.shape}')
    print(f'New Out File Name : {out_name}')
    # export to new csv file labeled 'recalculated'
    df.to_csv(out_name, index=False)

if __name__ == '__main__':
    main()