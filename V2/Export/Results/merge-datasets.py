#!/usr/bin/env python3

import pandas as pd
from os import walk, path
import argparse

columns = ['experiment_id',
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

parser = argparse.ArgumentParser(
        prog='sudo python3 merge-datasets.py [Options]',
        description='A Research Program That Opens CSV files (Given in a path),'
                    ' Merges the Datasets and Stores Values in a Master CSV file',
        epilog='Created by Daniel Lisachuk for FlashNetworks QoE Project'
    )
parser.add_argument('-b', '--base-dir',
                    dest='base_dir',
                    default='/home/daniel/Studies/Third_year/QoEProject/Page_Load_POC/Export/Results/',
                    help="Base directory to merge CSV DataSets from.")

parser.add_argument('-o', '--output-dir',
                    dest='out_dir',
                    default='/home/daniel/Studies/Third_year/QoEProject/Page_Load_POC/Export/Results/Master',
                    help="Target directory to merge CSV DataSets to.")

args = parser.parse_args()
csv_file_dfs = []

for current_dir, sub_dirs, files in walk(args.base_dir):
    for file in files:
        if file.startswith('Recalculated') and file.endswith('.csv'):
            print(f"Found File {f'{current_dir}/{file}'}... Appending...")
            df = pd.read_csv(path.join(current_dir, file))
            df = df[~df[columns].isnull()]
            df = df[columns]
            csv_file_dfs.append(df)

df_len = 0
new_total_df = pd.DataFrame()
for df in csv_file_dfs:
    new_total_df = pd.concat([df, new_total_df], ignore_index=True)
    df_len += len(df)

out_file = path.join(args.out_dir, 'PLT_DataSet.csv')
try:
    existing_total_df = pd.read_csv(out_file)
    pd.concat([existing_total_df, new_total_df], ignore_index=True).to_csv(out_file, index=False)
except FileNotFoundError:
    new_total_df.to_csv(out_file, index=False)
# print(len(new_total_df))