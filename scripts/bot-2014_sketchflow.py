import os
import glob
from os.path import join
from multiprocessing import Pool
import math
from labeler import label_iscx_bot_2014
import time

dataroot = '/home/juma/data/net_intrusion/ISCX-Bot-2014/PCAPs'
num_of_layers =3
#num_of_ones,sampling_interval = 0,1
#num_of_ones,sampling_interval= 3,5.11604451868295
#num_of_ones,sampling_interval = 4,7.15183056968443
num_of_ones,sampling_interval = 5,9.76362232845268
counter_memory = 110


sampling_interval **=num_of_layers

def round_up(n, decimals=0):
    multiplier = 10 ** decimals
    return math.ceil(n * multiplier) / multiplier

def execute(cmd):
    os.system(cmd)

def ensure_dir(filename):
    if not os.path.exists(os.path.dirname(filename)):
        try:
            os.makedirs(os.path.dirname(filename))
        except OSError as exc: # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise

cmds = []
for pcap_file in glob.glob(join(dataroot,'*.pcap')):
        output_file = pcap_file.replace('PCAPs','CSVs/sk_sr_m_{}_mem_{}'.format(round_up(sampling_interval,2),counter_memory)).replace('.pcap','.pcap_Flow.csv')
        ensure_dir(output_file)
        cmd = "../sketchflow '{}' '{}' {} {} {} ".format(pcap_file,output_file,num_of_ones,sampling_interval, num_of_layers)
        cmds.append(cmd)
        print(cmd)

# multi-processing
tick = time.time()
p = Pool(processes=8)
#p.map(execute,cmds)
for cmd in cmds:
    execute(cmd)
tock = time.time()
print("Time taken {} sec".format(tock-tick))
#labeling
label_iscx_bot_2014(join(dataroot.replace('PCAPs','CSVs'),'sk_sr_m_{}_mem_{}'.format(round_up(sampling_interval,2),counter_memory)))

