import os
import glob
from os.path import join
from multiprocessing import Pool
import numpy as np
import math
import time
from labeler import label_ids_2018


def round_up(n, decimals=0):
    multiplier = 10 ** decimals
    return math.ceil(n * multiplier) / multiplier

dataroot = '/home/juma/data/net_intrusion/CIC-IDS-2018/PCAPs'
num_of_layers =3 
num_of_ones = 5
sampling_interval = 9.76362232845268

sampling_interval **= num_of_layers

NUM_OF_CORES= 12 

def get_immediate_subdirs(a_dir):
    return [name for name in os.listdir(a_dir)
            if os.path.isdir(os.path.join(a_dir, name))]

def execute(cmd):
    print(cmd)
    os.system(cmd)

def ensure_dir(filename):
    if not os.path.exists(os.path.dirname(filename)):
        try:
            os.makedirs(os.path.dirname(filename))
        except OSError as exc: # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise

def get_num_concurrent_flows(output_file,d,pcap_filename):
    i = output_file.find('sk_sr_')
    fpath = join(output_file[:i], 'sf_sr_1/',d, pcap_filename.replace('.pcap','.pcap_Flow.csv.nflows'))
    with open(fpath,'r') as f:
        n = f.readline()
        print(fpath,n)
    return n 

subdirs = get_immediate_subdirs(dataroot)
print(subdirs)
cmds = []
for d in subdirs:
    #for pcap_file in glob.glob(join(dataroot,d,'*.pcap')):
    for pcap_filename in os.listdir(join(dataroot,d)):
        pcap_file = join(dataroot,d,pcap_filename)
        output_file = pcap_file.replace('PCAPs','CSVs/sk_sr_{}_mem'.format(round_up(sampling_interval,2))).replace('.pcap','.pcap_Flow.csv')
        num_concurrent_flows  = get_num_concurrent_flows(output_file,d,pcap_filename)
        ensure_dir(output_file)
        cmd = "../sketchflow '{}' '{}' {} {} {} {}".format(pcap_file,output_file,num_of_ones,sampling_interval, num_of_layers,num_concurrent_flows)
        cmds.append(cmd)
        print(cmd)

# multi-processing
p = Pool(processes=NUM_OF_CORES)
tick = time.time()
p.map(execute,cmds)
tock = time.time()
print("Time it took: {0:.2f}".format(tock-tick))

#labeling
tick = time.time()
label_ids_2018(dataroot.replace('PCAPs','CSVs/sk_sr_{}_mem'.format(round_up(sampling_interval,2))))
tock = time.time()
print("For labeling it took {} sec".format(tock-tick))
