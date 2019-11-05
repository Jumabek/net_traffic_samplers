import os
import glob
from os.path import join
from multiprocessing import Pool
from labeler import label_ids_2018
import time

dataroot = '/home/juma/data/net_intrusion/CIC-IDS-2018/PCAPs'
s=4
l=8

SR = 32

def get_immediate_subdirs(a_dir):
    return [name for name in os.listdir(a_dir)
            if os.path.isdir(os.path.join(a_dir, name))]

def execute(cmd):
    os.system(cmd)

def ensure_dir(filename):
    if not os.path.exists(os.path.dirname(filename)):
        try:
            os.makedirs(os.path.dirname(filename))
        except OSError as exc: # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise

def get_num_concurrent_flows(output_file,d,pcap_filename):
    i = output_file.find('ffs_')
    fpath = join(output_file[:i], 'sf_sr_1/',d, pcap_filename.replace('.pcap','.pcap_Flow.csv.nflows'))
    with open(fpath,'r') as f:
        n = f.readline()
        print(fpath,n)
    return n


subdirs = get_immediate_subdirs(dataroot)
print(subdirs)

cmds = []
for d in subdirs:
    for pcap_filename in os.listdir(join(dataroot,d)):
        pcap_file = join(dataroot,d,pcap_filename)
        output_file = pcap_file.replace('PCAPs','CSVs/ffs_({},{},{})_mem'.format(s,l,SR)).replace('.pcap','.pcap_Flow.csv')
        num_concurrent_flows = get_num_concurrent_flows(output_file,d,pcap_filename)
        ensure_dir(output_file)
        cmd = "../ffs '{}' '{}' {} {} {} {}".format(pcap_file,output_file,s,l,SR,num_concurrent_flows)
        cmds.append(cmd)
        print(cmd)

# multi-processing
tick = time.time()
p = Pool(processes=12)
p.map(execute,cmds)
tock = time.time()
print("Sampling time: {} sec".format(tock - tick))

#labeling
tick = time.time()
label_ids_2018(join(dataroot.replace('PCAPs','CSVs'),'ffs_({},{},{})_mem'.format(s,l,SR)))
tock = time.time()
print("Labeling time: {} sec".format(tock-tick))
