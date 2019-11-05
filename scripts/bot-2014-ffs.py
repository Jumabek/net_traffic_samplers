import os
import glob
from os.path import join
from multiprocessing import Pool
from labeler import label_iscx_bot_2014


dataroot = '/home/juma/data/net_intrusion/ISCX-Bot-2014/PCAPs'
s = 4 
l = 8
sampling_interval = 35  
counter_memory = 110

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
        output_file = pcap_file.replace('PCAPs','CSVs/ffs_({},{},{})_mem_{}'.format(s,l,sampling_interval,counter_memory)).replace('.pcap','.pcap_Flow.csv')
        ensure_dir(output_file)
        cmd = "../ffs '{}' '{}' {} {} {}".format(pcap_file,output_file,s,l,sampling_interval)
        cmds.append(cmd)
        print(cmd)

# multi-processing
p = Pool(processes=8)
p.map(execute,cmds)

#labeling
label_iscx_bot_2014(join(dataroot.replace('PCAPs','CSVs'),'ffs_({},{},{})_mem_{}'.format(s,l,sampling_interval,counter_memory)))
