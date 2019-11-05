import os
import glob
from os.path import join
from multiprocessing import Pool
from labeler import label_ids_2018
import time

dataroot = '/home/juma/data/net_intrusion/CIC-IDS-2018/PCAPs'
z=12 
c=1
n=100

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

subdirs = get_immediate_subdirs(dataroot)
print(subdirs)

cmds = []
for d in subdirs:
    #for pcap_file in glob.glob(join(dataroot,d,'*.pcap')):
    for pcap_file in os.listdir(join(dataroot,d)):
        pcap_file = join(dataroot,d,pcap_file)
        output_file = pcap_file.replace('PCAPs','CSVs/sel_({},{},{})'.format(z,c,n)).replace('.pcap','.pcap_Flow.csv')
        ensure_dir(output_file)
        cmd = "../selective_flow '{}' '{}' {} {} {}".format(pcap_file,output_file,z,c,n)
        cmds.append(cmd)
        print(cmd)

# multi-processing
tick = time.time()
p = Pool(processes=8)
p.map(execute,cmds)
tock = time.time()
print("Sampling took {} sec".format(tock-tick))
#labeling
tick = time.time()
label_ids_2018(dataroot.replace('PCAPs','CSVs/sel_({},{},{})'.format(z,c,n)))
tock = time.time()
print("Labeling took {} sec".format(tock-tick))
