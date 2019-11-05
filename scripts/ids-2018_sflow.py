import os
import glob
from os.path import join
from multiprocessing import Pool
from labeler import label_ids_2018
import sys
import time
import subprocess 

dataroot = '/home/juma/data/net_intrusion/CIC-IDS-2018/PCAPs'
SR = 1 

def get_immediate_subdirs(a_dir):
    return [name for name in os.listdir(a_dir)
            if os.path.isdir(os.path.join(a_dir, name))]

def execute(cmd):
    
    print("trying cmd ",cmd)
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
        output_file = pcap_file.replace('PCAPs','CSVs/sf_sr_{}'.format(SR)).replace('.pcap','.pcap_Flow.csv')
        ensure_dir(output_file)
        #cmd = ['../sflow',pcap_file,output_file,str(SR)]
        cmd = '../sflow "{}" "{}" {} '.format(pcap_file,output_file,SR)
        cmds.append(cmd)
        #print(cmd)
        print("{:70} - {:20}".format(pcap_file,os.path.getsize(pcap_file)))

# multi-processing
#print(cmds)
p = Pool(processes=12)
tick = time.time()
p.map(execute,cmds)
tock = time.time()
print("TOTAL Time it took for sampling: {} sec ",tock-tick)

#labeling
tick = time.time()
label_ids_2018(dataroot.replace('PCAPs','CSVs/sf_sr_{}'.format(SR)))
tock = time.time()
print("Time take for labeling {} sec".format(tock-tick))
