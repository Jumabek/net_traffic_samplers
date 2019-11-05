import os
import glob
from os.path import join
from multiprocessing import Pool
from labeler import label_iscx_bot_2014
import numpy as np


dataroot = '/home/juma/data/net_intrusion/ISCX-Bot-2014/PCAPs'
z=6
c=0.5
n=7
Z=[z]
C=[c]
N=[n]

def execute(cmd):
    os.system(cmd)

def ensure_dir(filename):
    if not os.path.exists(os.path.dirname(filename)):
        try:
            os.makedirs(os.path.dirname(filename))
        except OSError as exc: # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise

for z in Z:#np.arange(3,1000,100):
    for c in C:#np.arange(0.1,0.8,0.1):
        for n in N:#np.arange(3,1000,100):
            cmds = []
            for pcap_file in glob.glob(join(dataroot,'*.pcap')):
                    output_file = pcap_file.replace('PCAPs','CSVs/sel_({},{},{})'.format(z,c,n)).replace('.pcap','.pcap_Flow.csv')
                    ensure_dir(output_file)
                    cmd = "../selective_flow '{}' '{}' {} {} {}".format(pcap_file,output_file,z,c,n)
                    cmds.append(cmd)
                    print(cmd)
            
            # multi-processing
            p = Pool(processes=8)
            p.map(execute,cmds)
            
            # labeling
            label_iscx_bot_2014(join(dataroot.replace('PCAPs','CSVs'),'sel_({},{},{})'.format(z,c,n)))
