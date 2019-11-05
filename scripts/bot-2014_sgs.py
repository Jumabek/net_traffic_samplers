import os
import glob
from os.path import join
from multiprocessing import Pool
from labeler import label_iscx_bot_2014
import time

dataroot = '/home/juma/data/net_intrusion/ISCX-Bot-2014/PCAPs'
EB= 55 
counter_memory = 110 # in kbyte

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
        output_file = pcap_file.replace('PCAPs','CSVs/sgs_e_{}_mem_{}'.format(EB,counter_memory)).replace('.pcap','.pcap_Flow.csv')
        ensure_dir(output_file)
        cmd = "../sgs '{}' '{}' {}".format(pcap_file,output_file,EB)
        cmds.append(cmd)
        print(cmd)

# multi-processing
tick = time.time()
p = Pool(processes=8)
p.map(execute,cmds)
tock= time.time()
print("Time taken for sampling {} sec".format(tock-tick))
#labeling

label_iscx_bot_2014(join(dataroot.replace('PCAPs','CSVs'),'sgs_e_{}_mem_{}'.format(EB,counter_memory)))
