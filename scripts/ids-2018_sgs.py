import os
import glob
from os.path import join
from multiprocessing import Pool
from labeler import label_ids_2018
import time

dataroot = '/home/juma/data/net_intrusion/CIC-IDS-2018/PCAPs'
ERROR_BOUND = 0.0008  #epsilon error

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
    i = output_file.find('sgs_e_')
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
        output_file = pcap_file.replace('PCAPs','CSVs/sgs_e_{}_mem'.format(ERROR_BOUND)).replace('.pcap','.pcap_Flow.csv')
        num_concurrent_flows = get_num_concurrent_flows(output_file,d,pcap_filename)
        ensure_dir(output_file)
        cmd = "../sgs '{}' '{}' {} {}".format(pcap_file,output_file,ERROR_BOUND,num_concurrent_flows)
        cmds.append(cmd)
        print(cmd)

# multi-processing
tick = time.time()
p = Pool(processes=8)
p.map(execute,cmds)
tock = time.time()
print("It took for sampling: {} sec.".format(tock-tick))

#labeling
tick = time.time()
label_ids_2018(join(dataroot.replace('PCAPs','CSVs'),'sgs_e_{}_mem'.format(ERROR_BOUND)))
tock = time.time()
print("It took for labeling: {} sec.".format(tock-tick))

