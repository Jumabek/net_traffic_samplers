import os
import glob
import pandas as pd
from os.path import join
import numpy as np
from datetime import datetime
from collections import defaultdict
import argparse
import sys
from multiprocessing import Pool, Manager, Lock, Process
from shutil import copyfile

def label_flows (data, malicious_ips):
    data['Label']='Benign'
    print('data info',data.shape)
    data.loc[data['Source IP'].isin(malicious_ips['Ips']),'Label']='Bot'
    data.loc[data['Destination IP'].isin(malicious_ips['Ips']),'Label']='Bot'
    return data


#currently used for saving label_dist
def save_dict_to_csv(filename,d):
        with open(filename,'w') as f:
            for key in sorted(d.keys()):
                f.write('{},{}\n'.format(key,d[key]))


def get_immediate_subdirectories(a_dir):
    return [name for name in os.listdir(a_dir)
            if os.path.isdir(os.path.join(a_dir, name)) and not 'archive' in name]


def merge(dataroot):
    folders = get_immediate_subdirectories(dataroot)
    print(folders)
    for folder in folders:
        filenames = [i for i in glob.glob(join(dataroot,folder,'*.pcap_Flow.csv'))]
        combined_csv = pd.concat([pd.read_csv(f) for f in filenames],sort=False)
        combined_csv.to_csv(join(dataroot,folder+'_TrafficForML_CICFlowMeter.csv'),index=False,encoding='utf-8-sig')
        
        #now merge the counts.
        filenames = [i for i in glob.glob(join(dataroot,folder,"*.spc"))]
        counts = [int(open(f).readline()) for f in filenames]
        with  open(join(dataroot+'_l',folder+".spc"),"w") as f1:
            f1.write("{}\n".format(sum(counts)))


def label_iscx_bot_2014(dataroot):
        malicious_ip_file=  '/home/juma/data/net_intrusion/ISCX-Bot-2014/malicious_ips.csv'
#dataroot = '/hdd/juma/data/net_intrusion/ISCX-Bot-2014/CSVs/sf_sr_155'
        outputroot = dataroot + '_l'
        if not os.path.exists(outputroot):
            os.makedirs(outputroot)

        #move pkt cnt
        src = join(dataroot,'ISCX_Botnet-Testing.pcap_Flow.csv.spc')
        dst = join(outputroot,'ISCX_Botnet-Testing.pcap_Flow.csv.spc')
        copyfile(src,dst)
        
        src = join(dataroot,'ISCX_Botnet-Training.pcap_Flow.csv.spc')
        dst = join(outputroot,'ISCX_Botnet-Training.pcap_Flow.csv.spc')
        copyfile(src,dst)

        malicious_ips = pd.read_csv(malicious_ip_file)
        label_dist=  defaultdict(lambda:0)

        data = pd.read_csv(join(dataroot,'ISCX_Botnet-Testing.pcap_Flow.csv'))
        data = label_flows(data,malicious_ips)
        print(data.shape)
        data.to_csv(join(outputroot,'ISCX_Botnet-Testing.pcap_Flow.csv'),index=False,encoding='utf-8-sig')
        dist = data.Label.value_counts()

        print(dist)
        for k,v in dist.items():
            label_dist[k]+= v

        data = pd.read_csv(join(dataroot,'ISCX_Botnet-Training.pcap_Flow.csv'))
        data = label_flows(data,malicious_ips)
        print(data.shape)
        data.to_csv(join(outputroot,'ISCX_Botnet-Training.pcap_Flow.csv'),index=False,encoding='utf-8-sig')
        dist = data.Label.value_counts()

        print(dist)
        for k,v in dist.items():
            label_dist[k]+= v

        save_dict_to_csv(join(outputroot,'label_dist.csv'),label_dist)
        print('Done!')


def label_flows_bidirectionally(filename,outputname,attackers, victims, attack_time, attack_names,label_dist, lock):
    data = pd.read_csv(filename,encoding='utf-8-sig')
    data['Label']='Benign'
    data['Timestamp'] = pd.to_datetime(data['Timestamp'],format='%d/%m/%Y %H:%M:%S %p')
    #not_flipped=True
    for ttx, attack_name in enumerate(attack_names):
        for attacker in attackers[ttx]:
            for victim in victims[ttx]:
                    #print('Labeling: {}->{}'.format(attacker,victim))
                    #if ttx == 0 and not_flipped:
                    #    data[idx][0]= order_flowid(record[0])
                    attacker_flow1 = (data['Destination IP']==attacker) & (data['Source IP']==victim)
                    attacker_flow2 = (data['Source IP']==attacker)&(data['Destination IP']==victim)
                    attacker_flow = attacker_flow1 | attacker_flow2
                        
                    before = data['Timestamp']>=datetime.strptime(attack_time[ttx][0],'%d/%m/%Y %H:%M %p')
                    after = data['Timestamp']<= datetime.strptime(attack_time[ttx][1], '%d/%m/%Y %H:%M %p')
                            
                    data.loc[attacker_flow & before & after, 'Label'] = attack_name

            #not_flipped=False
    data.to_csv(outputname,index=False,encoding='utf-8-sig')

    local_label_dist = data.Label.value_counts()
    print("label distribtion for {}".format(filename))
    print(local_label_dist)
    print()
    #updating shared variable to count label distribution
    with lock:
        for key in local_label_dist.keys():
            if key in label_dist:
                label_dist[key]+=local_label_dist[key]
            else:
                label_dist[key]=local_label_dist[key]
#end of function
    

def label_ids_2018(dataroot):
    outputroot = dataroot + '_l'
    if not os.path.exists(outputroot):
        os.makedirs(outputroot)

    merge(dataroot)

    with Manager() as manager:  
        label_dist = manager.dict()
        lock = Lock()
        args_list = [] # one for each day.

        #Day 1
        attack_names = ['FTP-BruteForce','SSH-BruteForce']
        attackers = [['18.221.219.4'], ['13.58.98.64']]
        victims = [['172.31.69.25'],['172.31.69.25']]

        attack_times = [['14/02/2018 10:32 AM','14/02/2018 12:09 PM'], 
                   ['14/02/2018 14:01 PM','14/02/2018 15:31 PM']]

        filename = join(dataroot,'Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv')
        outputname = join(outputroot,'Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv')  
        args = (filename,outputname, attackers, victims, attack_times, attack_names,label_dist,lock)
        args_list.append(args)

        #Day 2        
        attack_names = ['DoS-GoldenEye','DoS-Slowloris']
        attackers = [['18.219.211.138'], ['18.217.165.70']]
        victims = [['172.31.69.25'],
            ['172.31.69.25']]
        attack_times = [['15/02/2018 09:26 AM','15/02/2018 10:09 AM'], 
                       ['15/02/2018 10:59 AM','15/02/2018 11:40 AM']]
        
        filename = join(dataroot,'Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv')
        outputname = join(outputroot,'Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv')   
        args = (filename,outputname, attackers, victims, attack_times, attack_names,label_dist,lock)
        args_list.append(args)

        #Day3
        attack_names = ['DoS-SlowHTTPTest','DoS-Hulk']
        attackers = [['13.59.126.31'], ['18.219.193.20']]
        victims = [['172.31.69.25'],['172.31.69.25']]
        
        attack_times = [['16/02/2018 10:12 AM','16/02/2018 11:08 AM'], 
                       ['16/02/2018 13:45 PM','16/02/2018 14:19 PM']]
        
        filename = join(dataroot,'Friday-16-02-2018_TrafficForML_CICFlowMeter.csv')
        outputname = join(outputroot,'Friday-16-02-2018_TrafficForML_CICFlowMeter.csv') 
        args = (filename,outputname, attackers, victims, attack_times, attack_names,label_dist,lock)
        args_list.append(args)

        #Day 4
        attack_names = ['DDoS attacks-LOIC-HTTP','DDoS-LOIC-UDP']
        attackers = [['18.218.115.60',
                            '18.219.9.1',
                            '18.219.32.43',
                            '18.218.55.126',
                            '52.14.136.135',
                            '18.219.5.43',
                            '18.216.200.189',
                            '18.218.229.235',
                            '18.218.11.51',
                            '18.216.24.42'], 
                         ['18.218.115.60',
                            '18.219.9.1',
                            '18.219.32.43',
                            '18.218.55.126',
                            '52.14.136.135',
                            '18.219.5.43',
                            '18.216.200.189',
                            '18.218.229.235',
                            '18.218.11.51',
                            '18.216.24.42']]
        victims = [['172.31.69.25'],
        ['172.31.69.25']]
        
        attack_times = [['20/02/2018 10:12 AM','20/02/2018 11:17 AM'], 
                       ['20/02/2018 13:13 PM','20/02/2018 13:32 PM']]
        
        filename = join(dataroot,'Tuesday-20-02-2018_TrafficForML_CICFlowMeter.csv')
        outputname = join(outputroot,'Tuesday-20-02-2018_TrafficForML_CICFlowMeter.csv')    
        args = (filename,outputname, attackers, victims, attack_times, attack_names,label_dist,lock)
        args_list.append(args)

        #Day 5
        attack_names = ['DDoS-LOIC-UDP','DDoS-HOIC']
        attackers = [['18.218.115.60',
                            '18.219.9.1',
                            '18.219.32.43',
                            '18.218.55.126',
                            '52.14.136.135',
                            '18.219.5.43',
                            '18.216.200.189',
                            '18.218.229.235',
                            '18.218.11.51',
                            '18.216.24.42'], 
                         ['18.218.115.60',
                            '18.219.9.1',
                            '18.219.32.43',
                            '18.218.55.126',
                            '52.14.136.135',
                            '18.219.5.43',
                            '18.216.200.189',
                            '18.218.229.235',
                            '18.218.11.51',
                            '18.216.24.42']]
        victims = [['172.31.69.28'],['172.31.69.28']]
        attack_times = [['21/02/2018 10:09 AM','21/02/2018 10:43 AM'], 
                       ['21/02/2018 14:05 PM','21/02/2018 15:05 PM']]
        
        filename = join(dataroot,'Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv')
        outputname = join(outputroot,'Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv')  
        args = (filename,outputname, attackers, victims, attack_times, attack_names,label_dist,lock)
        args_list.append(args)

        #Day 6
        attack_names = ['Brute Force-Web','Brute Force-XSS','SQL Injection']
        attackers = [['18.218.115.60'], 
                         ['18.218.115.60'],
                         ['18.218.115.60']]
        victims = [['172.31.69.28'],
                  ['172.31.69.28'],
                  ['172.31.69.28']]
        
        attack_times = [['22/02/2018 10:17 AM','22/02/2018 11:24 AM'], 
                       ['22/02/2018 13:50 PM','22/02/2018 14:29 PM'],
                       ['22/02/2018 16:15 PM','22/02/2018 16:29 PM']]
        
        filename = join(dataroot,'Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv')
        outputname = join(outputroot,'Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv')   
        args = (filename,outputname, attackers, victims, attack_times, attack_names,label_dist,lock)
        args_list.append(args)

        #Day 7
        attack_names = ['Brute Force-Web','Brute Force-XSS','SQL Injection']
        attackers = [['18.218.115.60'], 
                         ['18.218.115.60'],
                         ['18.218.115.60']]
        
        attack_times = [['23/02/2018 10:03 AM','23/02/2018 11:03 AM'], 
                       ['23/02/2018 13:00 PM','23/02/2018 14:10 PM'],
                       ['23/02/2018 15:05 PM','23/02/2018 15:18 PM']]
        
        filename = join(dataroot,'Friday-23-02-2018_TrafficForML_CICFlowMeter.csv')
        outputname = join(outputroot,'Friday-23-02-2018_TrafficForML_CICFlowMeter.csv') 
        args = (filename,outputname, attackers, victims, attack_times, attack_names,label_dist,lock)
        args_list.append(args)

        #Day 8
        attack_names = ['Infiltration','Infiltration']
        attackers = [['13.58.225.34'], 
                         ['13.58.225.34']]
        victims = [['172.31.69.24'],
            ['172.31.69.24']]
        
        attack_times = [['28/02/2018 10:50 AM','28/02/2018 12:05 PM'], 
                       ['28/02/2018 13:42 PM','28/02/2018 14:40 PM']]
        
        filename = join(dataroot,'Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv')
        outputname = join(outputroot,'Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv')  
        args = (filename,outputname, attackers, victims, attack_times, attack_names,label_dist,lock)
        args_list.append(args)

        # Day 9
        attack_names = ['Infiltration','Infiltration']
        attackers = [['13.58.225.34'], 
                         ['13.58.225.34']]
        victims = [['172.31.69.13'],
                      ['172.31.69.13']]
        attack_times = [['01/03/2018 09:57 AM','01/03/2018 10:55 AM'], 
                       ['01/03/2018 14:00 PM','01/03/2018 15:37 PM']]
        
        filename = join(dataroot,'Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv')
        outputname = join(outputroot,'Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv')   
        args = (filename,outputname, attackers, victims, attack_times, attack_names,label_dist,lock)
        args_list.append(args)


        #multiprocessing
        procs = [Process(target=label_flows_bidirectionally,args=arguments) for arguments in args_list]
        for p in procs: p.start()
        for p in procs: p.join()
        print("Total label_dist")
        print(label_dist)    
        save_dict_to_csv(join(outputroot,'label_dist.csv'),label_dist)      
