from scapy.all import *
from collections import defaultdict
import time
import numpy as np
import pandas as pd
import os
main_directory='/home/ecs-user/filter_data/Malicious'
protos={
        'dns2tcp':['tunnel'],
        'dnscat2':['default-baseline','txt-tunnel','txt-baseline','default-tunnel'],
        'iodine':['null-32-baseline',  "null-32-tunnel" , 'null-64-baseline' , 'null-64-tunnel' , 'srv-32-baseline',  'srv-32-tunnel' , 'srv-64-baseline', 'srv-64-tunnel',  'txt-32-baseline' , 'txt-32-tunnel' , 'txt-64-baseline',  'txt-64-tunnel']
    }
FORWARD=1
BACKWARD=0
# 返回Malicious流量所在路径
def get_paths(tool,modes):   
    directory=main_directory+'/'+tool

    os.chdir(directory)
    if not os.path.exists('output'):
        os.mkdir('output')
    paths=[]
    dns_servers=['Quad9','Google','AdGuard','Cloudflare']
    for mode in modes:
        for d_s in dns_servers:
            path= directory+"/"+mode+"/"+d_s
            paths.append(path)
    return paths
# 返回当前目录下所有文件
def get_files(path):
    files = [entry.name for entry in os.scandir(path) if entry.is_file()]
    return files

def get_packets(input_file):
    return rdpcap(input_file)

def get_direction(packet_srcip):
    if packet_srcip in ["192.168.20.144","192.168.20.204","192.168.20.205","192.168.20.206","192.168.20.207","192.168.20.208","192.168.20.209","192.168.20.210","192.168.20.211","192.168.20.212"]:
        return FORWARD
    else:
        return BACKWARD

# 获取数据包的tls长度和timestamp
def feature(packet):
    tcp_payload = bytes(packet[TCP].payload)
    # content_type = tcp_payload[0]  # 第1字节是内容类型
    # version = tcp_payload[1:3]     # 第2-3字节是TLS版本
    length = int.from_bytes(tcp_payload[3:5], 'big')  # 第4-5字节是TLS Record Length
    timestamp=float(packet.time)
    return {"Length":length,"Timestamp":timestamp}

# 处理数据包，进行流聚合
def process_packets(packets):
    flows=dict()
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            direct=get_direction(pkt[IP].src)
            flow_id=tuple(sorted([(pkt[IP].src,pkt[TCP].sport),(pkt[IP].dst,pkt[TCP].dport)]))
            if flow_id not in flows:
                flows[flow_id]={
                    'src2dst': [],
                    'dst2src': [],
                    'biddirectional':[]
                }
            feature_pkt=feature(pkt)
            flows[flow_id]['biddirectional'].append(feature_pkt)
            if direct==FORWARD:
                flows[flow_id]['src2dst'].append(feature_pkt)
            else:
                flows[flow_id]['dst2src'].append(feature_pkt)
        else:
            continue
    return flows

def extract_save_features(flows,attack_type,doh_server,outputfile):
    features_list = []

    for flow_id,packets_features in flows.items():

        src2dst=packets_features['src2dst']
        dst2src=packets_features['dst2src']
        bidirectional=packets_features['biddirectional']
        
        src2dst_lengths=np.array([pkt_feature['Length'] for pkt_feature in src2dst])
        src2dst_time_intervals=np.array([src2dst[i]['Timestamp']-src2dst[i-1]['Timestamp'] for i in range(1,len(src2dst))])
        if src2dst_lengths.size<=0:
            src2dst_lengths=np.array([0])
        if src2dst_time_intervals.size<=0:
            src2dst_time_intervals=np.array([0])

        dst2src_lengths=np.array([pkt_feature['Length'] for pkt_feature in dst2src])
        dst2src_time_intervals=np.array([dst2src[i]['Timestamp']-dst2src[i-1]['Timestamp'] for i in range(1,len(dst2src))])
        if dst2src_lengths.size<=0:
            dst2src_lengths=np.array([0])
        if dst2src_time_intervals.size<=0:
            dst2src_time_intervals=np.array([0])

        bidirectional_lengths=np.array([pkt_feature['Length'] for pkt_feature in bidirectional])
        bidirectional_time_intervals=np.array([bidirectional[i]['Timestamp']-bidirectional[i-1]['Timestamp'] for i in range(1,len(bidirectional))])
        if bidirectional_lengths.size<=0:
            bidirectional_lengths=np.array([0])
        if bidirectional_time_intervals.size<=0:
            bidirectional_time_intervals=np.array([0])

        # 计算统计特征
        src2dst_min_length = min(src2dst_lengths)
        src2dst_max_length = max(src2dst_lengths)
        src2dst_stddev_length = np.std(src2dst_lengths)
        src2dst_mean_length = np.mean(src2dst_lengths)
        src2dst_min_time = min(src2dst_time_intervals)
        src2dst_max_time = max(src2dst_time_intervals)
        src2dst_mean_time = np.mean(src2dst_time_intervals)
        src2dst_stddev_time = np.std(src2dst_time_intervals)

        dst2src_min_length = min(dst2src_lengths)
        dst2src_max_length = max(dst2src_lengths)
        dst2src_stddev_length = np.std(dst2src_lengths)
        dst2src_mean_length = np.mean(dst2src_lengths)
        dst2src_min_time = min(dst2src_time_intervals)
        dst2src_max_time = max(src2dst_time_intervals)
        dst2src_mean_time = np.mean(dst2src_time_intervals)
        dst2src_stddev_time = np.std(dst2src_time_intervals)
        
        bidirectional_min_length = min(bidirectional_lengths)
        bidirectional_max_length = max(bidirectional_lengths)
        bidirectional_stddev_length = np.std(bidirectional_lengths)
        bidirectional_mean_length = np.mean(bidirectional_lengths)
        bidirectional_min_time = min(bidirectional_time_intervals)
        bidirectional_max_time = max(bidirectional_time_intervals)
        bidirectional_mean_time = np.mean(bidirectional_time_intervals)
        bidirectional_stddev_time = np.std(bidirectional_time_intervals)
       

        features_list.append({
            'flow_id': flow_id,
            'src2dst_min_length': src2dst_min_length,
            'src2dst_max_length': src2dst_max_length,
            'src2dst_stddev_length': src2dst_stddev_length,
            'src2dst_mean_length': src2dst_mean_length,
            'src2dst_min_time': src2dst_min_time,
            'src2dst_max_time': src2dst_max_time,
            'src2dst_mean_time': src2dst_mean_time,
            'src2dst_stddev_time': src2dst_stddev_time,
            'dst2src_min_length': dst2src_min_length,
            'dst2src_max_length': dst2src_max_length,
            'dst2src_stddev_length': dst2src_stddev_length,
            'dst2src_mean_length': dst2src_mean_length,
            'dst2src_min_time': dst2src_min_time,
            'dst2src_max_time': dst2src_max_time,
            'dst2src_mean_time': dst2src_mean_time,
            'dst2src_stddev_time': dst2src_stddev_time,
            'bidirectional_min_length': bidirectional_min_length,
            'bidirectional_max_length': bidirectional_max_length,
            'bidirectional_stddev_length': bidirectional_stddev_length,
            'bidirectional_mean_length': bidirectional_mean_length,
            'bidirectional_min_time': bidirectional_min_time,
            'bidirectional_max_time': bidirectional_max_time,
            'bidirectional_mean_time': bidirectional_mean_time,
            'bidirectional_stddev_time': bidirectional_stddev_time,
            'label': 'Malicious',
            'type':attack_type,
            'doh_server':doh_server
        })
    print(len(features_list))
    df=pd.DataFrame(features_list)
    df.to_csv(outputfile,index=False)

# 什么破名字
def extract_by_tool(tool,mode):
    paths=get_paths(tool,mode)
    for path in paths:
        files=get_files(path)
        doh_server=path.split('/')[-1]
        for file in files:
            t1=time.time()
            input_file=path+'/'+file # /home/ecs-user/filter_data/Malicious/dns2tcp/AdGuard/*.pcap
            print(f"{input_file}")
            packets=get_packets(input_file)
            t2=time.time()
            print(f"Read pcap time: {str(t2-t1)} seconds")
            flows=process_packets(packets)
            attack_type=file.split('_')[0]+"_"+file.split("_")[1] # dns2tcp_tunnel
            doh_num=file.split('_')[2].split('.')[0]

            output_file='./output/'+doh_server+'_'+attack_type+'_'+doh_num+'_malicious.csv'
            # print(output_file)
            extract_save_features(flows,attack_type,doh_server,output_file)
            t3=time.time()
            print(f"Extract features time: {str(t3-t2)} seconds")
                
            #占内存太多
            del flows 
            del packets

def main():
    for tool,mode in protos.items():
        extract_by_tool(tool,mode)

if __name__ == '__main__':
    main()
        
