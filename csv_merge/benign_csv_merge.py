import pandas as pd
import os

directory="D:\\PCAP_FILE\\Benign_csv"
files = [entry.name for entry in os.scandir(directory) if entry.is_file()]

DNS_server={
    "AdGuard":[],
    "Cloudflare":[],
    "Google":[],
    "Quad9":[],
    
}
for file in files:
    if file.startswith("AdGuard"):
        DNS_server["AdGuard"].append(file)
    elif file.startswith("Cloudflare"):
        DNS_server["Cloudflare"].append(file)
    elif file.startswith("Google"):
        DNS_server["Google"].append(file)
    elif file.startswith("Quad9"):
        DNS_server["Quad9"].append(file)

for dns_server,files in DNS_server.items():
    print(dns_server)
    print(files)
    print("\n")
    dataframes=[]
    for file in files:
        df=pd.read_csv(directory+"\\"+file)
        dataframes.append(df)
    df_dns_server=pd.concat(dataframes)
    csv_name=dns_server+".csv"
    # 把数据保存为csv为文本
    df_dns_server.to_csv(csv_name,index=False)
