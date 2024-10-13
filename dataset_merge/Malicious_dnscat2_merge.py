import os
directory='/home/ecs-user/data/PCAPs/DoHMalicious/dnscat2'
# 获取类型
def get_type_list():
    types1=['default','txt']
    types2=['tunnel','baseline']
    
    types=[]
    for t1 in types1:
        for t2 in types2:
                t=t1+'-'+t2
                types.append('dsncat2_'+t)
    return types

def get_filenames(prefix):
    files_and_dirs = os.listdir(directory) 
    filenames = [file for file in files_and_dirs if os.path.isfile(os.path.join(directory, file)) and file.endswith(".pcap") and file.startswith(prefix)] 
    
    filenames_cloudflare={}
    filenames_google={}
    filenames_quad9={}
    filenames_adguard={}

    for file in filenames:
        file_split=file.split('_')
        dns_service=file_split[2]
        server=file_split[3]
        if dns_service=="1111": #cloudflare
            if server not in filenames_cloudflare:
                filenames_cloudflare[server]=[] #filenames_cloudflare['doh1']=["dns2tcp_tunnel_1111_doh1_2020-03-31T21:54:32.055088.pcap"]
            filenames_cloudflare[server].append(file)
        elif dns_service=="99911":
            if server not in filenames_quad9:
                filenames_quad9[server]=[] #filenames_cloudflare['doh1']=["dns2tcp_tunnel_1111_doh1_2020-03-31T21:54:32.055088.pcap"]
            filenames_quad9[server].append(file)
        elif dns_service=="dnsadguardcom":
            if server not in filenames_adguard:
                filenames_adguard[server]=[] #filenames_cloudflare['doh1']=["dns2tcp_tunnel_1111_doh1_2020-03-31T21:54:32.055088.pcap"]
            filenames_adguard[server].append(file)
        elif dns_service=="dnsgoogle":
            if server not in filenames_google:
                filenames_google[server]=[] #filenames_cloudflare['doh1']=["dns2tcp_tunnel_1111_doh1_2020-03-31T21:54:32.055088.pcap"]
            filenames_google[server].append(file)


    return filenames_cloudflare,filenames_google,filenames_quad9,filenames_adguard

    
def emrge(filenames_service,dns_service_name,type):
    
    # server: doh1,doh2,... filenames: a list, ["dns2tcp_tunnel_1111_doh1_2020-03-31T21:54:32.055088.pcap",...]
    for server,filename_list in filenames_service.items():
        folder=type.split('_')[1] # default-tunnel ...
        output=f"./dnscat2/{folder}/{dns_service_name}/{type}_{server}.pcap"
        # make filename sorted by time
        filename_list=sorted(filename_list)
        filename_concat=''
        for filename in filename_list:
            filename_concat=filename_concat+filename+' '
        cmd=f'mergecap -a {filename_concat} -w {output}'
        os.system(cmd)
    # print(f"{dns_service_name} {type}_{server} success!")


def main():
    types=get_type_list()
    for type in types:
        filenames_cloudflare,filenames_google,filenames_quad9,filenames_adguard=get_filenames(type)
        print(f"{type}")
        emrge(filenames_cloudflare,'Cloudflare',type)
        
        emrge(filenames_adguard,"AdGuard",type)
        
        emrge(filenames_google,"Google",type)
        
        emrge(filenames_quad9,'Quad9',type)
        

if __name__ == '__main__':
    main()

