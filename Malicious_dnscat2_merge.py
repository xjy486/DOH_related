import os
directory='/home/ecs-user/data/PCAPs/DoHMalicious/dnscat2'

def get_filenames():
    files_and_dirs = os.listdir(directory)
    # ! NEED CHANGE, parameter: dsncat2_default-tunnel, dsncat2_default-baseline, dsncat2_txt-tunnel, dsncat2_txt-baseline
    filenames = [file for file in files_and_dirs if os.path.isfile(os.path.join(directory, file)) and file.endswith(".pcap") and file.startswith('dsncat2_txt-baseline')] 
    
    filenames_cloudflare={}
    filenames_google={}
    filenames_quad9={}
    filenames_adguard={}

    for file in filenames:
        file_split=file.split('_')
        dns_service=file_split[2]
        server=file_split[3]
        if dns_service=="1111": #cloudflare
            if server not in filenames:
                filenames_cloudflare[server]=[] #filenames_cloudflare['doh1']=["dns2tcp_tunnel_1111_doh1_2020-03-31T21:54:32.055088.pcap"]
            filenames_cloudflare[server].append(file)
        elif dns_service=="99911":
            if server not in filenames:
                filenames_quad9[server]=[] #filenames_cloudflare['doh1']=["dns2tcp_tunnel_1111_doh1_2020-03-31T21:54:32.055088.pcap"]
            filenames_quad9[server].append(file)
        elif dns_service=="dnsadguardcom":
            if server not in filenames:
                filenames_adguard[server]=[] #filenames_cloudflare['doh1']=["dns2tcp_tunnel_1111_doh1_2020-03-31T21:54:32.055088.pcap"]
            filenames_adguard[server].append(file)
        elif dns_service=="dnsgoogle":
            if server not in filenames:
                filenames_google[server]=[] #filenames_cloudflare['doh1']=["dns2tcp_tunnel_1111_doh1_2020-03-31T21:54:32.055088.pcap"]
            filenames_google[server].append(file)


    return filenames_cloudflare,filenames_google,filenames_quad9,filenames_adguard

    
def emrge(filenames_service,dns_service_name):
    
    # server: doh1,doh2,... filenames: a list, ["dns2tcp_tunnel_1111_doh1_2020-03-31T21:54:32.055088.pcap",...]
    for server,filename_list in filenames_service.items():
        # ! NEED CHANGE, parameter:default-tunnel, default-baseline, txt-tunnel, txt-baseline
        output=f"./dnscat2/txt-baseline/{dns_service_name}/dnscat2_txt-baseline_{server}.pcap"
        # make filename sorted by time
        filename_list=sorted(filename_list)
        filename_concat=''
        for filename in filename_list:
            filename_concat=filename_concat+filename+' '
        cmd=f'mergecap -a {filename_concat} -w {output}'
        try:
            os.system(cmd)
            print(f"{dns_service_name} success!")
        except Exception as e:
            print(f"{dns_service_name} falied: {e}")
    

def main():
    filenames_cloudflare,filenames_google,filenames_quad9,filenames_adguard=get_filenames()
    emrge(filenames_cloudflare,'Cloudflare')
    emrge(filenames_adguard,"AdGuard")
    emrge(filenames_google,"Google")
    emrge(filenames_quad9,'Quad9')


if __name__ == '__main__':
    main()
