import os
directory='/home/ecs-user/data/PCAPs/DoHMalicious/dns2tcp'

def get_filenames():
    files_and_dirs = os.listdir(directory)
    filenames = [file for file in files_and_dirs if os.path.isfile(os.path.join(directory, file)) and file.endswith(".pcap")]
    # print(filenames)
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

    
def emrge(filenames_service,dns_service_name):
    
    # server: doh1,doh2,... filenames: a list, ["dns2tcp_tunnel_1111_doh1_2020-03-31T21:54:32.055088.pcap",...]
    for server,filename_list in filenames_service.items():
        output=f"./dns2tcp/{dns_service_name}/dns2tcp_tunnel_{server}.pcap"
        # make filename sorted by time
        filename_list=sorted(filename_list)
        filename_concat=''
        for filename in filename_list:
            filename_concat=filename_concat+filename+' '
        cmd=f'mergecap -a {filename_concat} -w {output}'
        os.system(cmd)
    print(f"{dns_service_name} success!")

def main():
    filenames_cloudflare,filenames_google,filenames_quad9,filenames_adguard=get_filenames()
    emrge(filenames_cloudflare,'Cloudflare')
    emrge(filenames_adguard,"AdGuard")
    emrge(filenames_google,"Google")
    emrge(filenames_quad9,'Quad9')


if __name__ == '__main__':
    main()
