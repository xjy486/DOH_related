import os

directory='/home/ecs-user/data/PCAPs/DoHBenign-NonDoH/Quad9'
def get_filenames():
    files_and_dirs = os.listdir(directory)
    filenames = [file for file in files_and_dirs if os.path.isfile(os.path.join(directory, file)) and file.endswith(".pcap")]
    filenames = sorted(filenames)
    print(filenames)
    return filenames


def main():
    filenames=get_filenames()
    output_file_list=[]
    for f in filenames:
        f_list=f.split('_')
        output_file=f_list[0]+f_list[1]
        output_file_list.append(output_file)
        filter_shell=f'tshark -r {f} -Y "ip.dst == 149.112.112.10||ip.src==149.112.112.10 || ip.src==149.112.112.112 || ip.dst==149.112.112.112 || ip.dst==9.9.9.9 || ip.src==9.9.9.9||ip.dst==9.9.9.10 || ip.src==9.9.9.10||ip.dst==9.9.9.8 || ip.src==9.9.9.8" -w {output_file}.pcap'
        os.system(filter_shell)
    file=''
    for f in output_file_list:
        file=file+f+'.pcap '
    print(file)
    merge_shell=f'mergecap -w Quad9-chrome.pcap {file}'
    os.system(merge_shell)
if __name__ == '__main__':
    main()
