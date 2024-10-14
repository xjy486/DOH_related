# DoH related
试图复现论文：Detecting DNS over HTTPS based data exfiltration，但是没得代码和数据集。  
最后的结果是没有复现成功，因为菜，但是有些东西还是要记录下来，这是工作量的证明。  
使用DoH-Brw2020去提取相关统计特征，但是估计写的代码有问题，导致提取出来的csv文件太小。

##  数据集
原始数据集来自DoH-Brw2020: https://www.unb.ca/cic/datasets/dohbrw-2020.html

## 文件夹说明
dataset_merge 将官网下的原始pcap下载下来并解压后，会注意到许多pcap文件太零散了，这里的代码就是用于将pcap文件组装成一个大pcap文件的。但是这里的代码不能处理所有的pcap文件，因为有些pcap文件是通过shell命令来合并的，比如良性流量的firefox相关的pcap文件。  

dataset_feature 用于从合并后的pcap文件中提取统计特征，并将其保存为csv文件。这些csv文件存储在csv_merge/Benign_csv和csv_merge/Malicious_csv。  

csv_merge  用于将csv_merge/Benign_csv和csv_merge/Malicious_csv下的csv文件进行合并。合并后的csv文件存储在csv_merge/all csv_merge/benign csv_merge/malicious下。

train_and_eval 使用csv_merge/all下的csv文件去做实验，这里的实验和论文里的实验不完全一致，不仅缺了一部分，还有一些实验和论文里描述的不一致。

最后，dataset_feature，dataset_merge里的代码可阅读性会很差，变量名的命名也很糟糕，因为写的时候没有AI插件辅助修改。

## some usful commads:  
备忘录
```
# 清空文件夹下的文件，但不删除文件夹
find /path/to/folder -type f -exec rm {} \;

# 查看文件夹大小
du -sh /path/folder

# 移动文件到另一个地方
mv adguard cloudflare google quad9 ./Benign

# 文件重命名
mv file1.txt file2.txt
```
