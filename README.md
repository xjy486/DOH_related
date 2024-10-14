# DoH related
试图复现论文：Detecting DNS over HTTPS based data exfiltration，但是没得代码和数据集。  
最后的结果是没有复现成功，因为菜，但是有些东西还是要记录下来，这是工作量的证明。
使用DoH-Brw2020去提取相关统计特征，但是估计写的代码有问题，提取出来的csv文件太小了。
 
##  数据集
原始数据集来自DoH-Brw2020: https://www.unb.ca/cic/datasets/dohbrw-2020.html
## some usful commads:  

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
