#                ---------- PcapSnort ----------  
##### This script filter a network packet from a PCAP file into New PCAP files by some condition.  


# Description
为IDS平台做能力支撑. 分析恶意流量，并过滤形成新的pcap文件+特征文件，还能自动生成snort规则。  


# Usage:  
        python main.py [-h] -i I [-o O] [-r R] -t {stream,single} [--multi {true,false}]

# Example:
        [-] 以Stream流的方式分割Pcap包并过滤,将符合的首个Stream包生成新Pcap文件:
        python2 main.py -i pcap/jboss.pcap -t streamn
        [-] 以Stream流的方式分割Pcap包并过滤,将所有符合的Stream包输出到不同Pcap文件:
        python2 main.py -i pcap/jboss.pcap -t streamn --multi true
        [-] 过滤包并生成snort规则
        python2 main.py -i pcap/jboss.pcap -t stream --snort true --multi true

# Optional arguments:  
    -h, --help            show this help message and exit  
    -i I                  input pcap filepath
    -r R                  读取特征库, default=/home/pcap_filter/conf/data.json  
    -t {stream,single}    choose from <stream> pcap, <single> pcap  
    --multi {true,false}  The matching package is divided into several pcap files by stream, otherwise the matching will stop  
    --snort {true,false}  只输出snort规则, 否则只输出pcap文件和policy文件

# ThirdPart:
        Policy策略字段解释详看./thirdpart/README.md

# Product
1、恶意pcap+特征json文件
2、snort规则生成

# Attention
正在开发中，目前检测的恶意pcap较少。
