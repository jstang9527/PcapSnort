### Pcap2Snort

```
1. Pcap2Snort.py 
提取snort规则的主程序
```

```
2. Pcap2Snort.json
字段解释
{
    "policy_1":{
        "proto":"http",
        "offset":0,
        "depth":0,
        "keywords":["GET /wls-wsat/CoordinatorPortType"],
        "keywords_count":"all of them",
        "behavior":"VulnerabilityIntrusion",
        "classify":"Exploits",
        "cve_num":"CVE-2017-10271",
        "family":"",
        "app_info":"Weblogic",
        "description":"Weblogic 漏洞验证"
    },
    "policy_2":{
        "proto":"tcp",
        "offset":0,
        "depth":0,
        "keywords":["VERSONEX","MHz","MB"],
        "keywords_count":"all of them",
        "behavior":"OnlineBehavior",
        "classify":"RAT",
        "cve_num":"",
        "family":"Trojan[DDoS]/Linux.Dofloo",
        "app_info":"Trojan",
        "description":"木马上线包"
    },
    "policy_3":{
        "proto":"dns",
        "offset":0,
        "depth":0,
        "keywords":["post","ksosoft","com"],
        "keywords_count":"all of them",
        "behavior":"DNSQuery",
        "classify":"",
        "cve_num":"",
        "family":"",
        "app_info":"",
        "description":"可疑域名解析请求"
    },
    "policy_4":{
        "proto":"icmp",
        "offset":0,
        "depth":0,
        "keywords":["abcdefghijk"],
        "keywords_count":"all of them",
        "behavior":"ICMPDataTraffic",
        "classify":"BackDoor",
        "cve_num":"",
        "family":"",
        "app_info":"",
        "description":"可疑ICMP数据输入"
    }
}

proto:      通信协议类型,目前支持tcp、udp、icmp、http、dns 五种协议
policy_1:   策略名称,确保唯一性
offset:     提取规则时,需要提取的特征payload的偏移量,从payload的什么位置开始匹配,空值使用0
depth:      提取规则时,需要提取的特征payload的长度,和offset组合使用表示,提取从某位置开始的指定长度的特征,空值使用0
keywords:   关键字,提取流量中存在的关键字作为特征,可以与offset,depth组合使用,空值使用[]
keywords_count:     关键字统计,如果存在多个关键字,使用all of them, 表示匹配所有关键字,如果使用1 of them 表示匹配其中的一个即可,先匹配到的特征字符串先返回作为特征,空值使用"all of them"
behavior:   特征提取后对应的行为,空值使用""
classify:   特征提取后对应的威胁类别,空值使用""
cve_num:    特征提取后对应的cve漏洞编号,空值使用""
family:     特征提取后对应的家族,空值使用""
app_info:   特征对应的应用名字
description:    特征详细的描述
``` 

```
3. snortlib
生成的snort规则文件存在的位置
```

```
4. pcap
需要提取的pcap包存放的位置

* 注意使用wireshark抓取的pcap保存时请使用tcpdump格式对应的pcap包,如果使用的pcapng格式的pcap,请用wireshark打开后另存为tcpdump格式的pcap包再进行特征提取，否则格式将识别不了
```

```
5.运行方法
示例：
python3 Pcap2Snort.py -p ./pcap       ##测试pcap
python3 Pcap2Snort.py -p E:\\TestPcap\\test.pcap   ##pcap文件
python3 Pcap2Snort.py -p E:\\TestPcap     ##包含pcap的文件夹
```