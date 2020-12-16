# -*- coding: utf-8 -*-
'''
用于从给定的策略中自动提取snort规则
'''
import os
import sys
import json
import time
import random
import hashlib
import argparse

try:
    import dpkt
except Exception as e:
    print('maybe run <sudo pip3 install dpkt>')
    raise e

pcap_ext = [".pcap"]

class Pcap2Snort(object):

    def __init__(self, policy_path):
        self.policy = dict()
        self.curdir = os.path.dirname(os.path.realpath(__file__))
        # self.policy_path = os.path.join(self.curdir,"Pcap2Snort.json")
        self.policy_path = policy_path
        self.snortlib = os.path.join(self.curdir,"snortlib")
        if not os.path.exists(self.snortlib):
            os.mkdir(self.snortlib)
        
    def load_pcap(self, pcappath:str)->iter:
        if os.path.isdir(pcappath):
            for root,dirname,filenames in os.walk(pcappath):
                for filename in filenames:
                    if os.path.splitext(filename)[-1] in pcap_ext:
                        yield os.path.join(root,filename)
        elif os.path.isfile(pcappath):
            yield pcappath

    def load_policy(self):
        """
        加载规则策略
        """
        if not self.policy_path:
            self.policy_path = os.path.join(self.curdir,"Pcap2Snort.json")
        try:
            with open(self.policy_path,"rb") as fr:
                self.policy = json.load(fr)
        except Exception as e:
            raise e

    def sidrandom(self):
        sid_header = 13000000
        sid_body = random.randint(1,999999)
        return "{}".format(sid_header+sid_body)

    def str2hexstr(self, buf):
        return ' '.join(['%02x' % x for x in buf])

    def timestamp2date_d(self, time_stamp="", format_string="%Y%m%d"):
        if not time_stamp:
            time_stamp = time.time()
        time_array = time.localtime(time_stamp)
        str_date = time.strftime(format_string, time_array)
        return str_date

    def md5_calculator_str(self,str_obj):
        str_obj = bytes(str_obj, encoding="utf-8")
        md5_obj = hashlib.md5()
        md5_obj.update(str_obj)
        hash_code = md5_obj.hexdigest()
        md5 = str(hash_code).lower()
        return md5

    def app_proto_check(self,basic_proto,net_data):
        '''基于底层协议检查数据是否属于上层应用协议'''
        if basic_proto == "tcp":
            try:
                dpkt.http.Request(net_data)
                return "http"
            except:
                return basic_proto
        elif basic_proto == "udp":
            try:
                dns = dpkt.dns.DNS(net_data)
                if dns.qr != dpkt.dns.DNS_Q:
                    return basic_proto
                if dns.opcode != dpkt.dns.DNS_QUERY:
                    return basic_proto
                if len(dns.qd) != 1:
                    return basic_proto
                if len(dns.an) != 0:
                    return basic_proto
                if len(dns.ns) != 0:
                    return basic_proto
                if dns.qd[0].cls != dpkt.dns.DNS_IN:
                    return basic_proto
                if dns.qd[0].type != dpkt.dns.DNS_A:
                    return basic_proto
                return "dns"
            except:
                return basic_proto
        else:
            return basic_proto           
        

    def matching(self, net_data, basic_proto, app_proto):
        """
        根据策略中的内容提取snort规则
        """
        for rulename, rule in self.policy.items():
            if rule.get("proto") != app_proto:  ##判断流量包的协议是否与策略制定的协议匹配
                continue
            rule_max_len = rule.get("offset") + rule.get("depth")
            if rule_max_len > len(net_data):   ##排除偏移和长度之和大于整个包的长度情况
                continue
            elif rule_max_len == 0 and rule.get("keywords") == []:   ##排除偏移和关键字都没有值的情况
                continue
            else:
                keywords_count = rule.get("keywords_count").split("of")[0].strip()
                if keywords_count == "all":    ##当统计范围为all是转为所有的元素的个数总和
                    keywords_count = len(rule.get("keywords"))
                keywords_count = int(keywords_count)  ##将字符串转为整形
                if not rule.get("keywords"):
                    if rule_max_len > 0:
                        rule["snort_item"] = {}
                        rule["snort_item"][self.str2hexstr(net_data[rule.get("offset"):rule.get("offset")+rule.get("depth")])] = None
                        return rule
                    else:
                        return {}
                if rule_max_len > 0:
                    net_data = net_data[rule.get("offset"):rule.get("offset")+rule.get("depth")]
                rule["snort_item"] = {}  ##使用字典统计匹配的部分,字典key的唯一性也可以用来去重
                flag_count = 0   ##统计是否达到匹配的部分数量
                for word in rule.get("keywords"):
                    if net_data.find(word.encode()) ==-1:
                        continue
                    hexstr = self.str2hexstr(word.encode())
                    if hexstr in rule["snort_item"]:
                        continue
                    rule["snort_item"][hexstr] = None
                    flag_count += 1
                    if flag_count == keywords_count: ##匹配满足要求的一部分之后返回
                        return rule                    
        return {}

    def snort_out(self, rule_data:dict):
        """
        snort规则格式化输出
        alert tcp any any -> any any (msg:"{'org': '', 'author': 'zhuqing', 'behavior': ['VulnerabilityIntrusion'], 'vulnerability_id': 'CVE-2017-10271', 'app_info': 'WebLogic, WebLogic==10.3.6.0.0', 'description': 'Weblogic 任意文件上传执行', 'extract_date': '20201009', 'threat_name': '', 'family': 'Unknown', 'sign_source': 'ArtificialExtraction', 'refer': []}"; content:"POST"; depth:5; content:"/wls-wsat/CoordinatorPortType"; content:"java.lang.ProcessBuilder"; distance:50; content:"wget"; pcre:"/wget.*http/i"; distance:0; classtype:Exploits;sid:130000018;rev:1;)
        """
        rule_header = '''alert %s any any -> any any '''%(rule_data.get("proto"))
        rule_msg = '''msg:"{'org': '', 'author': 'snort_tools', 'behavior': ['%s'], 'vulnerability_id': '%s', 'app_info': '%s', 'description': '%s', 'extract_date': '%s', 'threat_name': '', 'family': '%s', 'sign_source': 'ArtificialExtraction', 'refer': ['']}";'''%(rule_data.get("behavior"),
                                                                                                                                                                                                                                                                          rule_data.get("cve_num"),
                                                                                                                                                                                                                                                                          rule_data.get("app_info"),
                                                                                                                                                                                                                                                                          rule_data.get("description"),
                                                                                                                                                                                                                                                                          self.timestamp2date_d(),
                                                                                                                                                                                                                                                                          rule_data.get("family"))
        
        
        rule_body = ''''''
        if rule_data.get("snort_item"):
            for key,value in rule_data.get("snort_item").items():
                rule_body += '''content:"|%s|";'''%(key)
        else:
            return 
        # rule_sid = '''sid:%s;'''%(self.sidrandom())
        rule_classify = '''classtype:%s;'''%(rule_data.get("classify")) if rule_data.get("classify") else ""
        snort_info = "{}({}{}{})".format(rule_header,rule_msg,rule_body,rule_classify)
        print (snort_info)
        with open(os.path.join(self.snortlib,"snort_{}.rules".format(self.md5_calculator_str(snort_info))),"wb") as fw:
            fw.write(bytes(snort_info,encoding="utf-8"))

    def analysis(self,pcap:dpkt.pcap.Reader)->dict:
        """
        dpkt.pcap.Reader对象的Pcap流量分析
        """
        if not isinstance(pcap,dpkt.pcap.Reader):
            raise "parameter pcap need dpkt.pcap.Reader"
        
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            #确认流量包有ip信息
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            
            # 检查是否是icmp包
            if isinstance(ip.data, dpkt.icmp.ICMP):
                icmp = ip.data
                icmp_operate = icmp.data
                if not isinstance(icmp_operate,dpkt.icmp.ICMP.Echo):
                    continue
                if len(icmp_operate.data) > 0:
                    ret = self.matching(icmp_operate.data,
                                        "icmp",
                                        self.app_proto_check("icmp",icmp_operate.data))
                    self.snort_out(ret)

            # 检查是否是tcp包
            elif ip.p == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
                if len(tcp.data) > 0:
                    ret = self.matching(tcp.data,
                                        "tcp",
                                        self.app_proto_check("tcp",tcp.data))
                    self.snort_out(ret)
                else:
                    pass

            # 检查是否是udp包
            elif ip.p == dpkt.ip.IP_PROTO_UDP:
                udp = ip.data
                if len(udp.data) > 0:
                    ret = self.matching(udp.data,
                                        "udp",
                                        self.app_proto_check("udp",udp.data))
                    self.snort_out(ret)
                else:
                    pass                 

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p","--pcap",help="输入待提取snort规则的pcap目录或者文件绝对路径,eg.E:\\PcapTest or E:\\PcapTest\\test.pcap")
    parser.add_argument("-d","--data",help="特征数据源字段, eg.E:\\PcapTest\\Pcap2Snort.json")
    args = parser.parse_args()
    if not args.pcap or not os.path.exists(args.pcap):
        parser.print_help()
    else:
        p2s = Pcap2Snort(args.data)
        p2s.load_policy()
        for filepath in p2s.load_pcap(args.pcap):
            with open(filepath,"rb") as f:
                print (filepath)
                p2s.analysis(dpkt.pcap.Reader(f))
    
