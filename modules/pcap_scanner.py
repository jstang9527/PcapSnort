# coding=utf-8
import sys
try:
    import dpkt
except ImportError:
    sys.stderr.write("ERROR: You must have dpkt installed.\n")
    sys.stderr.write("You can install it by running: sudo pip2 install -U 'dpkt'\n")
    exit(1)
import re
"""
hash_table = {
    'seq(number)': {               # 首次出现并且没有ack的第一次请求的seq
        'second': {        # 第二次握手
            'seq': '',
            'ack': '',
        },
        'three': {         # 第三次握手
            'seq': '',
            'ack': '',
        }
    }
}
"""
"""
resp_relation = {  # 响应方的req与请求方的req进行关联
    'resp_seq1': 'req_seq1',
    'resp_seq2': 'req_seq2',
}
"""
"""
stream_table = {
    'seq(number1)':[buf, buf, buf, ....],  # 同一个请求的以太网的数据包(string->Eth), 把他们输出到pcap文件即可
    'seq(number2)':[buf, buf, buf, ....],
}
"""


# 输出三次握手的后的流表追踪buf
class PcapScanner():
    def __init__(self, pcapfile):
        self.pcapfile = pcapfile
        # self.newpcap = newpcap
        self.seq_pattern = re.compile(r'seq=(\d+),')
        self.ack_pattern = re.compile(r'ack=(\d+),')
        self.hash_table = {}
        self.stream_table = {}
        self.resp_relation = {}

    def run(self):
        # if not self.newpcap:
        #     pcapname = self.pcapfile.split('/')[-1].split('.')[0]
        #     self.newpcap = "new_{}_{}.pcap".format(pcapname, int(time.time()))
        # else:
        #     if 'pcap' not in self.newpcap:
        #         self.newpcap = self.newpcap + '.pcap'
        self.filter()
        # print self.hash_table
        # print '=*=*' * 30
        # print self.stream_table
        # print '=*=*' * 30
        return self.stream_table  # 返回stream_buf

    def filter(self):
        """return information about each packet in a pcap
            Args:
            pcap: dpkt pcap reader object (dpkt.pcap.Reader)
        """
        # outfile = open(self.newpcap, 'wb')
        # writer = dpkt.pcap.Writer(outfile)
        f = open(self.pcapfile, 'rb')
        packets = dpkt.pcap.Reader(f)

        for timestamp, buf in packets:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):   # 确保以太网数据包含一个IP数据包, Non IP Packet type not supported
                continue                               # 过滤空IP包
            ip = eth.data                              # 获取以太网帧（IP数据包）
            if not isinstance(ip.data, dpkt.tcp.TCP):  # 在传输层中检查TCP
                continue
            tcp = ip.data                              # 获取tcp数据
            # print('-->TCP Data: ', repr(tcp))

            """ 过滤三次握手后的首包"""
            seq = self.seq_pattern.findall(repr(tcp))
            ack = self.ack_pattern.findall(repr(tcp))
            if not (seq or ack):                       # seq、ack必须有一个, 一真即真
                continue
            if ack:
                ack = ack[0]
            if seq:
                seq = seq[0]

            if not ack and seq:                                                          # 一次握手请求
                self.hash_table[seq] = {}
                self.stream_table[seq] = [buf]
            if ack and seq:                                                              # 二次、三次、交流包
                if str(int(ack) - 1) in self.hash_table.keys():                          # 有一次握手记录
                    number = str(int(ack) - 1)
                    if 'second' not in self.hash_table[number].keys():                   # 新增二次握手
                        self.hash_table[number]['second'] = {'seq': seq, 'ack': ack}
                        self.stream_table[number].append(buf)                            # 将二次握手添加到buf
                        self.resp_relation[seq] = ack                                    # 新增关系表

                    # 存在二次握手记录, 看hash表有无第三次握手记录, 有就保存stream流
                    # 基本就是traffic响应包了
                    elif 'three' in self.hash_table[number].keys():
                        if number not in self.stream_table.keys():
                            self.stream_table[number] = []
                            self.stream_table[number].append(buf)
                        else:
                            self.stream_table[number].append(buf)

                # ack-1没有对应的hash表, 可能是三次握手或traffic请求包
                elif str(int(seq) - 1) in self.hash_table.keys():
                    number = str(int(seq) - 1)
                    if 'second' not in self.hash_table[number]:
                        pass
                    elif 'three' not in self.hash_table[number]:                 # 三次包
                        self.hash_table[number]['three'] = {'seq': seq, 'ack': ack}
                        self.stream_table[number].append(buf)
                    # 否则就是traffic包了
                    else:
                        if number not in self.stream_table.keys():
                            self.stream_table[number] = []
                            self.stream_table[number].append(buf)
                        else:
                            self.stream_table[number].append(buf)
                # traffic响应包
                elif str(int(seq) - 1) in self.resp_relation.keys():
                    number = str(int(seq) - 1)
                    second_ack = self.resp_relation[number]
                    number = str(int(second_ack) - 1)
                    if number not in self.stream_table.keys():
                        self.stream_table[number] = []
                        self.stream_table[number].append(buf)
                    else:
                        self.stream_table[number].append(buf)
            else:
                continue                                       # seq不存在

        # outfile.close()
        f.close()


if __name__ == "__main__":
    psf = PcapScanner('../jboss.pcap')
    print psf.run()
