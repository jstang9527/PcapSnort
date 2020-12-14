# coding=utf-8
import os

# 当前文件的路径
CURRENT_DIR = os.path.abspath(os.path.dirname(__file__))

# main.py的路径
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 配置文件路径
CONF_DIR = BASE_DIR + '/conf'

# 默认数据文件
DEFAULT_DATA = CONF_DIR + '/data.json'

# 默认pcap输出路径
OUTPUT_DIR = BASE_DIR + '/output'

# 第三方脚本工具目录
ThirdPart_DIR = BASE_DIR + '/thirdscript'