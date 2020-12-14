# coding=utf-8
# desc: output snort rule by Pack2Snort.py
import os
import shlex
from subprocess import Popen, PIPE
from conf.app import ThirdPart_DIR


class SnortExport:
    def __init__(self, pcapfile, policyfile):
        self.pcapfile = pcapfile              # stream包或单包
        self.policyfile = policyfile          # 策略
        self.stderr = ''
        self.stdout = ''
        self.script_path = ThirdPart_DIR + '/Pcap2Snort.py'
        # self.script_path = '/home/pcapfilter/kubernetes/thirdscript' + '/Pcap2Snort.py'

    def _format_args(self):
        """
        return;; array=['python', 'Pcap2Snort.py', '-p', 'pcapfile.pcap', '-d', 'policy.json']
        """
        command = 'python3 {} -p {} -d {}'.format(self.script_path, self.pcapfile, self.policyfile)
        return shlex.split(command)

    def run(self):
        if not os.path.exists(self.script_path):
            print('File not found<{}>'.format(self.script_path))
            return

        command = self._format_args()
        process = Popen(command, stdout=PIPE, stderr=PIPE)
        try:
            (self.stdout, self.stderr) = process.communicate()
        except Exception as e:
            print(process.pid, e)
        finally:
            if os.path.exists(self.pcapfile):
                os.remove(self.pcapfile)
            if os.path.exists(self.policyfile):
                os.remove(self.policyfile)
        if self.stderr:
            print('Faield exec command <python3 Pcap2Snort.py -p {} -d {}>'.format(self.pcapfile, self.policyfile))
            print(self.stderr)
        else:
            print self.stdout


if __name__ == "__main__":
    temp_path = '/home/pcapfilter/kubernetes/output/'
    pcapfile = '{}jboss_j5gdv8two2.pcap'.format(temp_path)
    policyfile = '{}jboss_j5gdv8two2.json'.format(temp_path)
    se = SnortExport(pcapfile, policyfile)
    se.run()
