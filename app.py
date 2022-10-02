import os
import sys
import socket
import ipwhois
import netaddr
import argparse
import subprocess

def realpath(file):
    return os.path.dirname(os.path.abspath(__file__)) + file

def log(value, end='\n'):
    sys.stdout.write('\033[K' + str(value) + '\033[0m' + str(end))
    sys.stdout.flush()

class IpScrapper(object):
    def __init__(self):
        super(IpScrapper, self).__init__()

        self.verbose = False

    def log(self, value):
        log(value, end='\n')

    def log_replace(self, value):
        log(value, end='\r' if not self.verbose else '\n')

    def grab_cidr_from_asn(self, file_name, ip, asn):
        self.log(f"Grabbing cidr list from asn ({asn})")
        data_list = ipwhois.asn.ASNOrigin(ipwhois.net.Net(ip)).lookup(asn=asn, asn_methods=['whois'])
        cidr_list = []
        with open(file_name, 'w') as file:
            for i, data in enumerate(data_list['nets']):
                if ':' in data['cidr']:
                    continue
                cidr_list.append(data['cidr'])
                file.write(data['cidr'] + '\n')
                self.log_replace(f"  From {i} to {len(data_list['nets'])} - {data['cidr']}")
        self.log('  Complete \n')

        return list(set(cidr_list))

    def save_cleaned_cidr_list(self, file_name, cidr_list):
        self.log(f"Writing cidr list to file {realpath('/storage/.cache')}")
        with open(realpath('/storage/.cache'), 'w') as file:
            for i, cidr in enumerate(cidr_list):
                file.write(cidr + '\n')
                self.log_replace(f"  From {i} to {len(cidr_list)} - {cidr}")
        self.log('  Complete \n')

        self.log(f"Writing cleaned cidr list to file {file_name}")
        command = '{} < {}'.format(realpath('/cidr-cleaner.sh'), realpath('/storage/.cache'))
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        cidr_list = []
        with open(file_name, 'w') as file:
            for line in process.stdout:
                cidr = line.decode().strip()
                cidr_list.append(cidr)
                file.write(cidr + '\n')
                self.log_replace(f"  {cidr}")
        self.log('  Complete \n')

        return cidr_list

    def save_ip_from_cidr_list(self, file_name, cidr_list):
        self.log('Generating ip from cidr list')
        ip_list = []
        for i, cidr in enumerate(cidr_list):
            for ip in netaddr.IPNetwork(cidr):
                ip_list.append(str(ip))
                self.log_replace(f"  From {i} to {len(cidr_list)} - {cidr} - {ip}")
        self.log('  Complete \n')

        ip_list = list(set(ip_list))
        ip_list = sorted(ip_list, key=lambda ip: (
            int(ip.split('.')[0]),
            int(ip.split('.')[1]), 
            int(ip.split('.')[2]), 
            int(ip.split('.')[3]),
        ))

        self.log(f"Writing sorted ip to file {file_name}")
        with open(file_name, 'w') as file:
            for i, ip in enumerate(ip_list):
                file.write(ip + '\n')
                self.log_replace(f"  From {i} to {len(ip_list)} - {ip}")
        self.log('  Complete \n')

        return True

def main():
    parser = argparse.ArgumentParser(formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=52))
    parser.add_argument('--verbose', help='increase output verbosity', dest='verbose', action='store_true')
    parser.add_argument('--ip', help='--ip 112.215.101.72', dest='ip', type=str)
    parser.add_argument('--asn', help='--asn AS24203', dest='asn', type=str)

    arguments = parser.parse_args()
    if not arguments.ip or not arguments.asn:
        sys.exit('Usage: python3 app.py --ip 192.xx --asn ASxx')

    ip_scrapper = IpScrapper()
    ip_scrapper.verbose = arguments.verbose

    cidr_list = ip_scrapper.grab_cidr_from_asn(realpath(f"/storage/{arguments.asn}-CIDR-DIRTY.txt"), arguments.ip, arguments.asn)
    cidr_list = ip_scrapper.save_cleaned_cidr_list(realpath(f"/storage/{arguments.asn}-CIDR.txt"), cidr_list)
    respomnse = ip_scrapper.save_ip_from_cidr_list(realpath(f"/storage/{arguments.asn}-IP.txt"), cidr_list)

if __name__ == '__main__':
    main()
