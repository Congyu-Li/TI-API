import sys
import csv
import json
import codecs
import urllib2
import argparse
from multiprocessing.dummy import Pool,Queue


ACCESS_KEY = 'your access_key'
API_URL = 'https://api.ti.360.com/ip/{ip}?accessKey={access_key}'

queue = Queue()

def request_api(ip):
    url = API_URL.format(ip=ip, access_key=ACCESS_KEY)
    for i in range(3):
        try:
            resp = urllib2.urlopen(url)
            break
        except:
            if i==2:
                raise
            pass
    return ip, json.loads(resp.read(), encoding='utf-8')

def ti_process(ip):
    ip, ret = request_api(ip)
    result = []
    if ret['code'] == 1100:
        detail = ret['detail']
        if detail.get('score'):
            result += [detail['score']['ip_address'],  detail['score']['360_ip_riskscore']]
        else:
            result += [ip, '']
        if detail.get('geo_location'):
            result += [detail['geo_location']['country'],detail['geo_location']['province/state'],
                    detail['geo_location']['city']]
        else:
            result += [''] * 3
        if detail.get('traits'):
            result += [
                detail['traits'].get('as_number', ''),
                detail['traits'].get('is_idc', ''),
                detail['traits'].get('is_proxy', ''),
                detail['traits'].get('latest_domain', ''),
                detail['traits'].get('latest_domain_time', ''),
                detail['traits'].get('service_provider', ''),
                detail['traits'].get('user_type', ''),
                ]
        else:
            result += [''] * 7
        if detail.get('malicious_type'):
            result += [
                detail['malicious_type']['is_botnet'],
                detail['malicious_type']['latest_botnet_time'],
                detail['malicious_type']['is_brute_force'],
                detail['malicious_type']['latest_brute_force_time'],
                detail['malicious_type'].get('is_ddos', ''),
                detail['malicious_type'].get('latest_ddos_time', ''),
                detail['malicious_type']['is_malicious'],
                detail['malicious_type']['latest_malicious_time'],
                detail['malicious_type']['is_scanner'],
                detail['malicious_type']['latest_scanner_time'],
                detail['malicious_type']['is_spam'],
                detail['malicious_type']['latest_spam_time']
                ]
        else:
            result += [''] * 12
        queue.put(result)
        return result

def input_reader(filename):
    with open(filename, 'r') as fd:
        csv_file = csv.reader(fd)
        lines = [line for line in csv_file]
    ip_index = lines[0].index('Source IP')
    if not ip_index:
        raise
    ips = {line[ip_index] for line in lines[1:]}
    return list(ips)

def writer_process(filename):
    with open(filename, 'w') as fw:
        writer = csv.writer(fw)
        headers = ['ip', 'score', 'country', 'province/state', 'city', 'as_number', 'is_idc', 'is_proxy',
                'latest_domain', 'latest_domain_time', 'service_provider', 'user_type', 'is_botnet',
                'latest_botnet_time', 'is_brute_force', 'latest_brute_force_time', 'is_ddos', 'latest_ddos_time',
                'is_malicious', 'latest_malicious_time', 'is_scanner', 'latest_scanner_time', 'is_spam',
                'latest_spam_time']
        writer.writerow(headers)
        while 1:
            row = queue.get()
            if row == 'finished!':
                break
            row = [i.encode('utf-8') for i in row]
            writer.writerow(row)

def make_argvparser():
     parser = argparse.ArgumentParser(description='from csv to csv')
     parser.add_argument('-i', '--input', dest='input_file', type=str, help='input file')
     parser.add_argument('-o', '--output', dest='output_file', type=str, help='output file')
     return parser

def main(option):
    input_file = option.input_file
    output_file = option.output_file
    ips = input_reader(input_file)
    w_pool = Pool(1)
    writer = w_pool.apply_async(writer_process, (output_file,))
    r_pool = Pool(5)
    r_pool.map(ti_process, ips)
    r_pool.close()
    r_pool.join()
    queue.put('finished!')
    writer.get()

if __name__ == '__main__':
    parser = make_argvparser()
    opt = parser.parse_args()
    if not opt.input_file and not opt.output_file:
        parser.print_help()
    else:
        main(opt)
