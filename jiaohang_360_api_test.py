#!/usr/bin/env python
# -*- coding: utf-8 -*-


import sys
import csv
import json
import urllib2
import logging
import argparse
from multiprocessing.dummy import Pool,Queue
import re
import codecs


logger = logging.getLogger('TI_API_DEMO')
_handler = logging.StreamHandler(sys.stdout)
logger.addHandler(_handler)
logger.setLevel(logging.INFO)

ACCESS_KEY = '2TuAdtJQFqs2SCyqc7G1'
API_URL = 'http://api.ti.360.com/ip/{ip}?accessKey={access_key}'

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
        if detail.get('score') and detail['score'].get('360_ip_riskscore'):
            result += [ip,  detail['score']['360_ip_riskscore']]
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
                detail['traits'].get('user_type', ''),
                detail['traits'].get('latest_domain', ''),
                detail['traits'].get('latest_domain_time', ''),
                detail['traits'].get('service_provider', ''),
                ]
        else:
            result += [''] * 7
        if detail.get('malicious_type'):
            result += [
                detail['malicious_type']['is_malicious'],
                detail['malicious_type']['latest_malicious_time'],
                detail['malicious_type']['is_botnet'],
                detail['malicious_type']['latest_botnet_time'],
                detail['malicious_type']['is_brute_force'],
                detail['malicious_type']['latest_brute_force_time'],
                detail['malicious_type']['is_ddos'],
                detail['malicious_type']['latest_ddos_time'],
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
    ip_match_reg = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
    ip_reg = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

    ip_list = []
    with open(filename, 'r') as f:
        line = f.readline()
        while line:
            line = line.strip()
            line = line.strip("\"")
            line = line.strip("'")
            line = line.strip()
            ips = ip_match_reg.findall(line)
            for ip in ips:
                if not ip_reg.match(ip):
                    print "非法IP\t" + line
                    #print "exit..."
                    #sys.exit(0)
                ip_list.append(ip)
            line = f.readline()
    print "查询IP共有:    " + str(len(ip_list))
    return ip_list

def writer_process(filename):
    count = 0
    with open(filename, 'w') as fw:
        #fw.write(codecs.BOM_UTF8)
        writer = csv.writer(fw)
        # headers = ['ip', 'score', 'country', 'province/state', 'city', 'as_number', 'is_idc', 'is_proxy',
        #         'latest_domain', 'latest_domain_time', 'service_provider', 'user_type', 'is_botnet',
        #         'latest_botnet_time', 'is_brute_force', 'latest_brute_force_time', 'is_ddos', 'latest_ddos_time',
        #         'is_malicious', 'latest_malicious_time', 'is_scanner', 'latest_scanner_time', 'is_spam',
        #         'latest_spam_time']
        headers = ['ip', '360风险值', '国家', '省/州', '城市', 'AS号', '是否IDC', '是否代理', '用户类型',
                   '最近解析域名', '最近解析域名时间', '服务提供商',  '是否有恶意行为',
                   '最近恶意行为时间', '是否botnet', '最近botnet时间', '是否brute_force', '最近brute_force时间',
                   '是否ddos', '最近ddos时间', '是否scanner', '最近scanner时间', '是否spam',
                   '最近spam时间']
        writer.writerow(headers)
        while 1:
            row = queue.get()
            if count % 100 == 0 and count > 0:
                logger.info('%d done!' % count)
            if row == 'finished!':
                break
            if row[0].encode('utf-8') == "":
                print row
            row = [i.encode('utf-8') for i in row]
            writer.writerow(row)
            count += 1
    logger.info('%d done' % count)
    logger.info('finished!')

def make_argvparser():
     parser = argparse.ArgumentParser(description='from csv to csv')
     parser.add_argument('-i', '--input', dest='input_file', type=str, help='input file')
     parser.add_argument('-o', '--output', dest='output_file', type=str, help='output file')
     #parser.add_argument('-p', '--precess_num', dest='pool_size', type=int, help='process pool size')
     return parser

def main(option):
    input_file = option.input_file
    output_file = option.output_file
    #pool_size = option.pool_size
    ips = input_reader(input_file)
    w_pool = Pool(1)
    writer = w_pool.apply_async(writer_process, (output_file,))
    r_pool = Pool(20)
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
