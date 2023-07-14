#!/usr/bin/env python3
import multiprocessing
import os
import re
import sys

import pydig


def get_lines(fname):
    with open(fname, "r") as f:
        lines = [l.strip() for l in f.readlines()]
        return lines

RESET="\033[0m"			# Normal Colour
RED="\033[0;31m" 		# Error / Issues
GREEN="\033[0;32m"		# Successful
BOLD="\033[01;01m"    		# Highlight
WHITE="\033[1;37m"		# BOLD
YELLOW="\033[1;33m"		# Warning
PADDING="  "
ip_regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"

def print_live(text):
    print(f"{PADDING}{YELLOW}{PADDING}⍥{PADDING}{RESET}[{GREEN}RESOLVER{RESET}]\t{text}")

def cyan(text):
    print('\033[36m {} \033[0m'.format(text))

def validate_ips(ip_list):
    valid_ips = []
    for ip in ip_list:
        if(re.search(ip_regex, ip)):
            valid_ips.append(ip)
    return valid_ips

def write_domain_ip(domain):
    with open("resolver_ips.txt", "a+") as fh:
        domain_name = str(domain).split(" ")[0]
        ip_addr = str(domain).split(" ")[1]
        fh.writelines(f"{domain_name} {ip_addr}\n")

def resolver(job_q, results_q):
    DEVNULL = open(os.devnull, 'w')
    while True:
        domain = job_q.get()
        if domain is None: break
        try:
            resolve = pydig.Resolver(executable='/usr/bin/dig', nameservers=['1.1.1.1', '1.0.0.1'], additional_args=['+time=10'])
            _ip = resolve.query(domain, 'A')
            if len(_ip) >= 1:
                ips = validate_ips(_ip)
                if len(ips) >= 1:
                    ip = ips[0]
                else:
                    ip = ""
            else:
                ip = ""
            results_q.put(domain + f" {ip}")
        except:
            pass
if __name__ == '__main__':
    domains = get_lines(str(sys.argv[1]))
    if len(domains) > 255:
        pool_size = 255
    else:
        pool_size = len(domains)
    jobs = multiprocessing.Queue()
    results = multiprocessing.Queue()
    pool = [
        multiprocessing.Process(target=resolver, args=(jobs, results))
        for i in range(pool_size)
    ]
    for p in pool:
        p.start()
    for i in domains:
        jobs.put(str(i))
    for p in pool:
        jobs.put(None)
    for p in pool:
        p.join()
    while not results.empty():
        domain = results.get()
        print_live(domain)
        write_domain_ip(domain)
