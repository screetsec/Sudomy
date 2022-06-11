#!/usr/bin/env python3
import multiprocessing
import subprocess
import os
import sys


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

def print_live(text):
    print(f"{PADDING}{YELLOW}{PADDING}⍥{PADDING}{RESET}[{GREEN}LIVE{RESET}]\t{text}")

def cyan(text):
    print('\033[36m {} \033[0m'.format(text))

def pinger(job_q, results_q):
    DEVNULL = open(os.devnull, 'w')
    while True:
        domain = job_q.get()
        if domain is None: break
        try:
            subprocess.check_call(['ping', '-c1', '-i 0.2', '-W1', domain], stdout=DEVNULL, stderr=DEVNULL)
            results_q.put(domain)
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
        multiprocessing.Process(target=pinger, args=(jobs, results))
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
