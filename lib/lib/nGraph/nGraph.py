# import json
import yaml
import datetime
import argparse

from pyvis.network import Network
from os.path import dirname as up

def init_argparse():
    parser = argparse.ArgumentParser(
        usage="%(prog)s --domain example.com --file vhost.yaml",
        description="Generate Network Graph For Sudomy."
    )
    parser.add_argument('--domain', type=str)
    parser.add_argument('--file', type=str, help="File in yaml format")
    return parser

parser = init_argparse()
args = parser.parse_args()

if args.file is None or args.domain is None:
    parser.print_help()
    exit(0)

main_domain = args.domain

# net =  Network(height="100%", width="100%", heading="{} - Graph".format(main_domain), bgcolor="#2d2e2e", font_color="white")
net =  Network(height="100%", width="100%", heading='<script>document.getElementsByTagName("center")[0].remove()</script>', bgcolor="#2d2e2e", font_color="white")
# net.barnes_hut()
# net.repulsion()
net.force_atlas_2based(gravity=-500, damping=2.0, overlap=5.0)
# net.hrepulsion(damping=5)
# def read_subdomain_data():
# with open("subdomain.txt", "rb") as f:
#     # data = read_subdomain_data()
#     json_data = {} #{"domain" : "tiket.com"}
#     for i in f.readlines():
#         tmp = i.split()
#         ip = tmp[0].decode()
#         domains = filter(None, tmp[1].decode().split(","))
#         # print(list(tmp))
#         # json_data[ip] = []
#         json_data[ip] = []
#         # json_data["ip"].append({ip : []})
#         # subdomain_data = tmp[1]
#         for domain in list(domains):
#             # print(domain)
#             # print(ip)
#             # for p in json_data["ip"]:
#                 # print(p)

#             json_data[ip].append(domain)
#     print(json.dumps(json_data))

# net.add_node(json_data.get("domain"))
# print(json_data)


try:
    domain_data = yaml.safe_load(open(args.file))
except:
    print("ERROR: File Is Not In Valid Yaml")
    exit(-1)

net.add_node(main_domain, color="#162347", label=main_domain, group=main_domain, labelHighlightBold=True)

for ip in domain_data:
    net.add_node(ip,label=ip, color="#bf281d", group=ip, physics=True, labelHighlightBold=True)
    net.add_edge(ip,main_domain,title=main_domain, arrowStrikethrough=True , width=3)

    for domain in domain_data.get(ip):
        net.add_node(domain, label=domain, title=domain, color="#828282", physics=True, group=domain, labelHighlightBold=True)
        net.add_edge(domain, ip, title=ip)

report_path = up(args.file)
d = datetime.date.today()
date_now = '{}-{}-{}'.format(d.strftime('%m'),d.strftime('%d'), d.strftime('%Y'))
net.show("{}/{}-nGraph_{}.html".format(report_path, main_domain, date_now))
