import random
import re
import subprocess
import sys
import time
import requests
from prettytable import PrettyTable
from bs4 import BeautifulSoup

debug = False

ip_regex = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
as_regex = re.compile("[Oo]riginA?S?:\s*([\d\w]+?)\s")
county_regex = re.compile("[Cc]ountry:\s*([\d\w]+?)\s")
provider_regex = re.compile("mnt-by:\s*([\w\d-]+?)\s")


def parse(s, reg: re.Pattern):
    try:
        res = reg.findall(s)
        return res[0]
    except IndexError:
        return ''


def tracert(ip: str):
    cmd = ['tracert', ip]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE)
    raw_output = proc.stdout.decode('utf-8')
    if raw_output.find('Trace complete.') >= 0:
        return ip_regex.findall(raw_output)
    else:
        print('Invalid ip/site name')
        sys.exit(1)


def isGray(ip: str):
    return ip.startswith('192.168.') or ip.startswith('10.') or (ip.startswith(
        '172.') and 15 < int(ip.split('.')[1]) < 32)


def getIpInfo(ip: str):
    if isGray(ip):
        return ip, 'Gray', 'Gray', 'Gray'
    else:
        url = f"https://www.nic.ru/whois/?searchWord={ip}"
        r = requests.get(url)
        if debug:
            print(r.status_code)

        time.sleep(random.randint(6, 10))
        # Unnecessary, but makes result more stable

        soup_ing = str(BeautifulSoup(r.content, "html.parser"))
        system = parse(soup_ing, as_regex)
        country = parse(soup_ing, county_regex)
        provider = parse(soup_ing, provider_regex)
        if debug:
            print(system, country, provider)
        return ip, system, country, provider


def make_table(ips):
    headers = ['№', 'Ip', "AS", "Country", "Provider"]
    table_data = []
    i = 0
    for ip in ips:
        table_entry = getIpInfo(ip)
        print(table_entry)
        if i == 0:
            table_data.append('Target')
        else:
            table_data.append(i)
        table_data.extend(table_entry)
        i += 1
    row_size = len(headers)
    table = PrettyTable(headers)
    while table_data:
        table.add_row(table_data[:row_size])
        table_data = table_data[row_size:]
    print(table)


def main():
    if len(sys.argv) != 2:
        print('Usage: python tracetr.py [site name|ip]')
        return
    else:
        ip = sys.argv[1]
        ip_trace = tracert(ip)
        if debug:
            print(ip_trace)
        make_table(ip_trace)


if __name__ == "__main__":
    main()
