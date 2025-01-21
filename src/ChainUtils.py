import ipaddress
import re
from Config import *
from urlextract import URLExtract

def extractIPAddresses(text):
    ipv4_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)'
    ipv4_addresses = re.findall(ipv4_pattern, text)
    if len(ipv4_addresses) == 0: 
        return False
    else:
        return ipv4_addresses

def ipJudge(ip, string):
    ip_list = extractIPAddresses(string)
    if ip_list is False: 
        return False
    if ip in ip_list: 
        return True
    for mask_bits in range(33): 
        network = ipaddress.IPv4Network(f"{ip}/{mask_bits}", strict=False)
        if str(network) in ip_list:
            return True
    return False

def extractDomains(text):
    extractor = URLExtract()
    urls = extractor.find_urls(text)
    if len(urls) == 0: 
        return False
    else:
        return urls

def sqlstr(s):
    return '"' + str(s) + '"'