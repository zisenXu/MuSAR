"""
auth2alarm.py: extract anomalous log pattern from imap.log and construct unified representation as network alarms.
"""
import pymysql
import pandas as pd
from sqlalchemy import create_engine
import re
from log_patterns import *

def cptcconn():
    # modify the following parameters according to your own environment
    # conn = pymysql.connect(host='', port=, user='', passwd='', db='', charset='utf8mb4')
    return conn

# read imap.log from database or implement an interface to read data from files
def search_auth(team):
    conn = cptcconn()
    cursor = conn.cursor()

    table = team + "_imap

    sql = "SELECT * FROM `" + table + "`;"

    cursor.execute(sql)
    data=cursor.fetchall()

    conn.close()
    return data

def getDataStructure():
    return {
        "_bkt": "",
        "_cd": "",
        "_indextime": "",
        "timestamp": "",
        "host": "",
        "source_type": "",
        "in_iface": "",
        "event_type": "",
        "proto": "",
        "sip": "",
        "sport": "",
        "dip": "",
        "dport": "",
        "signature_id": "",
        "category": "",
        "signature": "",
        "severity": "",
        "payload": "",
        "http_details": "",
        "icmp_details": "",
        "stream": "",
        "packet": "",
        "packet_info": ""
    }

def parse_imap(_raw):
    event_num = -1
    for k, v in feature_dict.items():
        if re.search(k, _raw):
            event_num = v
    if event_num == -1:
        return None
    valid_log = ' '.join(_raw.split(" ")[5:])
    proto = valid_log.split(': ')[0]    # 'dovecot'
    category = category_dict[event_num]
    signature = signature_dict[event_num]
    severity = severity_dict[event_num]
    if 'user' not in valid_log.split(': ')[3]:
        input_string = valid_log.split(': ')[4]
        user_match = re.search(r'user=<([^>]+)>', input_string)
        rip_match = re.search(r'rip=([\d.]+)', input_string)
        lip_match = re.search(r'lip=([\d.]+)', input_string)
    else:
        input_string = valid_log.split(': ')[3]
        user_match = re.search(r'user=<([^>]+)>', input_string)
        rip_match = re.search(r'rip=([\d.]+)', input_string)
        lip_match = re.search(r'lip=([\d.]+)', input_string)

    user = user_match.group(1) if user_match else ""
    rip = rip_match.group(1) if rip_match else ""
    lip = lip_match.group(1) if lip_match else ""
    return (proto, category, signature, severity, user, rip, lip)

def df2sql(df, team):
    # modify the following parameters according to your own environment
    # engine = create_engine("mysql+pymysql://<user>:<password>@<host>:<port>/<db_name>?charset=utf8mb4")
    df.to_sql(f"{team}_alert", con=engine, if_exists="append", index=False)

for team in ["t1", "t2", "t5", "t7", "t8", "t9"]:
    data = search_auth(team)
    dataList = []
    for data_i in data:
        alert_dict = getDataStructure()
        parse_result = parse_imap(data_i[4])
        if parse_result is None:
            continue
        proto, category, signature, severity, user, rip, lip = parse_result
        if not rip.startswith("10.0.254") or lip == "":
            continue
        alert_dict['_bkt'] = data_i[1]
        alert_dict['_cd'] = data_i[2]
        alert_dict['_indextime'] = data_i[3]
        alert_dict['timestamp'] = data_i[5]
        alert_dict['host'] = data_i[6]
        alert_dict['source_type'] = data_i[8]
        alert_dict['in_iface'] = user
        alert_dict['event_type'] = 'imap_log'
        alert_dict['proto'] = proto
        alert_dict['sip'] = rip
        alert_dict['dip'] = lip
        alert_dict['category'] = category
        alert_dict['signature'] = signature
        alert_dict['severity'] = severity
        alert_dict['payload'] = data_i[4]
        dataList.append(alert_dict)
    df = pd.DataFrame(dataList)
    duplicated_columns = ['timestamp', 'host', 'in_iface', 'proto', 'sip', 'sport', 'dip', 'dport', 'category', 'signature', 'severity']
    df = df.drop_duplicates(subset=duplicated_columns)

    df2sql(df, team)

