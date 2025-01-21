"""
auth2alarm.py: extract anomalous log pattern from mongo.log and construct unified representation as network alarms.
"""
import pymysql
import pandas as pd
from sqlalchemy import create_engine
import re
import host2ip
from log_patterns import *

def cptcconn():
    # modify the following parameters according to your own environment
    # conn = pymysql.connect(host='', port=, user='', passwd='', db='', charset='utf8mb4')
    return conn

def search_mongo(team):
    conn = cptcconn()
    cursor = conn.cursor()

    table = team + "_mongo"

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



def parse_mongo(_raw):
    event_num = -1
    for k, v in feature_dict.items():
        if re.search(k, _raw):
            event_num = v
    if event_num == -1:
        return None
    category = category_dict[event_num]
    signature = signature_dict[event_num]
    severity = severity_dict[event_num]
    ip_port_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5})'
    matches = re.findall(ip_port_pattern, _raw)

    if matches:
        ip_port = matches[0]
        ip, port = ip_port.split(':')
    else:
        ip, port = "", ""
    return (ip, port, category, signature, severity)

def df2sql(df, team):
    # modify the following parameters according to your own environment
    # engine = create_engine("mysql+pymysql://<user>:<password>@<host>:<port>/<db_name>?charset=utf8mb4")
    df.to_sql(f"{team}_alert", con=engine, if_exists="append", index=False)

for team in ["t1", "t2", "t5", "t7", "t8", "t9"]:
    data = search_mongo(team)
    dataList = []
    for data_i in data:
        alert_dict = getDataStructure()
        alert_dict['_bkt'] = data_i[1]
        alert_dict['_cd'] = data_i[2]
        alert_dict['_indextime'] = data_i[3]
        alert_dict['timestamp'] = data_i[5]
        alert_dict['host'] = data_i[6]
        alert_dict['source_type'] = data_i[8]
        parse_result = parse_mongo(data_i[4])
        if parse_result is None:
            continue
        sip, sport, category, signature, severity = parse_result
        if sip == '':
            continue
        alert_dict['event_type'] = 'mongodb_log'
        alert_dict['proto'] = "mongo"
        alert_dict['sip'] = sip
        alert_dict['dip'] = host2ip.host2ip(data_i[6][3:])
        alert_dict['category'] = category
        alert_dict['signature'] = signature
        alert_dict['severity'] = severity
        alert_dict['payload'] = data_i[4]
        dataList.append(alert_dict)
    df = pd.DataFrame(dataList)
    duplicated_columns = ['timestamp', 'host', 'in_iface', 'proto', 'sip', 'sport', 'dip', 'dport', 'category', 'signature', 'severity']
    df = df.drop_duplicates(subset=duplicated_columns)

    df2sql(df, team)
