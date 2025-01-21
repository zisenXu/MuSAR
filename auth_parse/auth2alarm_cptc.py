"""
auth2alarm.py: extract anomalous log pattern from auth.log and construct unified representation as network alarms.
"""
import pandas as pd
import pymysql
import re
from sqlalchemy import create_engine
from log_patterns import *

def cptcconn():
    # modify the following parameters according to your own environment
    # conn = pymysql.connect(host='', port=, user='', passwd='', db='', charset='utf8mb4')
    return conn

# read auth.log from database or implement an interface to read data from files
def search_auth(team):
    conn = cptcconn()
    cursor = conn.cursor()

    table = team + "_auth"

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

def parse_auth(_raw):
    event_num = -1
    for k, v in feature_dict.items():
        if re.search(k, _raw):
            event_num = v
    if event_num == -1:
        return None
    category = category_dict[event_num]
    signature = signature_dict[event_num]
    severity = severity_dict[event_num]

    if event_num == 0:
        user_match = re.search(r" user=(.*)$", _raw)
        rip_match = re.search(r"rhost=([\d.]+)", _raw)

    elif event_num == 1:
        user_match = ""
        rip_match = re.search(r"error: Received disconnect from (.*?) port", _raw)
    
    elif event_num == 2:
        if re.search("invalid user", _raw):
            user_match = re.search(r"Failed password for invalid user (.*?) from", _raw)  
        else:
            user_match = re.search(r"Failed password for (.*?) from", _raw)
        rip_match = re.search(r"from (.*?) port", _raw)

    elif event_num == 3:
        user_match = re.search(r"Failed none for invalid user  (.*?) from", _raw)
        rip_match = re.search(r"from (.*?) port", _raw)
    
    elif event_num == 4:
        user_match = re.search(r": Invalid user (.*?) from", _raw)
        rip_match = re.search(r"from (.*?) port", _raw)

    elif event_num == 5:
        user_match = re.search(r"Accepted password for (.*?) from", _raw)
        rip_match = re.search(r"from (.*?) port", _raw)
        
    elif event_num == 6:
        user_match = re.search(r"Accepted publickey for (.*?) from", _raw)
        rip_match = re.search(r"from (.*?) port", _raw)
        pass

    user = user_match.group(1) if user_match else ""
    rip = rip_match.group(1) if rip_match else ""

    return (user, rip, category, signature, severity)

def df2sql(df, team):
    # modify the following parameters according to your own environment
    # engine = create_engine("mysql+pymysql://<user>:<password>@<host>:<port>/<db_name>?charset=utf8mb4")
    df.to_sql(f"{team}_alert_final", con=engine, if_exists="append", index=False)


for team in ["t1", "t2", "t5", "t7", "t8", "t9"]:
    data = search_auth(team)
    dataList = []
    for data_i in data:
        alert_dict = getDataStructure()
        parse_result = parse_auth(data_i[4])
        if parse_result is None:
            continue
        user, rip, category, signature, severity = parse_result
        if rip == "":
            continue
        alert_dict['_bkt'] = data_i[1]
        alert_dict['_cd'] = data_i[2]
        alert_dict['_indextime'] = data_i[3]
        alert_dict['timestamp'] = data_i[11]
        alert_dict['host'] = data_i[12]
        alert_dict['dip'] = data_i[13]
        alert_dict['source_type'] = data_i[14]
        alert_dict['in_iface'] = user
        alert_dict['event_type'] = 'secure_log'
        alert_dict['proto'] = data_i[5]
        alert_dict['sip'] = rip
        alert_dict['category'] = category
        alert_dict['signature'] = signature
        alert_dict['severity'] = severity
        alert_dict['payload'] = data_i[4]
        dataList.append(alert_dict)
    
    df = pd.DataFrame(dataList)
    duplicated_columns = ['timestamp', 'host', 'in_iface', 'proto', 'sip', 'sport', 'dip', 'dport', 'category', 'signature', 'severity']
    df = df.drop_duplicates(subset=duplicated_columns)


    df2sql(df, team)

