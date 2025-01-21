"""
auth2alarm.py: extract anomalous log pattern from auth.log and construct unified representation as network alarms.
"""
import pandas as pd
import pymysql
import re
from sqlalchemy import create_engine
from datetime import datetime
from log_patterns import *

def cptcconn():
    # modify the following parameters according to your own environment
    # conn = pymysql.connect(host='', port=, user='', passwd='', db='', charset='utf8mb4')
    return conn


# read auth.log from database or implement an interface to read data from files
def search_auth():
    conn = mainconn()
    cursor = conn.cursor()

    table = "auth_ner"

    sql = "SELECT timestamp, source_port, _raw, host_ip  FROM `" + table + "` WHERE timestamp >= '2024-11-11 16:10:00' and timestamp <= '2024-11-11 18:30:00';"

    cursor.execute(sql)
    data=cursor.fetchall()

    conn.close()
    return data


def getDataStructure():
    return {
        "timestamp": "",
        "proto": "",
        "sip": "",
        "sport": "",
        "dip": "",
        "dport": "",
        "signature_id": "",
        "category": "",
        "signature": "",
        "severity": ""
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

def df2sql(df, table_name):
    # modify the following parameters according to your own environment
    # engine = create_engine("mysql+pymysql://<user>:<password>@<host>:<port>/<db_name>?charset=utf8mb4")
    df.to_sql(table_name, con=engine, if_exists="append", index=False)



data = search_auth()
dataList = {
    "s1_connection_new": [],
    "s2_connection_new": []
}
for data_i in data:
    timestamp, source_port, _raw, host_ip = data_i
    timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
    alert_dict = getDataStructure()
    parse_result = parse_auth(_raw)
    if parse_result is None:
        continue
    user, rip, category, signature, severity = parse_result
    if rip == "" and rip == host_ip:
        continue
    alert_dict['timestamp'] = timestamp
    alert_dict['proto'] = 'sshd'
    alert_dict['sip'] = rip
    alert_dict['sport'] = source_port
    alert_dict['dip'] = host_ip
    alert_dict['dport'] = 22
    alert_dict['category'] = category
    alert_dict['signature'] = signature
    alert_dict['severity'] = severity
    if timestamp >= "2024-11-11 16:10:00" and timestamp <= "2024-11-11 17:20:00":
        dataList["s1_connection_new"].append(alert_dict)
    if timestamp >= "2024-11-11 17:25:00" and timestamp <= "2024-11-11 18:30:00":
        dataList["s2_connection_new"].append(alert_dict)
for key, value in dataList.items():
    df = pd.DataFrame(value)
    duplicated_columns = ['timestamp', 'proto', 'sip', 'sport', 'dip', 'dport', 'category', 'signature', 'severity']
    df = df.drop_duplicates(subset=duplicated_columns)
    df2sql(df, key)

