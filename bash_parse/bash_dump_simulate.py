"""
dump_db.py stores the application logs (.bash_history) from six attack scenarios in the MSAS database
"""
import pandas as pd
import pymysql
from sqlalchemy import create_engine
import re
import json
import os
from CmdParser import CmdParser
from datetime import datetime
import copy

def mainconn():
    # modify the following parameters according to your own environment
    # conn = pymysql.connect(host='', port=, user='', passwd='', db='', charset='utf8mb4')
    return conn

def search_bash():
    conn = mainconn()
    cursor = conn.cursor()

    table = "_var_log_bash_command_history"

    sql = "SELECT id, hostname, log_message FROM `" + table + "`;"

    cursor.execute(sql)
    data=cursor.fetchall()

    conn.close()
    return data


host_list = {
    "web": "192.168.9.103",
    "reverseProxy": "192.168.9.105",
    "dataset": "192.168.9.101",
    "user1": "192.168.9.102",
    "user2": "192.168.9.104",
}

s1_timerange = ["2024-11-11 16:10:00", "2024-11-11 17:20:00"]
s2_timerange = ["2024-11-11 17:30:00", "2024-11-11 18:30:00"]


def df2sql(data, table_name):
    # modify the following parameters according to your own environment
    # engine = create_engine("mysql+pymysql://<user>:<password>@<host>:<port>/<db_name>?charset=utf8mb4")
    df = pd.DataFrame(data)
    df.to_sql(table_name, con=engine, if_exists="replace", index=False)

def getDataStructure():
    return {
        "command_id": "",
        "user": "",
        "remote_ip": "",
        "tty": "",
        "_raw": "",
        "authority": "",
        "command_keyword": "",
        "parsed_args": "",
        "input": "",
        "output": "",
        "target": "",
        "command_type": "",
        "is_sensitive": "",
        "timestamp": "",
        "host_ip": ""
    }

def sqlstr(s):
    return '"' + str(s) + '"'


pattern = r'\[([^]]*)\]'
command_id = 1
bash_parsed_list = {
    "s1_operation": [],
    "s2_operation": []
}
data = search_bash()
for data_i in data:
    bash_id, hostname, bash_command = data_i
    bash_parsed = getDataStructure()
    matches = re.findall(pattern, bash_command)
    timestamp, user, remote_ip, tty = matches
    timestamp = datetime.strptime(timestamp, '%Y-%m-%d-%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')
    if timestamp < s1_timerange[0] or timestamp > s2_timerange[1]:
        continue
    _raw = bash_command.split(']')[-1].strip()
    bash_parsed["timestamp"] = timestamp
    bash_parsed["user"] = user
    bash_parsed["remote_ip"] = remote_ip
    bash_parsed["tty"] = tty
    bash_parsed["authority"] = "root" if user == "root" else "user"
    bash_parsed["_raw"] = _raw
    bash_parsed["host_ip"] = host_list[hostname]
    try: 
        cmdParser = CmdParser(_raw)
        cmdParser.parse()
        for result in cmdParser.parsed_result:
            temp_parsed_dict = copy.deepcopy(bash_parsed)
            temp_parsed_dict["command_id"] = command_id
            temp_parsed_dict["command_keyword"] = result["command"]
            temp_parsed_dict["command_type"] = result["command_type"]
            temp_parsed_dict["parsed_args"] = sqlstr(result["parsed_args"])
            temp_parsed_dict["input"] = sqlstr(result["input"])
            temp_parsed_dict["output"] = sqlstr(result["output"])
            temp_parsed_dict["target"] = sqlstr(result["target"])
            temp_parsed_dict["is_sensitive"] = result["sensitive"]
            if timestamp >= s1_timerange[0] and timestamp <= s1_timerange[1]:
                bash_parsed_list["s1_operation"].append(temp_parsed_dict)
            if timestamp >= s2_timerange[0] and timestamp <= s2_timerange[1]:
                bash_parsed_list["s2_operation"].append(temp_parsed_dict)
            command_id += 1
    except Exception as e:
        print(e)
        continue
   

for key, value in bash_parsed_list.items():
    df2sql(value, key)