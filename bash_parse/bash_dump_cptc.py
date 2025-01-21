"""
dump_db.py stores the application logs (.bash_history) from six attack scenarios in the CPTC2018 database
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
import host2ip


def getDataStructure():
    return {
        "command_id": "",
        "_bkt": "",
        "_cd": "",
        "_indextime": "",
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
        "host": "",
        "host_ip": "",
        "source_type": "",
        "label": 1
    }


def df2sql(data, team):
    # modify the following parameters according to your own environment
    # engine = create_engine("mysql+pymysql://<user>:<password>@<host>:<port>/<db_name>?charset=utf8mb4")
    df = pd.DataFrame(data)
    df.to_sql(f"{team}_bash", con=engine, if_exists="replace", index=False)

def split_operaters(cmd):
    separators = ['&&', '\|\|']
    separator_regex = '|'.join(r'\s*{}\s*'.format(separator) for separator in separators)
    parts = re.split(separator_regex, cmd)
    return parts

def sqlstr(s):
    return '"' + str(s) + '"'

def parseData(log_file, team):
    with open(log_file, 'r')as f:
        content = eval(f.read())
    f.close()
    parsedList = []
    command_id = 1
    newline_flag = False
    for item in content[::-1]:
        _raw = item["_raw"].replace('\\', '/')
        if _raw == "clear":
            newline_flag = False
            continue
        if newline_flag == True:
            if _raw != _raw_last:
                _raw = _raw_last + _raw
        if _raw[-1] == '\\' and _raw[-2] != '\\':
            newline_flag = True
            _raw_last = _raw[:-1]
            continue
        else:
            newline_flag = False

        _raw_list = split_operaters(_raw)
        _bkt = item["_bkt"]
        _cd = item["_cd"]
        _indextime = item["_indextime"]
        if "root" in item["source"]:
            user = "root"
        else:
            user = item["source"].split("/")[2]

        timestamp = item["_time"].split('.')[0]
        host = item["host"]
        host_short = re.search(r't\d-(.*)', host)
        host_ip = host2ip.host2ip(host_short.group(1))
        source_type = item["sourcetype"]

        for _raw_i in _raw_list:
            dataDict = getDataStructure()
            dataDict["_bkt"] = _bkt
            dataDict["_cd"] = _cd
            dataDict["_indextime"] = _indextime
            dataDict["user"] = user
            dataDict["_raw"] = _raw_i
            dataDict["timestamp"] = timestamp
            dataDict["host"] = host
            dataDict["host_ip"] = host_ip
            dataDict["source_type"] = source_type
            if user == "root" or _raw_i.split(" ")[0] == "sudo":
                dataDict["authority"] = "root"
            else:
                dataDict["authority"] = "user"
            try:
                cmdParser = CmdParser(_raw)
                cmdParser.parse()
                for result in cmdParser.parsed_result:
                    temp_parsed_dict = copy.deepcopy(dataDict)
                    temp_parsed_dict["command_id"] = command_id
                    temp_parsed_dict["command_keyword"] = result["command"]
                    temp_parsed_dict["command_type"] = result["command_type"]
                    temp_parsed_dict["parsed_args"] = sqlstr(result["parsed_args"])
                    temp_parsed_dict["input"] = sqlstr(result["input"])
                    temp_parsed_dict["output"] = sqlstr(result["output"])
                    temp_parsed_dict["target"] = sqlstr(result["target"])
                    temp_parsed_dict["is_sensitive"] = result["sensitive"]
                    parsedList.append(temp_parsed_dict)
                    command_id += 1
            except Exception as e:
                print(e)
                continue
    df2sql(parsedList, team)



def main():
    for team in ["t1", "t2", "t5", "t7", "t8", "t9"]:
        # modify the following parameters according to your own environment
        json_file = "<path>/cptc-2018/{}/bash_history.json".format(team)
        parseData(json_file, team)


if __name__ == '__main__':
    main()