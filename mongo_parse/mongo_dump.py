"""
dump_db.py stores the application logs (mongo.log) from six attack scenarios in the CPTC2018 database
"""
import pandas as pd
from sqlalchemy import create_engine


def getDataStructure():
    return {
        "id": "",
        "_bkt": "",
        "_cd": "",
        "_indextime": "",
        "_raw": "",
        "timestamp": "",
        "host": "",
        "source": "",
        "source_type": "",
    }


def df2sql(data, team):
    # modify the following parameters according to your own environment
    # engine = create_engine("mysql+pymysql://<user>:<password>@<host>:<port>/<db_name>?charset=utf8mb4")
    df = pd.DataFrame(data)
    df.to_sql(f"{team}_mongo", con=engine, if_exists="replace", index=False)




def parseData(log_file, team):
    with open(log_file, 'r')as f:
        content = eval(f.read())
    f.close()
    parsedList = []
    id = 1
    for item in content:
        _bkt = item["_bkt"]
        _cd = item["_cd"]
        _indextime = item["_indextime"]
        _raw = item["_raw"]
        timestamp = item["_time"].split(".")[0]
        host = item["host"]
        source = item["source"]
        source_type = item["sourcetype"]

        dataDict = getDataStructure()
        dataDict["id"] = id
        dataDict["_bkt"] = _bkt
        dataDict["_cd"] = _cd
        dataDict["_indextime"] = _indextime
        dataDict["_raw"] = _raw
        dataDict["timestamp"] = timestamp
        dataDict["host"] = host
        dataDict["source"] = source
        dataDict["source_type"] = source_type

        parsedList.append(dataDict)
        id += 1
    df2sql(parsedList, team)


def main():
    for team in ["t2", "t5", "t7", "t8", "t9"]:
        # modify the following parameters according to your own environment
        json_file = "<path>/cptc-2018/{}/mongodb.json".format(team)
        parseData(json_file, team)


if __name__ == '__main__':
    main()