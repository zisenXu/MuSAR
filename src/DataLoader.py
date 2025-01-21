import pymysql
import os
import time
from Config import *

class DataLoader:
    def __init__(self):
        self.connect_host = connect_host 
        self.connect_port = connect_port
        self.connect_user = connect_user
        self.connect_pass = connect_pass
        self.connect_db = db_name
        self.alert_table_name = ""
        self.behaviour_table_name = ""
    
    def getConn(self):
        conn = pymysql.connect(host=self.connect_host, port=self.connect_port, user=self.connect_user,
                               passwd=self.connect_pass, db=self.connect_db, charset="utf8mb4")
        return conn

    def getBehaviourData(self, start_time, end_time):
        conn = self.getConn()
        cursor = conn.cursor()
        sql = "SELECT behaviour_id, host, start_time, end_time, info_path, attack_stage, raw_sequence, cmd_id_list, target FROM `" + self.behaviour_table_name + "`" + " WHERE start_time >= %s " + "and start_time < %s"
        sql_args = (start_time, end_time)
        try:
            cursor.execute(sql, sql_args)
            data = cursor.fetchall()
        except Exception as e:
            print("Error occurred in querying intra-host sensitive behaviors: {} \n Current query statement is: {}".format(e, sql))
        finally:
            cursor.close()
            conn.close()
        return data

## msas
class MSASDataLoader(DataLoader):
    def __init__(self, alert_table_name, host_log_table_name, behaviour_table_name):
        super(MSASDataLoader, self).__init__()
        self.alert_table_name = alert_table_name
        self.behaviour_table_name = behaviour_table_name
        self.host_log_table_name = host_log_table_name

    def getData(self, start_time, end_time, fetchAll=False):
        conn = self.getConn()
        cursor = conn.cursor()
        sql = "SELECT sip, dip, category, severity, 1, proto, sport, dport, signature, alert_id, timestamp, label FROM `" + self.alert_table_name + "` WHERE timestamp >= %s " + "and timestamp <= %s "
        sql_args = (start_time, end_time)
        if fetchAll:
            sql = "SELECT * FROM `" + self.alert_table_name + "`"
            # sql = "SELECT sip, dip, category, severity, 1, proto, sport, dport, signature, alert_id, timestamp FROM `" + self.alert_table_name + "`"
        try:
            if fetchAll:
                cursor.execute(sql)
            else:
                cursor.execute(sql, sql_args)
            data = cursor.fetchall()
        except Exception as e:
            print("Error occurred in querying inter-host connections: {} \n Current query statement is: {}".format(e, sql))
        finally:
            cursor.close()
            conn.close()
        return data
    

    def getHostData(self, start_time, end_time, fetchAll=False):
        conn = self.getConn()
        cursor = conn.cursor()
        sql = "SELECT command_id, user, _raw, authority, command_keyword, parsed_args, input, output, target, command_type, timestamp, host_ip, is_sensitive, label FROM `" + self.host_log_table_name + "`" + " WHERE timestamp >= %s " + "and timestamp <= %s"
        sql_args = (start_time, end_time)
        if fetchAll:
            sql = "SELECT * FROM `" + self.host_log_table_name + "`"
        try:
            if fetchAll:
                cursor.execute(sql)
            else:
                cursor.execute(sql,sql_args)
            data = cursor.fetchall()
        except Exception as e:
            print("Error occurred in querying intra-host operations: {} \n Current query statement is: {}".format(e, sql))
        finally:
            cursor.close()
            conn.close()
        return data


## cptc2018
class AlertDataLoader(DataLoader):
    def __init__(self, alert_table_name, host_log_table_name, behaviour_table_name):
        super(AlertDataLoader, self).__init__()
        self.alert_table_name = alert_table_name
        self.behaviour_table_name = behaviour_table_name
        self.host_log_table_name = host_log_table_name

    def getData(self, start_time, end_time, fetchAll=False):
        conn = self.getConn()
        cursor = conn.cursor()
        sql = "SELECT sip, dip, category, severity, host, proto, sport, dport, signature, alert_id, timestamp, label FROM `" + self.alert_table_name + "` WHERE timestamp >= %s " + "and timestamp <= %s "
        sql_args = (start_time, end_time)
        if fetchAll:
            sql = "SELECT sip, dip, category, severity, host, proto, sport, dport, signature, alert_id, timestamp, label FROM `" + self.alert_table_name + "`"
        try:
            if fetchAll:
                cursor.execute(sql)
            else:
                cursor.execute(sql, sql_args)
            data = cursor.fetchall()
        except Exception as e:
            print("Error occurred in querying inter-host connections: {} \n Current query statement is: {}".format(e, sql))
        finally:
            cursor.close()
            conn.close()
        return data
    
    def getHostData(self, start_time, end_time, fetchAll=False):
        conn = self.getConn()
        cursor = conn.cursor()
        sql = "SELECT command_id, user, _raw, authority, command_keyword, parsed_args, input, output, target, command_type, timestamp, host_ip, is_sensitive, label FROM `" + self.host_log_table_name + "`" + " WHERE timestamp >= %s " + "and timestamp <= %s"
        sql_args = (start_time, end_time)
        if fetchAll:
            sql = "SELECT * FROM `" + self.host_log_table_name + "`"
        try:
            if fetchAll:
                cursor.execute(sql)
            else:
                cursor.execute(sql,sql_args)
            data = cursor.fetchall()
        except Exception as e:
            print("Error occurred in querying intra-host operations: {} \n Current query statement is: {}".format(e, sql))
        finally:
            cursor.close()
            conn.close()
        return data