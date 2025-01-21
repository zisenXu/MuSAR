import pymysql
import os
import time
from Config import *
from sqlalchemy import create_engine
import pandas as pd

class DataSaver:
    def __init__(self, table_name):
        self.connect_host = connect_host 
        self.connect_port = connect_port
        self.connect_user = connect_user
        self.connect_pass = connect_pass
        self.connect_db = db_name
        self.table_name = table_name
    
    def getConn(self):
        conn = pymysql.connect(host=self.connect_host, port=self.connect_port, user=self.connect_user,
                               passwd=self.connect_pass, db=self.connect_db, charset="utf8mb4")
        return conn
    
    def getEngine(self):
        engine = create_engine("mysql+pymysql://{}:{}@{}:{}/{}?charset=utf8mb4".format(connect_user, connect_pass, connect_host, connect_port, db_name))
        return engine


    def tableCreate(self):
        conn = self.getConn()
        cursor = conn.cursor()
        sql1 = 'DROP TABLE IF EXISTS `' + self.table_name + '`'
        sql2 = 'CREATE TABLE IF NOT EXISTS `' + self.table_name + '`' +\
                '(behaviour_id INT NOT NULL,'\
                'host VARCHAR(255) NOT NULL,'\
                'start_time VARCHAR(255) NOT NULL,'\
                'end_time VARCHAR(255) NOT NULL,'\
                'info_path TEXT,'\
                'attack_stage TEXT,'\
                'raw_sequence TEXT,'\
                'cmd_id_list TEXT,' \
                'target TEXT,' \
                'PRIMARY KEY (behaviour_id))'
        try:
            cursor.execute(sql1)
            cursor.execute(sql2)
        except Exception as e:
            print('Error in creating intra-host sensitive behaviors:{}'.format(e))

    def saveBehaviour(self, behaviour_data):
        engine = self.getEngine()
        df = pd.DataFrame(behaviour_data)
        df.to_sql(self.table_name, con=engine, if_exists="append", index=False)
        print("Data saved successfully!")