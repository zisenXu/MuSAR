from TimeUtils import TimeUtils
from DataLoader import AlertDataLoader, MSASDataLoader
from Dispatcher import Dispatcher
from DataSaver import DataSaver
from Config import *

###　use CPTC2018 dataset
if MODE == 'cptc':
    team_list = ["t1", "t2", "t5", "t7", "t8", "t9"]
    timeUtils = TimeUtils("2018-11-03 13:30:00", "2018-11-03 23:30:00", 60 * 60)
    for team in team_list:
        AG_OUTPUT_DIR = team + "_attackGraph" # output directory for attack graph
        alert_table_name = team + "_connection"  # table name for inter-host connections 
        host_log_table_name = team + "_operation" # table name for intra-host operations
        behaviour_table_name = team + "_behaviour" # table name for aggregated intra-host sensitive behaviours
        alertDataLoader = AlertDataLoader(alert_table_name=alert_table_name, host_log_table_name=host_log_table_name, behaviour_table_name=behaviour_table_name)
        dataSaver = DataSaver(behaviour_table_name)
        dispatcher = Dispatcher(timeUtils, alertDataLoader, dataSaver, AG_OUTPUT_DIR)
        dispatcher.dispatch()
### use MSAS dataset
elif MODE == 'msas':
    ### 连接靶场环境数据库
    scene_list = ["s1", "s2"]
    scene_timeUtils = {
        "s1": TimeUtils("2024-11-11 16:15:00", "2024-11-11 17:15:00", 60*60),
        "s2": TimeUtils("2024-11-11 17:30:00", "2024-11-11 18:30:00", 60*60)
    }      
    for i, scene in enumerate(scene_list):
        AG_OUTPUT_DIR = scene + "_attackGraph" # output directory for attack graph
        alert_table_name = scene + "_connection" # table name for inter-host connections
        host_log_table_name = scene + "_operation" # table name for intra-host operations
        behaviour_table_name = scene + "_behaviour" # table name for aggregated intra-host sensitive behaviours
        alertDataLoader = MSASDataLoader(alert_table_name=alert_table_name, host_log_table_name=host_log_table_name, behaviour_table_name=behaviour_table_name)
        dataSaver = DataSaver(behaviour_table_name)
        dispatcher = Dispatcher(scene_timeUtils[scene], alertDataLoader, dataSaver, AG_OUTPUT_DIR)
        dispatcher.dispatch()