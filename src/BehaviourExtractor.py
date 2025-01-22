from Config import *
import collections
from datetime import datetime
from ChainUtils import *
from prompt import get_behavior_stage
from AttackStage import *

class BehaviourExtractor(object):
    def __init__(self, alertDataLoader, dataSaver, behavior_id,  team=None) -> None:
        self.alertDataLoader = alertDataLoader
        self.dataSaver = dataSaver
        self.team = team
        self.behaviour_id = behavior_id
    def sort_data_by_host(self, data):
        res_dict = collections.defaultdict(list)
        host_list = list(set([bash[11] for bash in data]))
        for bash in data:
            res_dict[bash[11]].append(bash)
        for key, value in res_dict.items():
            res_dict[key] = sorted(value, key=lambda x: x[10])
        return res_dict
    
    def analyzeBehaviourResult(self, node_attribute_list, indices):
        cmd_id_list = []
        cmd_list = []
        info_path = ""
        stage_list = set()
        for index in range(len(indices)):
            cur_cmd_id = node_attribute_list[indices[index]]["cmd_id"]
            cmd_id_list.append(cur_cmd_id)
            cmd = node_attribute_list[indices[index]]["cmd"]
            cur_input = node_attribute_list[indices[index]]["input"]
            cmd_keyword = node_attribute_list[indices[index]]["cmd_keyword"]
            cur_cmd_type = node_attribute_list[indices[index]]["cmd_type"]
            if cur_cmd_type:
                stage_list.add(macro_inv["MacroAttackStage." + cur_cmd_type])
            cmd_list.append(cmd)
            if index == 0: # first operation 
                if cur_input != "None":
                    info_path += f"{cur_input}->"
                info_path += cmd_keyword
            else: 
                pre_output = node_attribute_list[indices[index-1]]["output"]
                pre_cmd_keyword = node_attribute_list[indices[index-1]]["cmd_keyword"]
                pre_cmd_type = node_attribute_list[indices[index-1]]["cmd_type"]
                if cur_input != "None" and cur_input != "stdout" and pre_output != "stdout" and pre_output == cur_input:
                    info_path += f"->{cur_input}->{cmd_keyword}"
                    continue
                if pre_cmd_keyword == cmd_keyword and cur_cmd_type == pre_cmd_type and cur_input == "None":
                    continue
                info_path += ";"
                if cur_input != "None":
                    info_path += f"{cur_input}->"
                info_path += cmd_keyword
        # no sensitive commands, return Collection stage
        if len(stage_list) == 0:
            stage = macro_inv["MacroAttackStage.Collection"]
        elif len(stage_list) == 1:
            stage = stage_list.pop()
        else:
            stage_qwen = get_behavior_stage(cmd_list)
            if stage_qwen != "invalid":
                stage = macro_inv["MacroAttackStage." + stage_qwen]
            else:
                stage = max(stage_list)
        return stage, info_path, cmd_id_list
    
    # structured representation of intra-host sensitive behaviors
    def getBehaviourStructure(self):
        return {
            "behaviour_id": 0,
            "host": "",
            "start_time": "",
            "end_time": "",
            "info_path": "",
            "attack_stage": "",
            "raw_sequence": "",
            "cmd_id_list": []
        }
    
    def extractUserBehavior(self, data):
        host_dict = self.sort_data_by_host(data)
        behaviour_data = []
        total_sensitive_cmd_cnt = 0
        total_sensitive_behavior_cmd_cnt = 0
        for host_ip, bash_list in host_dict.items():

            print("*"*25+f"extract user behaviour from host {host_ip}"+"*"*25)
            node_attribute_list = [] 
            user_behaviour_list = [0] * len(bash_list) # behavior id list
            behaviour_id = 1
            for i, bash in enumerate(bash_list):
                cmd_id = bash[0]
                user = bash[1]
                cmd = bash[2]
                authority = bash[3]
                cmd_keyword = bash[4]
                parsed_args =eval(bash[5].strip('"'))
                args_list = [item[1] for item in parsed_args if item[1] is not None]
                try:
                    input = eval(bash[6])
                except Exception as e:
                    input = bash[6]
                try: 
                    output = eval(bash[7])
                except Exception as e:
                    output = bash[7]
                target = eval(bash[8].strip('"'))
                cmd_type = bash[9]
                timestamp = bash[10]
                host_ip = bash[11]
                is_sensitive = int(bash[12])
                total_sensitive_cmd_cnt += 1 if is_sensitive else 0
                node_attribute = {
                    "cmd_id": cmd_id,
                    "user": user,
                    "cmd": cmd,
                    "authority": authority,
                    "cmd_keyword": cmd_keyword,
                    "parsed_args": parsed_args,
                    "args_list": args_list,
                    "input": input,
                    "output": output,
                    "target": target,
                    "cmd_type": cmd_type,
                    "timestamp": timestamp,
                    "host_ip": host_ip,
                    "is_sensitive": is_sensitive,
                }
                if i == 0: # first operation
                    if is_sensitive: # if sensitive, assign a new behavior id
                        user_behaviour_list[i] = behaviour_id
                        behaviour_id += 1
                    node_attribute_list.append(node_attribute)
                    continue
            
                max_association_score = 0
                max_association_score_index = -1
                for j, pre_attribute in enumerate(node_attribute_list[::-1]):
                    j = len(node_attribute_list) - 1 - j
                    if max_association_score >= SEQ_W / (i - j):
                        break
                    if cmd_type == pre_attribute['cmd_type'] and is_sensitive and pre_attribute['is_sensitive'] and i-j <= 5:  # Association Weight
                        score = ASSO_W / (i - j)
                        if score > max_association_score:
                            max_association_score = score
                            max_association_score_index = j             
                    if input == "None" and output == "stdout" and len(args_list) == 0:
                        break
                    if pre_attribute["input"] == "None" and pre_attribute["output"] == "stdout" and len(pre_attribute["args_list"]) == 0:
                        continue
                    if input != "None" and input != "stdout" and pre_attribute["output"] == input and (is_sensitive or pre_attribute['is_sensitive']):  # Sequential Weight
                        score = SEQ_W / (i - j)
                        if score > max_association_score:
                            max_association_score = score
                            max_association_score_index = j
                    if input != "None" and pre_attribute["input"] == input and (is_sensitive or pre_attribute['is_sensitive']) and i-j <= 10: # Similarity Weight
                        score = SIM_W / (i - j)
                        if score > max_association_score:
                            max_association_score = score
                            max_association_score_index = j
                if max_association_score_index != -1:
                    if user_behaviour_list[max_association_score_index] == 0:
                        user_behaviour_list[max_association_score_index] = behaviour_id
                        behaviour_id += 1
                    user_behaviour_list[i] = user_behaviour_list[max_association_score_index]
                else:
                    if is_sensitive:
                        user_behaviour_list[i] = behaviour_id
                        behaviour_id += 1

                node_attribute_list.append(node_attribute)

            # analyze behaviour
            behaviour_dict = collections.defaultdict(list)
            for i, behaviour_id in enumerate(user_behaviour_list):
                if behaviour_id != 0:
                    total_sensitive_behavior_cmd_cnt += 1
                    behaviour_dict[behaviour_id].append(i)
                    
            for behaviour_id, indices in behaviour_dict.items():
                _behaviour = self.getBehaviourStructure()
                _behaviour["behaviour_id"] = self.behaviour_id
                _behaviour["host"] = host_ip
                _behaviour["start_time"] = node_attribute_list[indices[0]]['timestamp']
                _behaviour["end_time"] = node_attribute_list[indices[-1]]['timestamp']
                stage, info_path, cmd_id_list = self.analyzeBehaviourResult(node_attribute_list=node_attribute_list, indices=indices)
                _behaviour["info_path"] = info_path
                _behaviour["attack_stage"] = stage
                _behaviour["cmd_id_list"] = sqlstr(cmd_id_list)
                _behaviour["raw_sequence"] = ";".join([node_attribute_list[index]["cmd"] for index in indices])
                _behaviour['target'] = sqlstr(list(set([t for index in indices for t in node_attribute_list[index]['target'] if len(t) > 0])))
                behaviour_data.append(_behaviour)
                self.behaviour_id += 1
        print(f"total number of history command logs (.bash_history) is:{len(data)}, total number of sensitive intra-host operations is:{total_sensitive_cmd_cnt}, total number of sensitive behaviors is:{total_sensitive_behavior_cmd_cnt}")
        return behaviour_data

    def OrganizeData(self, behaviour_data):
        host_behaviour_dict = collections.defaultdict(list)
        behaviour_data = sorted(behaviour_data, key=lambda x: x[2])
        for behaviour in behaviour_data:
            behaviour[2] = datetime.strptime(behaviour[2], "%Y-%m-%d %H:%M:%S") # start_time
            behaviour[3] = datetime.strptime(behaviour[3], "%Y-%m-%d %H:%M:%S") # end_time
            behaviour[-2] = eval(eval(behaviour[-2])) # cmd_id_list
            behaviour[-1] = eval(eval(behaviour[-1])) # target
            host_behaviour_dict[behaviour[1]].append(tuple(behaviour))
        return host_behaviour_dict, len(behaviour_data)


    def getData(self, start_time, end_time):
        host_data = self.alertDataLoader.getHostData(start_time, end_time)
        host_label_dict = collections.defaultdict(list)
        new_host_data = []
        for data in host_data:
            command_id = data[0]
            label = data[-1]
            host_label_dict[label].append(command_id)
            new_host_data.append(data[:])
        return new_host_data, host_label_dict


    def extract(self, start_time, end_time):
        host_data, host_label_dict = self.getData(start_time, end_time)
        if READ_BEHAVIOR_FROM_DATABASE: # read behaviors from database
            behaviour_data = [list(behaviour) for behaviour in self.alertDataLoader.getBehaviourData(start_time, end_time)]
        else: # extract behaviors from host_data and save into database
            behaviour_data = self.extractUserBehavior(host_data)
            self.dataSaver.saveBehaviour(behaviour_data)
            behaviour_data = [list(behaviour.values()) for behaviour in behaviour_data]
        host_behaviour_dict, behaviourCount = self.OrganizeData(behaviour_data)
        return host_data, host_behaviour_dict, behaviourCount, host_label_dict, self.behaviour_id