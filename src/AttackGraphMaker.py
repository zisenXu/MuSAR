from Config import *
from AttackStage import *
import os
import copy
from ChainUtils import *
from collections import defaultdict

class AttackGraphMaker(object):
    def __init__(self, completeChain, chain_label, AG_OUTPUT_DIR, chainResultStat) -> None:
        self.completeChain = completeChain
        self.chain_label = chain_label
        self.startTimes = {}
        self.AG_OUTPUT_DIR = AG_OUTPUT_DIR
        self.chainResultStat = chainResultStat

    def translate(self, label):
        new_label = ""
        parts = label.split("|")

        if len(parts) >= 1:
            new_label += verbose_micro[parts[0]]
        if len(parts) >= 2:
            new_label += "\n" + parts[1]
        if len(parts) >= 3:
            new_label += " | " + parts[2]
        if len(parts) >= 4:
            new_label += "|" + parts[3]

        return new_label


    def make_AG(self, condensed_data):
        nodes = {}
        edges = {}
        graph = []
        AGname = self.chain_label.replace(':', '-').replace(' ', '-')
        print(AGname)
        graph.append((0, 'digraph "' + AGname + '" {'))
        graph.append((0, 'rankdir="BT"; \n graph [ nodesep="0.2", ranksep="0.2"] \n node [ fontname=Arial, fontsize=24,penwidth=3]; \n edge [ fontname=Arial, fontsize=20,penwidth=5 ];'))
        count = 1
        for hop in condensed_data: 
            for attacker, episodes in hop.items():
                att, vic = attacker.split('->') 
                if att not in nodes:
                    nodes[att] = set()
                if vic not in nodes:
                    nodes[vic] = set()
                if (att, vic) not in edges:
                    edges[(att, vic)] = []
                
                for i, episode in enumerate(episodes):  
                    self.chainResultStat.result_dict["stageCount"] += 1 
                    match_flag, extra_flag = False, False
                    start_time, end_time, mcat, serv, protos, signs, cates, alert_ids, timestamps, episodeType, match_behaviour_id = episode
                    start_time = round((start_time-self.startTimes[self.chain_label]).total_seconds() / 1.0)
                    end_time = round((end_time-self.startTimes[self.chain_label]).total_seconds() / 1.0)
                    if episodeType == NETWORK_EPISODE:
                        cat = micro[mcat].split('.')[1]
                        vert_name = cat + '|' + serv + '|' + str(count)
                        if match_behaviour_id: 
                            vert_name += '| match{}'.format(match_behaviour_id)
                            if not match_flag:
                                match_flag = True
                        else:
                            if vert_name not in nodes:
                                nodes[vert_name] = set()
                        if "host:" in serv and not extra_flag:
                            extra_flag = True
                        
                    elif episodeType == HOST_BEHAVIOUR:
                        extra_flag = True if not extra_flag else False
                        info_path, raw_sequence = copy.deepcopy(signs), copy.deepcopy(cates)
                        raw_sequence = raw_sequence.replace('"', '').replace("'",'')
                        info_path = info_path.replace('"', '').replace("'",'')
                        vic_info_path = [path for path in info_path.split(";") if ipJudge(vic, path)]
                        raw_cmd_path = [cmd for cmd in raw_sequence.split(";") if ipJudge(vic, cmd)]
                        if len(vic_info_path) > 0:
                            vert_name = macro[int(mcat)].split('.')[1] + '|' + vic_info_path[0][:50] + '|' + str(count)
                        else:
                            vert_name = macro[int(mcat)].split('.')[1] + '|' + raw_cmd_path[0][:50] + '|' + str(count)
                        signs = set(raw_sequence.split(";"))
                    if vert_name not in nodes:
                        nodes[vert_name] = set()
                        self.chainResultStat.result_dict["matchCount"] += 1 if match_flag else 0 
                        self.chainResultStat.result_dict["extraCount"] += 1 if extra_flag else 0 
                        self.chainResultStat.result_dict["addInfoStageCount"] += 1 if match_flag or extra_flag else 0 # 
                    nodes[vert_name].update(signs) 
                    edges[(att, vic)].append((start_time, end_time, vert_name, signs, timestamps)) 
                edges[(att, vic)] = sorted(edges[(att, vic)], key=lambda x:x[0]) 
            count += 1
        

        edge_hop_dict = defaultdict(int)
        colorList = ["red","maroon","blue","green","black"]
        for attacker, episodes in edges.items():
            att, vic = attacker
            episodes_length = len(episodes)
            hop_num = episodes[0][2].split('|')[-1]
            edge_hop_dict[hop_num] += 1
            edgecolor = colorList[edge_hop_dict[hop_num] % len(colorList)]
            for index in range(episodes_length):
                start_time, end_time, vert_name, signs, timestamps = episodes[index]
                if index == 0:  
                    _to_first = timestamps[0].strftime("%H:%M:%S") 
                    _to_end = timestamps[-1].strftime("%H:%M:%S") 
                    graph.append((0, '"' + att + '"' + ' -> ' + '"' + self.translate(vert_name) + '" [ color=' + edgecolor + '] ' + '[label=<<font color="' + edgecolor + '">  end:  ' + _to_end + '<br/> start: ' + _to_first + '</font>>]'))
                else:
                    pre_start_time, pre_end_time, pre_vert_name, pre_signs, pre_timestamps = episodes[index-1]
                    _to_first = timestamps[0].strftime("%H:%M:%S")
                    _to_end = timestamps[-1].strftime("%H:%M:%S")
                    graph.append((pre_start_time, '"' + self.translate(pre_vert_name) + '"' + ' -> ' + '"' + self.translate(vert_name) + '" [ color=' + edgecolor + '] ' + '[label=<<font color="' + edgecolor + '">  end:  ' + _to_end + '<br/> start: ' + _to_first + '</font>>]'))
            graph.append((start_time, '"' + self.translate(vert_name) + '"' + ' -> ' + '"' + vic + '" [ color=' + edgecolor + '] '))


        for index, (vname, signatures) in enumerate(nodes.items()):
            if '|' in vname:
                highSevColor = 'salmon'
                middleSevColor = 'wheat'
                mas = vname.split('|')[0]
                cat = micro_inv['MicroAttackStage.'+mas] if 'MicroAttackStage.' + mas in micro_inv else host_stage_severity[mas]
                shape = 'box'
                if len(str(cat)) >= 3 and cat != 999:
                    graph.append((0, '"' + self.translate(vname) + '" [shape='+shape+',style=filled,fillcolor='+highSevColor+']'))
                elif len(str(cat)) >= 2:
                    graph.append((0, '"' + self.translate(
                        vname) + '" [shape=' + shape + ',style=filled,fillcolor=' + middleSevColor + ']'))
                else:
                    graph.append((0, '"' + self.translate(vname) + '" [shape=' + shape + ']'))
                graph.append((1, '"' + self.translate(vname)+'"'+' [tooltip="' + "\n".join(signatures) + '"]'))
            else:
                shape = 'oval'
                nodecolor = 'yellow'
                graph.append((0, '"' + vname + '" [shape='+shape+',style=filled,fillcolor='+nodecolor+']'))
        graph.append((1000, '}'))

        output_dir = os.path.join(os.getcwd(), self.AG_OUTPUT_DIR)
        if not os.path.exists(output_dir):
            os.mkdir(output_dir)
        out_f_name = os.path.join(output_dir, AGname)
        out_file = out_f_name + ".dot"
        with open(out_file, 'w') as f:
            for line in graph:
                f.write(line[1])
                f.write('\n')
            f.close()
        os.system("dot -Tpng " + out_f_name + ".dot -o " + out_f_name + ".png")
        os.system("dot -Tsvg " + out_f_name + ".dot -o " + out_f_name + ".svg")
        


    def most_frequent(self, freq_dict):
        return max(freq_dict, key=freq_dict.get)


    def make_condensed_data(self, hop_episodes):
        condensed_data = dict()
        counter = -1
        for att_vic, episodes in hop_episodes.items():
            counter += 1
            times = []
            for i, episode in enumerate(episodes):
                episode_id, start_time, end_time, mcat, reserved_1, reserved_2, timeRange, serv, protos, signs, cates, alert_ids, timestamps, episodeType, match_behaviour_id = episode
                if episodeType == NETWORK_EPISODE:
                    max_servs = self.most_frequent(serv)
                    times.append((start_time, end_time, mcat, max_servs, list(protos.keys()), list(signs.keys()), list(cates.keys()), alert_ids, timestamps, episodeType, match_behaviour_id))
                elif episodeType == HOST_BEHAVIOUR:
                    times.append((start_time, end_time, mcat, serv, protos, signs, cates, alert_ids, timestamps, episodeType, match_behaviour_id))
            real_attacker = '->'.join(list(att_vic))
            if real_attacker not in condensed_data:
                condensed_data[real_attacker] = []
            condensed_data[real_attacker].extend(times)
            condensed_data[real_attacker].sort(key=lambda tup: (tup[1], tup[2], tup[3]))
        return condensed_data
        


    def generate_AG(self):
        condensed_data = []
        for hop_index, hop in enumerate(self.completeChain):
            if hop_index == 0:
                self.startTimes[self.chain_label] = min([episodes[0][1] for att_vic, episodes in hop.items()])
            hop_condensed_data = self.make_condensed_data(hop)
            condensed_data.append(hop_condensed_data)
        self.make_AG(condensed_data)

    