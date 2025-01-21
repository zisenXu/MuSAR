from Config import *
import collections
import re
from AttackStage import *
from copy import deepcopy
from ChainUtils import *

class ChainEvaluator(object):
    def __init__(self, completeChain, att_vic_dict, host_data, host_behaviour_dict, alarm_label_dict, host_label_dict):
        self.completeChain = completeChain  # Result of multi-step attacks
        self.att_vic_dict = att_vic_dict  # inter-host connections
        self.host_data = host_data  # intra-host operations
        self.host_behaviour_dict = host_behaviour_dict  # intra-host sensitive behaviors
        self.alarm_label_dict = alarm_label_dict  # connection ID to label mapping
        self.host_label_dict = host_label_dict  # operation ID to label mapping
        self.label_to_cover_signatures = collections.defaultdict(set)  # reconstruction status of S-IoCs
        self.label_to_cover_operations = collections.defaultdict(set)  # reconstruction status of C-IoCs
        self.label_to_signatures = collections.defaultdict(set)  # Ground truth of S-IoCs
        self.label_to_operations = collections.defaultdict(set)  # Ground truth of C-IoCs
        self.alertID_to_signature = collections.defaultdict(str)  # Connection ID to signature mapping
        self.cmdID_to_operation = collections.defaultdict(str)  # Operation ID to operation mapping

    # mapping between behaviour ID and operations ID list it contains
    def get_behaviour_host_ids(self):
        behaviour_hostID_list = collections.defaultdict(list)
        for host, behaviour_list in self.host_behaviour_dict.items():
            for behaviour in behaviour_list:
                behaviour_id, host, start_time, end_time, info_path, attack_stage, raw_sequence, cmd_id_list, target = behaviour 
                behaviour_hostID_list[behaviour_id] = cmd_id_list 
                for cmd_id in cmd_id_list:
                    if cmd_id not in self.cmdID_to_operation or cmd_id not in self.hostID_label_mapping:
                        continue
                    operation = self.cmdID_to_operation[cmd_id]
                    label = self.hostID_label_mapping[cmd_id]
                    self.label_to_cover_operations[label].add(operation)
        self.behaviour_hostID_list = behaviour_hostID_list

    def get_attack_stage_mapping(self, signature):
        result = MicroAttackStage.NON_MALICIOUS
        if signature in usual_mapping.keys():
            result = usual_mapping[signature]
        elif signature in unknown_mapping.keys():
            result = unknown_mapping[signature]
        elif signature in ccdc_combined.keys():
            result = ccdc_combined[signature]
        elif signature in xt_combined.keys():
            result = xt_combined[signature]
        elif signature in msas_combined.keys():
            result = msas_combined[signature]
        elif signature in host_log_combined.keys():
            result = host_log_combined[signature]
        else:
            for k, v in attack_stage_mapping.items():
                if signature in v:
                    result = k
                    break
        return micro_inv[str(result)]
    
    def reOrganize_sign_mcat(self):
        for att_vic, alertData in self.att_vic_dict.items():
            for alert in alertData:
                category, severity, _, proto, sport, dport, signature, alert_id, timestamp, label = alert
                mcat = self.get_attack_stage_mapping(signature)
                if mcat == 999:
                    continue
                self.label_to_signatures[label].add(signature)
                self.alertID_to_signature[alert_id] = signature
        
        for cmd in self.host_data:
            command_id, user, _raw, authority, command_keyword, parsed_args, input, output, target, command_type, timestamp, host_ip, is_sensitive, label = cmd
            self.label_to_operations[label].add(_raw)
            self.cmdID_to_operation[command_id] = _raw
    def get_ID_label_mapping(self):
        alarmID_label_mapping = collections.defaultdict(int)
        for label, alarmIDs in self.alarm_label_dict.items():
            for alarmID in alarmIDs:
                alarmID_label_mapping[alarmID] = label
        self.alarmID_label_mapping = alarmID_label_mapping
        hostID_label_mapping = collections.defaultdict(int)
        for label, hostIDs in self.host_label_dict.items():
            for hostID in hostIDs:
                hostID_label_mapping[hostID] = label
        self.hostID_label_mapping = hostID_label_mapping

    def episodeAnalyze(self, hop_episodes):
        for att_vic, episodes in hop_episodes.items():
            for i, episode in enumerate(episodes):
                episode_id, start_time, end_time, mcat, reserved_1, reserved_2, timeRange, serv, protos, signs, cates, alert_ids, timestamps, episodeType, match_behaviour_id = episode
                if episodeType == NETWORK_EPISODE:
                    for alert_id in alert_ids:
                        sign = self.alertID_to_signature[alert_id]
                        label = self.alarmID_label_mapping[alert_id]
                        self.label_to_cover_signatures[label].add(sign)
                    if match_behaviour_id:
                        behaviour_id = int(re.findall(r"#(\d+)", match_behaviour_id)[0])
                        cmd_id_list = self.behaviour_hostID_list[behaviour_id]
                        for cmd_id in cmd_id_list:
                            operation = self.cmdID_to_operation[cmd_id]
                            label = self.hostID_label_mapping[cmd_id]
                            self.label_to_cover_operations[label].add(operation)
                elif episodeType == HOST_BEHAVIOUR:
                    for cmd_id in alert_ids:
                        operation = self.cmdID_to_operation[cmd_id]
                        label = self.hostID_label_mapping[cmd_id]
    def evaluate(self):
        self.reOrganize_sign_mcat()
        self.get_ID_label_mapping()
        self.get_behaviour_host_ids()
        for chain_index, completeChain in enumerate(self.completeChain):
            for hop_index, hop in enumerate(completeChain):
                self.episodeAnalyze(hop)