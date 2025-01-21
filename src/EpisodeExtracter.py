from AttackStage import *
from Config import *
import pandas as pd
import re
from datetime import datetime
from itertools import accumulate
from numpy import diff
import collections

class EpisodeExtracter(object):
    def __init__(self, att_vic_dict) -> None:
        self.att_vic_dict = att_vic_dict
        self.port_services = self.load_IANA_mapping()
        self.extra_service_mapping = {
            10022: "sshd",
            22022: "sshd",
            4444: "msf"
        }
        self.startTimes = collections.defaultdict(datetime)
        self.episode_window = EPISODE_WINDOW_LENGTH
        self.episode_id = 0

    def load_IANA_mapping(self):
        table = pd.read_csv(IANA_CSV_FILE_PATH)
        table = table.values
        ports = {}
        for row in table:
            row = ['' if pd.isna(item) else item for item in row]
            # Drop missing port number, Unassigned and Reserved ports
            if row[1] and 'Unassigned' not in row[3]:
                # Split range in single ports
                if '-' in row[1]: # port range
                    low_port, high_port = map(int, row[1].split('-'))
                else: 
                    low_port = high_port = int(row[1])

                for port in range(low_port, high_port + 1):
                    ports[port] = {
                        "name": row[0] if row[0] else "Unknown",  # port -> service name
                        "description": row[3] if row[3] else "---",  # port -> description
                    }
            else:
                # Do nothing
                pass
        return ports

    def port2service(self, sport, dport, proto):
        if proto in ["dovecot", "mongo", "sshd"]: # inter-host connections from host logs
            return "host:" + proto
        if dport in self.port_services.keys():
            service = self.port_services[dport]['name']
        elif dport in self.extra_service_mapping:
            service = self.extra_service_mapping[dport]
        elif sport in self.port_services.keys():
            service = self.port_services[sport]['name']
        elif sport in self.extra_service_mapping:
            service = self.extra_service_mapping[sport]
        else:
            service = "unknown({})".format(dport)
        return service

    def isValidPort(self, port):
        pattern = r'^\d{1,5}$'
        if re.match(pattern, str(port)) is not None and int(port) < 65536:
            return True
        else:
            return False

    # signature -> attack stage 
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

    # reference to SAGE
    def getepisodes(self, action_seq, mcat): 
        dx = 0.1
        y = [len(x) for x in action_seq]
        if sum(y) == 0:
            return []
        if len(y) == 1:
            y = [y[0], 0]
        cap = max(y) + 1
        dy = diff(y) / dx
        dim = len(dy)

        positive = [(0, dy[0])]
        positive.extend(
            [(ind, dy[ind]) for ind in range(1, dim) if (dy[ind - 1] <= 0 and dy[ind] > 0)])  # or ind-1 == 0]
        negative = [(ind + 1, dy[ind + 1]) for ind in range(0, dim - 1) if (dy[ind] < 0 and dy[ind + 1] >= 0)]
        if dy[-1] < 0:  # special case for last ramp down thats not fully gone down
            negative.append((len(dy), dy[-1]))
        elif dy[-1] > 0:  # special case for last ramp up without any ramp down
            # print('adding somthing at the end ', (len(dy), dy[-1]))
            negative.append((len(dy), dy[-1]))

        common = list(set(negative).intersection(positive))
        negative = [item for item in negative if item not in common]
        positive = [item for item in positive if item not in common]

        negative = [x for x in negative if (y[x[0]] <= 0 or x[0] == len(y) - 1)]  # the position of gradient descent
        positive = [x for x in positive if (y[x[0]] <= 0 or x[0] == 0)]  # the position of gradient ascent 

        if len(negative) < 1 or len(positive) < 1:
            return [(0, len(y))]
        

        episodes_ = []  # Tuple (startInd, endInd)
        for i in range(len(positive) - 1):
            ep1 = positive[i][0]
            ep2 = positive[i + 1][0]
            ends = []
            for j in range(len(negative)):
                if ep1 <= negative[j][0] < ep2: 
                    ends.append(negative[j])

            if len(ends) > 0:  
                episode = (ep1, max([x[0] for x in ends]))
                episodes_.append(episode)
        if len(positive) == 1 and len(negative) == 1: 
            episode = (positive[0][0], negative[0][0])
            episodes_.append(episode)

        if len(episodes_) > 0 and negative[-1][0] != episodes_[-1][1]:
            episode = (positive[-1][0], negative[-1][0])
            episodes_.append(episode)

        if len(episodes_) > 0 and positive[-1][0] != episodes_[-1][0]:
            elim = [x[0] for x in
                    common]
            if len(elim) > 0 and max(elim) > positive[-1][0]:
                episode = (positive[-1][0], max(elim))
                episodes_.append(episode)

        if len(episodes_) == 0 and len(positive) == 2 and len(negative) == 1:
            episode = (positive[1][0], negative[0][0])
            episodes_.append(episode)
        return episodes_



    def aggregate_into_episodes(self, att_vic, alertData):
        att, vic = att_vic
        mappingAlertData = []
        for alert in alertData:
            category, severity, host, proto, sport, dport, signature, alert_id, timestamp, label = alert
            mcat = self.get_attack_stage_mapping(signature)
            if mcat == 999: # disregard NON_MALICIOUS
                continue
            sport = int(sport) if self.isValidPort(sport) else 65000  # source port
            dport = int(dport) if self.isValidPort(dport) else 65000  # dest port
            port = self.port2service(sport, dport, proto)
            timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            mappingAlertData.append((mcat, timestamp, port, proto, signature, category, alert_id)) # structured representation of inter-host connections
        if len(mappingAlertData) == 0:
            return False
        
        mcats = list(micro.keys()) 

        ts = [x[1] for x in mappingAlertData]  # timestamps
        self.startTimes[att_vic] = ts[0]
        rest = [x for x in mappingAlertData]
        first_elapsed_time = 0.0 
        prev = -1
        DIFF = []
        for timeid, dt in enumerate(ts):
            if timeid == 0:
                DIFF.append(0.0)
            else:
                DIFF.append(round((dt - prev).total_seconds(), 2))
            prev = dt
        assert(len(ts) == len(DIFF))
        elapsed_time = list(accumulate(DIFF))
        relative_elapsed_time = [round(x + first_elapsed_time, 2) for x in elapsed_time]
        assert(len(elapsed_time) == len(DIFF))
        t0 = int(first_elapsed_time)
        tn = int(relative_elapsed_time[-1])

        h_ep = []
        for mcat in mcats:
            if sum([True if alert[0] == mcat else False for alert in rest]) == 0:
                continue
            mindata = []
            if t0 == tn: # only one connection
                mindata = [rest]
            else:
                for i in range(t0, tn, self.episode_window):
                    li = [a for d, a in zip(relative_elapsed_time, rest) if
                            (d >= i and d < (i + self.episode_window)) and a[0] == mcat]  # aggregate based on (attacker, victim, stage) triplet
                    mindata.append(li)
            episodes = self.getepisodes(mindata, micro[mcat])  # inter-host abnormal episodes aggregation
            if len(episodes) > 0:
                events = [len(x) for x in mindata]
                raw_ports = []
                raw_proto = []
                raw_sign = []
                raw_category = []
                raw_alert_id = []
                timestamps = []
                for e in mindata:
                    if len(e) > 0:
                        timestamps.append([(x[1]) for x in e])
                        raw_ports.append([(x[2]) for x in e])
                        raw_proto.append([(x[3]) for x in e])
                        raw_sign.append([(x[4]) for x in e])
                        raw_category.append([(x[5]) for x in e])
                        raw_alert_id.append([(x[6]) for x in e])
                    else:
                        timestamps.append([])
                        raw_ports.append([])
                        raw_proto.append([])
                        raw_sign.append([])
                        raw_category.append([])
                        raw_alert_id.append([])
                _flat_ports = [item for sublist in raw_ports for item in sublist]
                # The following makes exact start/end times based on alert timestamps
                filtered_timestamps = [timestamps[x[0]:x[1] + 1] for x in episodes]
                start_end_timestamps = [(sorted([item for sublist in x for item in sublist])[0],
                                        sorted([item for sublist in x for item in sublist])[-1]) for x in
                                        filtered_timestamps]
                minute_info = [
                            (x[0], x[1]) for x
                            in start_end_timestamps]  
                episode = [(mi[0], mi[1], mcat, events[x[0]:x[1] + 1],
                                    raw_ports[x[0]:x[1] + 1], raw_proto[x[0]:x[1] + 1], raw_sign[x[0]:x[1] + 1], raw_category[x[0]:x[1] + 1], raw_alert_id[x[0]:x[1] + 1], filtered_timestamps) for x, mi in zip(episodes, minute_info)]
                # EPISODE DEF: (startTime, endTime, mcat, len(rawevents), volume(alerts), epiPeriod, epiServices, list of unique signatures, (1st timestamp, last timestamp)
                episode = [(self.episode_id+index+1, x[0], x[1], x[2], x[3], round(sum(x[3]) / float(len(x[3])), 1), (x[1] - x[0]),
                            self.episodeFeatureStat([item for sublist in x[4] for item in sublist]), # serv
                            self.episodeFeatureStat([item for sublist in x[5] for item in sublist]), # proto
                            self.episodeFeatureStat([item for sublist in x[6] for item in sublist]), # sign
                            self.episodeFeatureStat([item for sublist in x[7] for item in sublist]), # cate
                            [item for sublist in x[8] for item in sublist],
                            se_ts,
                            NETWORK_EPISODE, '') for index, (x, se_ts) in enumerate(zip(episode, start_end_timestamps))]
                h_ep.extend(episode)
                self.episode_id += len(episode)
        if len(h_ep) == 0:
            print("warning, please check, the length of variable `h_ep` is zero")
            return False
        h_ep.sort(key=lambda tup: (tup[0], tup[1], tup[2]))
        return h_ep

    def episodeFeatureStat(self, featureList):
        stat_dict = collections.defaultdict(int)
        for feature in featureList:
            stat_dict[feature] += 1
        return stat_dict
        
    def extractEpisodes(self):
        episodes_dict = collections.defaultdict(list)
        feature_list = []
        episode_count = 0
        for att_vic, alertData in self.att_vic_dict.items():
            alertData = self.aggregate_into_episodes(att_vic, alertData)
            if alertData is False:
                continue
            episode_count += len(alertData)
            episodes_dict[att_vic] = alertData
        return episodes_dict, episode_count