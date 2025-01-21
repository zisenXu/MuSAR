import networkx as nx
import collections
import copy
from AttackStage import *
import re
import ipaddress
from Config import *
from ChainUtils import * 

class ChainSearcher(object):
    def __init__(self, episodes, behaviour_dict, start_time, end_time) -> None:
        self.episodes = episodes
        self.behaviour_dict = copy.deepcopy(behaviour_dict)
        self.start_time = start_time
        self.end_time = end_time
        self.chain = []
        self.edgeID_dict = {}
        self.idEdge_dict = {}
        self.numChain_dict = collections.defaultdict(int)
        self.edgeID = 1
        self.validChain = []
        self.attackChainEdgeList = []
        self.chainResult = {}
        self.episode_id = max([episode[0] for value in self.episodes.values() for episode in value])
        self.bash_signature_dict = {
            'ping': 'GPL ICMP_INFO PING',
            'ssh': 'ssh',
            'nmap': 'nmap',
            'curl': 'curl',
            'openvas': 'openvas',
            'msfconsole': 'Metasploit',
            'mongo': 'mongo',
            'dovecot': 'dovecot',
            'msf': 'msf'
        }
        

    def calcShortestPath(self):
        diGraph = nx.DiGraph()
        # add directed edges from inter-host abnormal episodes
        for att_vic in self.episodes.keys():
            att, vic = att_vic
            self.idEdge_dict[self.edgeID] = (att, vic)
            self.numChain_dict[self.edgeID] = 0
            self.edgeID_dict[(att, vic)] = self.edgeID
            diGraph.add_edge(att, vic, edgeType=NETWORK_EPISODE)
            self.edgeID += 1

        # add directed edges from intra-host sensitive behaviors
        remove_dict = collections.defaultdict(list)
        for att, behaviour_list in self.behaviour_dict.items():
            for behaviour in behaviour_list:
                behaviour_id, host, start_time, end_time, info_path, attack_stage, raw_sequence, cmd_id_list, target = behaviour
                if len(target) != 1: # no target entities
                    continue
                ipv4_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
                ipv4_addresses = re.findall(ipv4_pattern, target[0])
                if len(ipv4_addresses) == 0:
                    continue
                vic = ipv4_addresses[0]
                try:
                    ipaddress.IPv4Address(vic)
                except ipaddress.AddressValueError:
                    continue
                if vic not in whiteList:
                    continue
                if not diGraph.has_edge(att, vic):
                    self.idEdge_dict[self.edgeID] = (att, vic)
                    self.numChain_dict[self.edgeID] = 0
                    self.edgeID_dict[(att, vic)] = self.edgeID
                    diGraph.add_edge(att, vic, edgeType=HOST_BEHAVIOUR)
                    self.edgeID += 1
                    episode = [self.episode_id+1, start_time, end_time, int(attack_stage), RESERVED, RESERVED, end_time-start_time,
                                RESERVED,
                                RESERVED,
                                info_path,
                                raw_sequence,
                                cmd_id_list,
                                (start_time, end_time),
                                HOST_BEHAVIOUR, ''] # unified representation
                    self.episode_id += 1
                    self.episodes[(att, vic)] = [tuple(episode)]
                    remove_dict[att].append(behaviour)
        for att, remove_behavior_list in remove_dict.items():
            for remove_behavior in remove_behavior_list:
                self.behaviour_dict[att].remove(remove_behavior)

        
        shortestPath = nx.algorithms.shortest_paths.generic.shortest_path(diGraph)
        return diGraph, shortestPath

    def dfs(self, node, visited, shortestPath, current_path):
        visited[node] = True
        if len(current_path) >= 3:
            self.validChain.append(tuple(current_path))
        for target_node, path in shortestPath[node].items():
            if target_node == node:
                continue
            isLoop = [True if n in visited else False for n in path[1:]]
            if True in isLoop:
                new_path = tuple(current_path + path[1:])
                if len(new_path) >= 3:
                    self.validChain.append(new_path)
                continue
            for n in range(1, len(path)-1):
                visited[n] = True
            current_path.extend(path[1:])
            self.dfs(target_node, visited, shortestPath, current_path)
            for i in range(1, len(path)):
                current_path.pop()
            for n in range(1, len(path)-1):
                visited[n] = False
        visited.pop(node)
        return
    def chainLenFilter(self, diGraph, shortestPath):
        attackChainEdgeList = []
        skip_node = collections.defaultdict(int)
        for source_node, all_paths in shortestPath.items():
            self.validChain = []
            if diGraph.in_degree(source_node) != 0:  # begin at nodes with non-zero in-degree
                is_has_path = sum([nx.has_path(diGraph,source_node,pre) for pre in list(diGraph.predecessors(source_node))])
                if not is_has_path:
                    continue
            path2node = dict()
            pathList = []
            for target_node, path in all_paths.items():
                if source_node != target_node:
                    path2node[tuple(path)] = target_node
                    pathList.append(tuple(path))
            self.removeSubChain(pathList)  # redundant subset elimination
            for path in pathList:
                visited = collections.defaultdict(bool) # record visited nodes
                for i in range(len(path) - 1):
                    visited[path[i]] = True
                target_node = path2node[path]
                current_path = list(path)
                self.dfs(target_node, visited, shortestPath, current_path)
            if len(self.validChain) == 0:
                continue
            self.removeSubChain(self.validChain)
            for path in self.validChain:
                chain = []
                for i in range(len(path) - 1):
                    edgeKey = (path[i], path[i + 1])
                    edgeID = self.edgeID_dict[edgeKey]
                    chain.append(edgeID)
                    self.numChain_dict[edgeID] += 1
                attackChainEdgeList.append(chain)
        attackChainEdgeList = sorted(attackChainEdgeList, key=lambda x: len(x)) 
        self.removeSubChain(attackChainEdgeList)
        self.attackChainEdgeList = sorted(attackChainEdgeList, key=lambda x: len(x))

    # redundant subset elimination
    def removeSubChain(self, pathList):
        pathLength = len(pathList)
        pathDeleteList = []
        chainLenDict = {}
        chainNumDict = collections.defaultdict(int)

        for i in range(pathLength):
            if len(pathList[i]) not in chainLenDict:
                chainLenDict[len(pathList[i])] = i
            if tuple(pathList[i]) in chainNumDict:
                pathDeleteList.append(pathList[i])
            else:
                chainNumDict[tuple(pathList[i])] = 1
        
        for i in range(pathLength):
            arr_i = pathList[i]
            if len(arr_i) + 1 not in chainLenDict:
                break
            startIndex = chainLenDict[len(arr_i) + 1]
            for j in range(startIndex, pathLength):
                arr_j = pathList[j]
                if frozenset(arr_i).issubset(frozenset(arr_j)):
                    pathDeleteList.append(arr_i)
                    break
        for path in pathDeleteList:
            if path in pathList:
                for hop in path:
                    if hop in self.numChain_dict:
                        self.numChain_dict[hop] -= 1
                pathList.remove(path)

    #  validate one-hop attack
    def OneHopChainJudge(self, episodes):
        if HOST_BEHAVIOUR in [episode[-2] for episode in episodes]: # containing episodes from host behaviour
            return True
        valid_stage = [episode[3] for episode in episodes if episode[3] != 999]
        stage_num = len(valid_stage)
        stage_type = len(set(valid_stage))
        if stage_type >= 4 and not all([stage < 10 for stage in valid_stage]) :  # containing at least 4 stages and not all stages are reconnaissance
            return True
        return False
        
    # extracting one-hop attack from isolated associations
    def multiStageChainExtract(self): 
        edgeID_not_in_chain = [k for k, v in self.numChain_dict.items() if v == 0]
        for edgeID in edgeID_not_in_chain:
            edge = self.idEdge_dict[edgeID]
            episodes = self.episodes[edge]
            if self.OneHopChainJudge(episodes):
                self.attackChainEdgeList.append([edgeID])
                self.numChain_dict[edgeID] += 1
                continue

    def organizeChain(self):
        for chain in self.attackChainEdgeList:
            chainKey = tuple(chain)
            self.chainResult[chainKey] = []
            for hop in chain:
                att_vic = self.idEdge_dict[hop]
                self.chainResult[chainKey].append(self.episodes[att_vic])
    
    # temporal causality verification
    def chainTimeFilter(self):
        temp_attackChainEdgeList = []
        temp_chainResult = {}
        for chain in self.attackChainEdgeList:
            chainKey = tuple(chain)
            if len(chain) == 1: # one-hop attack, skip
                temp_attackChainEdgeList.append(chain)
                temp_chainResult[chainKey] = self.chainResult[chainKey]
                continue

            chainEpisodes = self.chainResult[chainKey]
            hop_length = len(chain)
            filteredChain = []
            filteredChainResult = []
            for i in range(hop_length - 1):
                hop_i_earliest = chainEpisodes[i][0][1] # episode[1]:start_time
                hop_j_latest = chainEpisodes[i+1][-1][2] # episode[2]:end_time
                if hop_j_latest >= hop_i_earliest: # valid
                    chainEpisodes[i] = list(filter(lambda x: x[1] <= hop_j_latest, chainEpisodes[i]))
                    chainEpisodes[i+1] = list(filter(lambda x: x[2] >= hop_i_earliest, chainEpisodes[i+1]))
                    filteredChain.append(chain[i])
                    filteredChainResult.append(chainEpisodes[i])
                else: # invalid
                    if len(filteredChain) == 0:
                        if self.numChain_dict[chain[i]] > 1:
                            self.numChain_dict[chain[i]] -= 1
                        else:
                            # validate one-hop attack 
                            if self.OneHopChainJudge(chainEpisodes[i]):
                                filteredChainResult.append(chainEpisodes[i])
                                filteredChain.append(chain[i])
                                filteredChainKey = tuple(filteredChain)
                                temp_attackChainEdgeList.append(filteredChain)
                                temp_chainResult[filteredChainKey] = filteredChainResult
                            else:
                                self.numChain_dict[chain[i]] -= 1
                    else: 
                        filteredChain.append(chain[i])
                        if filteredChain not in temp_attackChainEdgeList and self.connectedCheck(filteredChain):
                            filteredChainResult.append(chainEpisodes[i])
                            filteredChainKey = tuple(filteredChain)
                            temp_attackChainEdgeList.append(filteredChain)
                            temp_chainResult[filteredChainKey] = filteredChainResult
                    filteredChain = []
                    filteredChainResult = []
            if len(filteredChain) == 0:
                if self.numChain_dict[chain[-1]] > 1:
                    self.numChain_dict[chain[-1]] -= 1
                else:
                    if self.OneHopChainJudge(chainEpisodes[-1]):
                        filteredChainResult.append(chainEpisodes[-1])
                        filteredChain.append(chain[-1])
                        filteredChainKey = tuple(filteredChain)
                        temp_attackChainEdgeList.append(filteredChain)
                        temp_chainResult[filteredChainKey] = filteredChainResult
                    else:
                        self.numChain_dict[chain[-1]] -= 1
            else:
                filteredChain.append(chain[-1])
                if filteredChain not in temp_attackChainEdgeList and self.connectedCheck(filteredChain):
                    filteredChainResult.append(chainEpisodes[-1])
                    filteredChainKey = tuple(filteredChain)
                    temp_attackChainEdgeList.append(filteredChain)
                    temp_chainResult[filteredChainKey] = filteredChainResult
        self.attackChainEdgeList = temp_attackChainEdgeList
        self.chainResult = temp_chainResult

    # attack stage semantics verification
    def chainValidityFilter(self):
        temp_attackChainEdgeList = []
        temp_chainResult = {}
        valid_chain_num = 0
        invalid_chain_num = 0
        new_chain_num = 0
        for chain in self.attackChainEdgeList:
            chainKey = tuple(chain)
            chainEpisodes = self.chainResult[chainKey]
            chainLength = len(chain)
            is_hop_valid_list = []
            for i in range(chainLength):
                hop_episodes = chainEpisodes[i]
                is_hop_valid_list.append(not all([episode[3] < 10 and episode[-2] == NETWORK_EPISODE for episode in hop_episodes])) # episodes with all reconnaissance stage
            if False not in is_hop_valid_list[:-1]:  # valid
                temp_attackChainEdgeList.append(chain)
                temp_chainResult[chainKey] = chainEpisodes
                valid_chain_num += 1
                continue
            if True not in is_hop_valid_list[:-1]:  # invalid
                invalid_chain_num += 1
                for hop in chain:
                    if hop in self.numChain_dict:
                        self.numChain_dict[hop] -= 1
                lastHop = chain[-1]
                lastHopEpisodes = chainEpisodes[-1]
                if self.numChain_dict[lastHop] == 0 and self.OneHopChainJudge(chainEpisodes[-1]): # validate whether the invalid hop is a one-hop attack
                    self.numChain_dict[lastHop] += 1
                    valid_chain_num += 1
                    temp_attackChainEdgeList.append(chain[-1:])
                    temp_chainResult[tuple(chain[-1:])] = chainEpisodes[-1:]
                continue
            # Not all of the first N-1 hops exclusively contain attacks from the reconnaissance phase;
            else:
                temp_chain_edge_list = []
                temp_chain_result = {}
                start_index = -1
                for index, is_valid in enumerate(is_hop_valid_list):
                    if is_valid and start_index != -1:
                        continue
                    if is_valid and start_index == -1:
                        start_index = index
                    if not is_valid and start_index == -1:
                        self.numChain_dict[chain[index]] -= 1
                        if self.numChain_dict[chain[index]] == 0 and self.OneHopChainJudge(chainEpisodes[index]):
                            self.numChain_dict[chain[index]] += 1
                            temp_chain_edge_list.append([chain[index]])
                            temp_chain_result[tuple([chain[index]])] = chainEpisodes[index]
                        continue
                    if not is_valid and start_index != -1:
                        valid_chain = chain[start_index:index+1]
                        if len(valid_chain) >= 2:
                            temp_chain_edge_list.append(valid_chain)
                            temp_chain_result[tuple(valid_chain)] = chainEpisodes[start_index:index+1]
                        start_index = -1
                if start_index != -1:
                    valid_chain = chain[start_index:]
                    if len(valid_chain) >= 2:
                        temp_chain_edge_list.append(valid_chain)
                        temp_chain_result[tuple(valid_chain)] = chainEpisodes[start_index:]
                invalid_chain_num += 1
                new_chain_num += len(temp_chain_edge_list)
                temp_attackChainEdgeList.extend(temp_chain_edge_list)
                temp_chainResult.update(temp_chain_result)
        temp_attackChainEdgeList = sorted(temp_attackChainEdgeList, key=lambda x: len(x))
        self.removeSubChain(temp_attackChainEdgeList)
        self.attackChainEdgeList = temp_attackChainEdgeList
        self.chainResult = temp_chainResult

    def getContinuousChainKey(self, chain):
        return tuple(chain[0])

    def mergeContinuousChain(self, suffixMergeChain, suffixMergeEpisodes):
        mergedChain = []
        mergedEpisodes = []
        continuousChain = []
        continuousEpisodes = {}
        for index, chain in enumerate(suffixMergeChain):
            if len(chain) == 1:
                continuousChain.append(chain)
                continuousEpisodes[self.getContinuousChainKey(chain)] = suffixMergeEpisodes[index]
            else:
                mergedChain.append(chain)
                mergedEpisodes.append(suffixMergeEpisodes[index])
        if len(continuousChain) < 2:
            return suffixMergeChain, suffixMergeEpisodes
        sipSameChain = {}
        isMerged = collections.defaultdict(bool)
        for chain in continuousChain:
            chainKey = self.getContinuousChainKey(chain)
            isMerged[chainKey] = False
            hopID = chainKey[0]
            att, vic = self.idEdge_dict[hopID]
            if att not in sipSameChain:
                sipSameChain[att] = []
            sipSameChain[att].append(chain)
        sipSameChain = dict(sorted(sipSameChain.items(), key=lambda item: len(item[1]), reverse=True))
        for sip, chains in sipSameChain.items():
            if len(chains) > 1 and sum([1 for chain in chains if isMerged[self.getContinuousChainKey(chain)] is False]) > 1: 
                chains = [chain for chain in chains if isMerged[self.getContinuousChainKey(chain)] is False]
                tempChain, tempEpisodes = set(), dict()
                for chain in chains:
                    isMerged[self.getContinuousChainKey(chain)] = True
                    tempChain = tempChain.union(chain[0])
                    tempEpisodes.update(continuousEpisodes[self.getContinuousChainKey(chain)][0])
                mergedChain.append([tempChain])
                mergedEpisodes.append([tempEpisodes])   
        for chain in continuousChain:
            if isMerged[self.getContinuousChainKey(chain)]:
                continue
            tempChain, tempEpisodes = set(), dict()
            tempChain = tempChain.union(chain[0])
            tempEpisodes.update(continuousEpisodes[self.getContinuousChainKey(chain)][0])
            mergedChain.append([tempChain])
            mergedEpisodes.append([tempEpisodes])
        return mergedChain, mergedEpisodes

    def connectedCheck(self, chain):
        graph = nx.Graph()
        for hop in chain:
            att, vic = self.idEdge_dict[hop]
            graph.add_edge(att, vic)
        isConnected = nx.is_connected(graph)
        return isConnected

    def getPrefix(self, chain, index):
        chain_length = len(chain)
        chainEpisodes = self.chainResult[tuple(chain)]
        prefix_key = []
        for i in range(index):
            hop = chain[i]
            episode_mcats = [episode[3] for episode in chainEpisodes[i]]
            prefix_key.append(tuple([hop, tuple(episode_mcats)]))
        return tuple(prefix_key)

    def prefixMerge(self):
        prefixSameChain = {}
        prefixMergeChain = [] 
        prefixMergeEpisodes = []
        isMerged = collections.defaultdict(bool)
        for chain in self.attackChainEdgeList:
            isMerged[tuple(chain)] = False
            chainLength = len(chain)
            if chainLength == 1:
                continue
            for i in range(chainLength - 1):
                prefix = self.getPrefix(chain, i+1)
                if prefix not in prefixSameChain:
                    prefixSameChain[prefix] = []
                prefixSameChain[prefix].append(chain)
        prefixSameChain = dict(sorted(prefixSameChain.items(), key=lambda item: len(item[0]), reverse=True))
        
        # Similar prefix merging
        for prefix, chains in prefixSameChain.items():
            if len(chains) > 1 and sum([1 for chain in chains if isMerged[tuple(chain)] is False]) > 1:
                chains = [chain for chain in chains if isMerged[tuple(chain)] is False]
                chainMaxLength = len(sorted(chains, key=lambda x: len(x), reverse=True)[0])
                mergeChain = [set() for i in range(chainMaxLength)]
                mergeEpisodes = [dict() for i in range(chainMaxLength)]
                prefixLength = len(prefix)
                prefix_merge_flag = False
                for index, chain in enumerate(chains):
                    isMerged[tuple(chain)] = True
                    if not prefix_merge_flag:
                        for i in range(prefixLength):
                            mergeChain[i].add(chain[i])
                            att_vic = self.idEdge_dict[chain[i]]
                            mergeEpisodes[i][att_vic] = self.chainResult[tuple(chain)][i]
                        prefix_merge_flag = True
                    for i in range(prefixLength, len(chain)):
                        mergeChain[i].add(chain[i])
                        att_vic = self.idEdge_dict[chain[i]]
                        if att_vic not in mergeEpisodes[i]:
                            mergeEpisodes[i][att_vic] = self.chainResult[tuple(chain)][i]
                        else:
                            for episode in self.chainResult[tuple(chain)][i]:
                                if episode not in mergeEpisodes[i][att_vic]:
                                    mergeEpisodes[i][att_vic].append(episode)
                            mergeEpisodes[i][att_vic] = sorted(mergeEpisodes[i][att_vic], key=lambda x: (x[1], x[2], x[3])) 
                prefixMergeChain.append(mergeChain)
                prefixMergeEpisodes.append(mergeEpisodes)
        # remaining multi-hop attacks that cannot be merged
        for chain in self.attackChainEdgeList:
            if isMerged[tuple(chain)]:
                continue
            mergeChain = [set() for i in range(len(chain))]
            mergeEpisodes = [dict() for i in range(len(chain))]
            for index, path in enumerate(chain):
                mergeChain[index].add(path)
                att_vic = self.idEdge_dict[path]
                mergeEpisodes[index][att_vic] = self.chainResult[tuple(chain)][index]
            prefixMergeChain.append(mergeChain)
            prefixMergeEpisodes.append(mergeEpisodes)
        return prefixMergeChain, prefixMergeEpisodes
         
    def getSuffix(self, chain, index):
        chain_length = len(chain)
        suffix_key = []
        for i in range(chain_length-index, chain_length):
            suffix_key.append(tuple(chain[i]))
        return tuple(suffix_key)

    def getChainKey(self, chain):
        return tuple([tuple(hop) for hop in chain])

    def mergeEpisodes(self, src, dst):
        for att_vic, episodes in src.items():
            if att_vic not in dst:
                dst[att_vic] = episodes
            else:
                for episode in episodes:
                    if episode not in dst[att_vic]:
                        dst[att_vic].append(episode)


    def suffixMerge(self, prefixMergeChain, prefixMergeEpisodes):
        suffixSameChain = {}
        suffixMergeChain = []
        suffixMergeEpisodes = []
        isMerged = collections.defaultdict(bool)
        chain2Index = collections.defaultdict(int)
        for index, chain in enumerate(prefixMergeChain):
            chainEpisodes = prefixMergeEpisodes[index]
            chain_key = self.getChainKey(chain)
            isMerged[chain_key] = False
            chain2Index[chain_key] = index
            chainLength = len(chain)
            if chainLength == 1:
                continue
            for i in range(chainLength - 1):
                suffix = self.getSuffix(chain, i + 1)
                if suffix not in suffixSameChain:
                    suffixSameChain[suffix] = []
                suffixSameChain[suffix].append(chain)
        suffixSameChain = dict(sorted(suffixSameChain.items(), key=lambda item: len(item[0]), reverse=True))
        
        # suffix prefix merging
        for suffix, chains in suffixSameChain.items():
            if len(chains) > 1 and sum([1 for chain in chains if isMerged[self.getChainKey(chain)] is False]) > 1:
                chains = [chain for chain in chains if isMerged[self.getChainKey(chain)] is False]
                chainMaxLength = len(sorted(chains, key=lambda x: len(x), reverse=True)[0])
                mergeChain = [set() for i in range(chainMaxLength)]
                mergeEpisodes = [dict() for i in range(chainMaxLength)]
                for index, chain in enumerate(chains):
                    chain_key = self.getChainKey(chain)
                    chainLength = len(chain)
                    isMerged[chain_key] = True
                    for i in range(chainLength):
                        mergeChain[chainMaxLength-1-i] = mergeChain[chainMaxLength-1-i].union(chain[chainLength-1-i])
                        chainEpisodes = prefixMergeEpisodes[chain2Index[chain_key]][chainLength-1-i]
                        self.mergeEpisodes(chainEpisodes, mergeEpisodes[chainMaxLength-1-i])
                for index, hop_episodes in enumerate(mergeEpisodes):
                    for att_vic, episodes in hop_episodes.items():
                        mergeEpisodes[index][att_vic] = sorted(mergeEpisodes[index][att_vic], key=lambda x: (x[1], x[2], x[3]))
                suffixMergeChain.append(mergeChain)
                suffixMergeEpisodes.append(mergeEpisodes)
        # remaining multi-hop attacks that cannot be merged
        for index, chain in enumerate(prefixMergeChain):
            chain_key = self.getChainKey(chain)
            if isMerged[chain_key]:
                continue
            mergeChain = [set() for i in range(len(chain))]
            mergeEpisodes = [dict() for i in range(len(chain))]
            for index, path in enumerate(chain):
                mergeChain[index] = mergeChain[index].union(path)
                chainEpisodes = prefixMergeEpisodes[chain2Index[chain_key]][index]
                self.mergeEpisodes(chainEpisodes, mergeEpisodes[index])
            for index, hop_episodes in enumerate(mergeEpisodes):
                for att_vic, episodes in hop_episodes.items():
                    mergeEpisodes[index][att_vic] = sorted(mergeEpisodes[index][att_vic], key=lambda x: (x[1], x[2], x[3]))
            suffixMergeChain.append(mergeChain)
            suffixMergeEpisodes.append(mergeEpisodes)

        return suffixMergeChain, suffixMergeEpisodes


    def chainExtract(self):
        diGraph, shortestPath = self.calcShortestPath()
        self.chainLenFilter(diGraph, shortestPath)
        self.multiStageChainExtract()
        self.organizeChain()
        

    def chainFilter(self):
        self.chainValidityFilter()
        self.chainTimeFilter()
       
    def chainMerge(self):
        prefixMergeChain, prefixMergeEpisodes = self.prefixMerge()
        suffixMergeChain, suffixMergeEpisodes = self.suffixMerge(prefixMergeChain, prefixMergeEpisodes)
        mergedChain, mergedEpisodes = self.mergeContinuousChain(suffixMergeChain, suffixMergeEpisodes)
        return mergedChain, mergedEpisodes
    def bashMatchSignature(self, episode, behaviour):
        protos = ','.join(list(episode[8].keys()))
        signatures = ','.join(list(episode[9].keys()))
        behaviour_id = behaviour[0]
        raw_sequence = behaviour[6]
        for k, v in self.bash_signature_dict.items():
            if re.search(k, raw_sequence, re.IGNORECASE) and re.search(v, protos + ',' + signatures, re.IGNORECASE):
                return True
        return False

    # identify the most relevant behaviour that exhibit semantic matching of attack stages
    def getMatchBehaviour(self, episode, matched_behaviour, vic, unmatched_id):
        match_id = -1
        candidate_behaviour = []
        other_behaviour = []
        behaviour_cmd_list_dict = {-1: []}
        for index, behaviour in enumerate(matched_behaviour):
            behaviour_id = behaviour[0]
            raw_sequence = behaviour[6]
            cmd_id_list = behaviour[7]
            behaviour_cmd_list_dict[behaviour_id] = cmd_id_list
            if ipJudge(vic, raw_sequence):
                candidate_behaviour.append((behaviour_id, self.bashMatchSignature(episode, behaviour)))
                if behaviour_id in unmatched_id:
                    unmatched_id.remove(behaviour_id)
            elif extractIPAddresses(raw_sequence) is False:
                other_behaviour.append((behaviour_id, self.bashMatchSignature(episode, behaviour)))
                if behaviour_id in unmatched_id:
                    unmatched_id.remove(behaviour_id)
        if candidate_behaviour:
            for behaviour_id, isMatch in candidate_behaviour:
                if isMatch:
                    match_id = behaviour_id
                    return match_id, behaviour_cmd_list_dict[match_id]
            match_id = candidate_behaviour[0][0]
            return match_id, behaviour_cmd_list_dict[match_id]
        if other_behaviour:
            for behaviour_id, isMatch in other_behaviour:
                if isMatch:
                    match_id = behaviour_id
                    return match_id, behaviour_cmd_list_dict[match_id]
        return match_id, behaviour_cmd_list_dict[match_id]


    def chainComplement(self, mergedChain):
        stat_dict = { # result statistics
            "AGCount": len(mergedChain),
            "addInfoAGCount": 0,
            "stageCount": 0,
            "addInfoStageCount": 0,
            "extraCount": 0,
            "behaviourCount": 0,
            "episodeCount": 0,
            "matchCount": 0,
        }
        # semantic supplement
        for chain_index, chain in enumerate(mergedChain):
            isMatchFlag = False
            isAddFlag = False
            isHostEpisodeFlag = False
            for hop_index, hop in enumerate(chain): # iterate through each hop
                for att_vic, episodes in hop.items():
                    for episode in episodes:
                        if episode[-2] == HOST_BEHAVIOUR and isHostEpisodeFlag is False:
                            isHostEpisodeFlag = True
                            break
                        if episode[-2] == NETWORK_EPISODE:
                            hostEpisodeNum = len([proto for proto in episode[7].keys() if proto.startswith('host')])
                            if isHostEpisodeFlag is False and hostEpisodeNum > 0:
                                isHostEpisodeFlag = True
                                break
                    episodes_ = []
                    att, vic = att_vic
                    if att not in self.behaviour_dict: # no host logs
                        for episode in episodes:
                            episodes_.append(episode)
                    else:
                        unmatched_id = [behaviour[0] for behaviour in self.behaviour_dict[att]]
                        for episode in episodes:
                            if episode[-2] == HOST_BEHAVIOUR:
                                episodes_.append(tuple(episode))
                                continue
                            mcat = episode[3] # episode[3]:mcat
                            matched_behaviour = list(filter(lambda x: int(x[5]) == macro_inv[micro2macro[micro[mcat]]], self.behaviour_dict[att]))
                            if len(matched_behaviour) == 0:
                                episodes_.append(tuple(episode))
                                continue
                            match_id, cmd_id = self.getMatchBehaviour(episode, matched_behaviour, vic, unmatched_id)
                            episode = list(episode)
                            episode[-1] = f'#{match_id}' if match_id != -1 else ''
                            episodes_.append(tuple(episode))
                            isMatchFlag = True if isMatchFlag is False and match_id != -1 else False

                        # attempt to supplement new episode from unmatched behaviors
                        if len(unmatched_id) > 0:
                            for behaviour in self.behaviour_dict[att]:
                                behaviour_id, host, start_time, end_time, info_path, attack_stage, raw_sequence, cmd_id_list, target = behaviour
                                if behaviour_id in unmatched_id and ipJudge(vic, raw_sequence):
                                    episode = [self.episode_id+1, start_time, end_time, int(attack_stage), RESERVED, RESERVED, end_time-start_time,
                                                RESERVED,
                                                RESERVED,
                                                info_path,
                                                raw_sequence,
                                                cmd_id_list,
                                                (start_time, end_time),
                                                HOST_BEHAVIOUR, '']
                                    episodes_.append(tuple(episode))
                                    self.episode_id += 1
                                    isAddFlag = True
                    episodes_ = sorted(episodes_, key=lambda x: (x[1], x[2], x[3]))
                    mergedChain[chain_index][hop_index][att_vic] = episodes_
            if isMatchFlag or isAddFlag or isHostEpisodeFlag:
                stat_dict['addInfoAGCount'] += 1
        return mergedChain, stat_dict
    def chainSearch(self):
        self.chainExtract()
        self.chainFilter()
        MergeChain, MergeEpisodes = self.chainMerge()
        completeChain, stat_dict = self.chainComplement(MergeEpisodes)
        return completeChain, stat_dict