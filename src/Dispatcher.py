from DataPreprocessor import DataPreprocessor
from FalseAlarmFilter import FalseAlarmFilter
from EpisodeExtracter import EpisodeExtracter
from BehaviourExtractor import BehaviourExtractor
from ChainSearcher import ChainSearcher
from AttackGraphMaker import AttackGraphMaker
from ChainResultStat import ChainResultStat
from ChainEvaluator import ChainEvaluator
import time
from Config import *

class Dispatcher(object):
    def __init__(self, timeUtils, alertDataLoader, dataSaver, AG_OUTPUT_DIR) -> None:
        self.timeUtils = timeUtils
        self.alertDataLoader = alertDataLoader
        self.AG_OUTPUT_DIR = AG_OUTPUT_DIR
        self.dataSaver = dataSaver

    def dispatch(self):
        t1 = time.time()
        if not READ_BEHAVIOR_FROM_DATABASE:
            self.dataSaver.tableCreate()
        timeList = self.timeUtils.getIterList() 
        chainDict = {}
        chainResultStat = ChainResultStat()
        behavior_id = 1
        for t in timeList:
            start_time = t[0]
            end_time = t[1]
            print(f"processing from {start_time} to {end_time}")
            # data preprocessing 
            dataPreprocessor = DataPreprocessor(self.alertDataLoader, start_time, end_time)
            att_vic_dict, alarm_label_dict = dataPreprocessor.dataProcess()

            # false alarm filtering
            falseAlarmFilter = FalseAlarmFilter(att_vic_dict)
            att_vic_dict = falseAlarmFilter.falseAlarmFilter()

            # Inter-host abnormal episode aggregation
            episodeExtracter = EpisodeExtracter(att_vic_dict)
            episodes_dict, episode_count = episodeExtracter.extractEpisodes()

            # Intra-host sensitive behavior aggregation
            behaviourExtractor = BehaviourExtractor(self.alertDataLoader, self.dataSaver, behavior_id)
            host_data, host_behaviour_dict, behaviourCount, host_label_dict, new_behavior_id = behaviourExtractor.extract(start_time, end_time)
            behavior_id = new_behavior_id

            # heuristic multi-step attack searching
            chainSearcher = ChainSearcher(episodes_dict, host_behaviour_dict, start_time, end_time)
            completeChain, stat_dict = chainSearcher.chainSearch()
            chainDict[(start_time, end_time)] = completeChain

            # evaluation of reconstructed IoCs
            chainEvaluator = ChainEvaluator(completeChain, att_vic_dict, host_data, host_behaviour_dict, alarm_label_dict, host_label_dict)
            chainEvaluator.evaluate()
            chainResultStat.evaluationResultMerge(chainEvaluator)

            # # statistics
            stat_dict['behaviourCount'] = behaviourCount
            stat_dict['episodeCount'] = episode_count
            chainResultStat.chainResultMerge(stat_dict)

        t2 = time.time()
        # Attack Graph Visualization
        for key, value in chainDict.items():
            start_time = key[0]
            end_time = key[1]
            for chain_index, completeChain in enumerate(value):
                chain_label = f"{start_time}-{end_time}-{chain_index}"
                attackGraphMaker = AttackGraphMaker(completeChain, chain_label, self.AG_OUTPUT_DIR, chainResultStat)
                attackGraphMaker.generate_AG()
          
        chainResultStat.outputEvaluateResult()  
        chainResultStat.chainResultOutput()
        t3 = time.time()
        print(f"analysis time: {t2-t1}s")
        print(f"total time: {t3-t1}s")



