import collections
from Config import *
import re
import bashlex


class ChainResultStat(object):
    def __init__(self) -> None:
        self.result_dict = collections.defaultdict(int)
        self.label_to_cover_signatures = collections.defaultdict(set) # reconstruction status of S-IoCs
        self.label_to_cover_operations = collections.defaultdict(set) # reconstruction status of C-IoCs
        self.label_to_signatures = collections.defaultdict(set) # ground truth of S-IoCs 
        self.label_to_operations = collections.defaultdict(set) # ground truth of C-IoCs
        self.label_to_cover = collections.defaultdict(set) # reconstruction status of IoCs
        self.label_to_IoCs = collections.defaultdict(set) # ground truth of C-IoCs

        
    def evaluationResultMerge(self, chainEvaluator):
        if len(self.label_to_cover_signatures) == 0:
            for k, v in chainEvaluator.label_to_cover_signatures.items():
                self.label_to_cover_signatures[k] = v
        else:
            for k, v in chainEvaluator.label_to_cover_signatures.items():
                self.label_to_cover_signatures[k] = self.label_to_cover_signatures[k].union(v)
        
        if len(self.label_to_cover_operations) == 0:
            for k, v in chainEvaluator.label_to_cover_operations.items():
                self.label_to_cover_operations[k] = v
        else:
            for k, v in chainEvaluator.label_to_cover_operations.items():
                self.label_to_cover_operations[k] = self.label_to_cover_operations[k].union(v)

        if len(self.label_to_signatures) == 0:
            for k, v in chainEvaluator.label_to_signatures.items():
                self.label_to_signatures[k] = v
        else:
            for k, v in chainEvaluator.label_to_signatures.items():
                self.label_to_signatures[k] = self.label_to_signatures[k].union(v)

        if len(self.label_to_operations) == 0:
            for k, v in chainEvaluator.label_to_operations.items():
                self.label_to_operations[k] = v
        else:
            for k, v in chainEvaluator.label_to_operations.items():
                self.label_to_operations[k] = self.label_to_operations[k].union(v)

    def outputEvaluateResult(self):
        self.label_to_cover = {k:self.label_to_cover_signatures[k].union(self.label_to_cover_operations[k]) for k,v in self.label_to_cover_signatures.items()}
        self.label_to_IoCs = {k:self.label_to_signatures[k].union(self.label_to_operations[k]) for k,v in self.label_to_signatures.items()}
        for k in self.label_to_IoCs.keys():
            if k not in self.label_to_cover:
                self.label_to_cover[k] = set()

        print("*" * 25 + "result of each attack step" + "*" * 25)
        print("cover number of each attack step")
        Step_sign_count_dict = {k:len(v) for k,v in self.label_to_cover.items()}
        print(dict(sorted(Step_sign_count_dict.items(), key=lambda x:x[0])))
        print("cover rate of each attack step")
        Step_sign_coverage_dict = {key: float(len(self.label_to_cover[key])) / len(self.label_to_IoCs[key]) for key in self.label_to_IoCs.keys() if key in self.label_to_cover}
        print(dict(sorted(Step_sign_coverage_dict.items(), key=lambda x:x[0])))

        print("*" * 25 + "evaluation of S-IoCs" + "*" * 25)
        total_signatures = 0
        total_covered_signatures = 0
        fp_signatures = 0
        uncovered_signatures = {k:set() for k in self.label_to_signatures.keys() if k != 0}
        for key, value in self.label_to_signatures.items():
            if key == 0:
                if key in self.label_to_cover_signatures:
                    fp_signatures += len(self.label_to_cover_signatures[key])
                continue
            total_signatures += len(value)
            total_covered_signatures += len(self.label_to_cover_signatures[key])
            uncovered_signatures[key] = value - self.label_to_cover_signatures[key]
        print("total_signs_num:", total_signatures)
        print("total_covered_signs_num:", total_covered_signatures, "total_cover_rate:", float(total_covered_signatures) / total_signatures)
        print("fp_signs_num: ", fp_signatures)
        tp = total_covered_signatures
        fp = fp_signatures
        fn = total_signatures - tp
        epsilon = 1e-7
        precision = tp / (tp + fp + epsilon)
        recall = tp / (tp + fn + epsilon)
        f1_score = 2 * (precision * recall) / (precision + recall + epsilon)
        print("precision:", precision, "recall:", recall, "f1_score:", f1_score)

        print("*" * 25 + "evaluation of C-IoCs" + "*" * 25)
        total_operations = 0
        total_covered_operations = 0
        fp_operations = 0
        uncovered_operations_dict = {k:set() for k in self.label_to_operations.keys() if k != 0}
        for key, value in self.label_to_operations.items():
            if key == 0:
                if key in self.label_to_cover_operations:
                    fp_operations += len(self.label_to_cover_operations[key])
                continue
            total_operations += len(value)
            total_covered_operations += len(self.label_to_cover_operations[key])
            uncovered_operations_dict[key] = value - self.label_to_cover_operations[key]
        print("total_operations_num:", total_operations)
        print("total_covered_operations_num:", total_covered_operations, "total_cover_rate:", float(total_covered_operations) / total_operations)
        print("fp_operations_num: ", fp_operations)
        tp = total_covered_operations
        fp = fp_operations
        fn = total_operations - tp
        epsilon = 1e-7
        precision = tp / (tp + fp + epsilon)
        recall = tp / (tp + fn + epsilon)
        f1_score = 2 * (precision * recall) / (precision + recall + epsilon)
        print("precision:", precision, "recall:", recall, "f1_score:", f1_score)


        print("*" * 25 + "total result of multi-step reconstrction" + "*" * 25)
        total_covered_IoCs = 0
        total_IoCs = 0
        fp_IoCs_num = 0
        uncovered_signs = {k:set() for k in self.label_to_IoCs.keys() if k != 0}
        for key, value in self.label_to_IoCs.items():
            if key == 0:
                if key in self.label_to_cover:
                    fp_IoCs_num += len(self.label_to_cover[key])
                continue
            total_IoCs += len(value) 
            total_covered_IoCs += len(self.label_to_cover[key])
            uncovered_signs[key] = value - self.label_to_cover[key]
        print("total_signs_num:", total_IoCs)
        print("total_covered_signs_num:", total_covered_IoCs, "total_cover_rate:", float(total_covered_IoCs) / total_IoCs)
        print("fp_signs_num: ", fp_IoCs_num)
        print("uncovered_signs:", uncovered_signs)
        tp = total_covered_IoCs
        fp = fp_IoCs_num
        fn = total_IoCs - tp
        epsilon = 1e-7
        precision = tp / (tp + fp + epsilon)
        recall = tp / (tp + fn + epsilon)
        f1_score = 2 * (precision * recall) / (precision + recall + epsilon)
        print("precision:", precision, "recall:", recall, "f1_score:", f1_score)

    def chainResultMerge(self, stat_dict):
        for key, value in stat_dict.items():
            self.result_dict[key] += value

    def chainResultOutput(self):
        AGCount, addInfoAGCount, stageCount, addInfoStageCount, extraCount, behaviourCount, episodeCount, matchCount = list(self.result_dict.values())

        print(f"Number of attack graphs: {AGCount}, number of attack graphs with semantic supplementation: {addInfoAGCount}")
        print(f"Total number of attack stages in attack graphs: {stageCount}, number of attack stages with semantic supplementation {addInfoStageCount}")
        print(f"Number of inter-host abnormal episodes: {episodeCount}, number of intra-host sensitive behaviors: {behaviourCount}")
        print(f"Number of behaviors exhibiting semantic matching: {matchCount}")
        print(f"Number of behaviors supplemented as new episodes: {extraCount}")
        print(f"Percentage of attack stages with semantic supplementation: {addInfoStageCount/stageCount if stageCount > 0 else 0:.2%}")
        print(f"Percentage of mutli-step attacks with semantic supplementation: {addInfoAGCount/AGCount:.2%}")
        