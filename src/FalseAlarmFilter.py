from Config import *
from ChainUtils import *
"""
 You can integrate your false positive filtering method here according to different scenarios.
 Since cptc and msas dataset are primarily concerned with attack traffic, we use a whitelist to filter out irrelevant alerts.
"""


class FalseAlarmFilter(object):
    def __init__(self, att_vic_dict) -> None:
        self.att_vic_dict = att_vic_dict

    def falseAlarmFilter(self):
        falseAlarmKey = []
        for att, vic in self.att_vic_dict.keys():
            if vic not in whiteList:
                falseAlarmKey.append((att, vic))
        for key in falseAlarmKey:
            self.att_vic_dict.pop(key)
        return self.att_vic_dict