
import collections

# Data preprocessing, mainly used for data querying, data cleaning.
class DataPreprocessor:
    def __init__(self, alertDataLoader, start_time, end_time) -> None:
        self.alertDataLoader = alertDataLoader
        self.start_time = start_time
        self.end_time = end_time
        
    def getAlertData(self):
        data = self.alertDataLoader.getData(self.start_time, self.end_time)
        data = list(data)
        return data
    def dataClean(self, data):
        invalid_alert = []
        for alert in data:
            sip, dip = alert[:2]
            if not sip or not dip or sip == dip:
                invalid_alert.append(alert)
        for alert in invalid_alert:
            data.remove(alert)
        return data

    # (att, vic) : {alert_list}
    def dataOrganize(self, data):
        alarm_label_dict = collections.defaultdict(list)
        data = sorted(data, key=lambda x: x[-2]) # timestamp
        att_vic_dict = collections.defaultdict(list)
        for alert in data:
            att, vic = alert[:2]
            key = (att, vic)
            alert_id = alert[-3]
            label = alert[-1]
            alarm_label_dict[label].append(alert_id)
            att_vic_dict[key].append(alert[2:])
        return att_vic_dict, alarm_label_dict

    def dataProcess(self):
        data = self.getAlertData()
        data = self.dataClean(data)
        return self.dataOrganize(data)
