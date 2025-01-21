import time


class TimeUtils:
    """
    Utility class for handling time-related operations.
    
    start_time: The start time for the search window.
    end_time: The end time for the search window.
    span: The interval of the search window in seconds. If span is 0, the search window will be a single time point.
    """

    def __init__(self, start_time, end_time, span=0):
        self.start_time = start_time
        self.end_time = end_time
        self.span = float(span)

    def getFloatTime(self, t):
        return time.mktime(time.strptime(t, '%Y-%m-%d %H:%M:%S'))

    def getStructTime(self, f):
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(f))

    def getIterList(self):
        if self.span == 0:
            return [(self.start_time, self.end_time)]
        cur_time = self.start_time
        iterList = []
        while cur_time < self.end_time:
            t1 = cur_time
            t2 = self.getStructTime(self.getFloatTime(t1) + self.span)
            if t2 > self.end_time:
                t2 = self.end_time
            iterList.append((t1, t2))
            cur_time = t2
        return iterList