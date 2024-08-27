
from datetime import datetime


class OverlapAnalysis():

    def __init__(self) -> None:
        pass

    def analyze_group(self, replica_group : ReplicaGroup):

        percent_count = {}
        day_count = {}
        
        # 对每个分组内部进行处理
        for domain, group in replica_group.entry_dict.items():

            # 将证书按 not_before 排序
            group.sort(key=lambda x: x.not_before)

            for i in range(len(group) - 1):
                current_entry = group[i]

                for j in range(i + 1, len(group)):
                    next_entry = group[j]
                    
                    overlap = self.calculate_overlap(current_entry, next_entry)
                    if overlap != None:

                        if overlap[0] not in day_count:
                            day_count[overlap[0]] = 0
                        day_count[overlap[0]] += 1

                        if overlap[1] not in percent_count:
                            percent_count[overlap[1]] = 0
                        percent_count[overlap[1]] += 1

                        if overlap[2] not in percent_count:
                            percent_count[overlap[2]] = 0
                        percent_count[overlap[2]] += 1
                        
                    else:
                        break

        return percent_count, day_count
    

    def calculate_overlap(self, entry1, entry2):
        overlap_start = max(entry1.not_before, entry2.not_before)
        overlap_end = min(entry1.not_after, entry2.not_after)

        if overlap_start < overlap_end:
            overlap_duration = (overlap_end - overlap_start).days

            # 计算每个证书的有效期
            total_duration1 = (entry1.not_after - entry1.not_before).days
            total_duration2 = (entry2.not_after - entry2.not_before).days

            # 计算相交百分比
            overlap_percentage1 = (overlap_duration / total_duration1) * 100
            overlap_percentage2 = (overlap_duration / total_duration2) * 100

            return overlap_duration, overlap_percentage1, overlap_percentage2
        else:
            return None
