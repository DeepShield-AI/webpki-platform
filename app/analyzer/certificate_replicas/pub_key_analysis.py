
from .replica_counting import ReplicaGroup, ReplicaEntry


class PubKeyAnalysis():

    def __init__(self) -> None:
        pass

    def analyze_group(self, replica_group : ReplicaGroup):

        pub_key_count = {}
        
        # 对每个分组内部进行处理
        for domain, group in replica_group.entry_dict.items():

            # 将证书按 not_before 排序
            group.sort(key=lambda x: x.not_before)

            for entry in group:
                if entry.key_id not in pub_key_count:
                    pub_key_count[entry.key_id] = 0
                pub_key_count[entry.key_id] += 1

        return pub_key_count
    