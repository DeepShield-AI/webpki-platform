
from .replica_counting import ReplicaGroup, ReplicaEntry


class IssuerAnalysis():

    def __init__(self) -> None:
        pass

    def analyze_group(self, replica_group : ReplicaGroup):

        issuer_cn_count = {}
        issuer_org_count = {}
        
        # 对每个分组内部进行处理
        for domain, group in replica_group.entry_dict.items():

            # 将证书按 not_before 排序
            group.sort(key=lambda x: x.not_before)

            for entry in group:
                if entry.issuer_cn not in issuer_cn_count:
                    issuer_cn_count[entry.issuer_cn] = 0
                issuer_cn_count[entry.issuer_cn] += 1

                if entry.issuer_org not in issuer_org_count:
                    issuer_cn_count[entry.issuer_org] = 0
                issuer_cn_count[entry.issuer_org] += 1

        return issuer_cn_count, issuer_org_count
    