
import json
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_cert

tot_num = 0
validity = []
new_conn = engine_cert.raw_connection()

with open("13-id_seed.txt", "r") as input:
    for id in input:

        with new_conn.cursor() as cursor:
            query = """
                SELECT * from cert_search
                WHERE id = %s
            """
            cursor.execute(query, (id,))
            row = cursor.fetchone()

        if row:
            issuer = row[0]
            not_valid_before = row[-3]
            not_valid_after = row[-2]
            try:
                days = (not_valid_after - not_valid_before).days
                validity.append((not_valid_before.isoformat(), not_valid_after.isoformat()))
            except:
                pass

with open("13-validity.json", "w") as f:
    json.dump(validity, f, indent=2)

# with open("13-validity.json", "r") as f:
#     my_dict = json.load(f)

# # # 取前 2000 条
# # top_entries = my_dict[:2000]

# # # 输出 CSV 文件
# # with open("13-validity.csv", "w", newline='') as csvfile:
# #     writer = csv.writer(csvfile)
# #     for item in top_entries:
# #         not_before = datetime.fromisoformat(item[0]).strftime("%Y-%m-%d")
# #         not_after = datetime.fromisoformat(item[1]).strftime("%Y-%m-%d")
# #         writer.writerow([not_before, not_after])

# # exit(0)

# validity_list = []

# for item in my_dict:
#     not_before = datetime.fromisoformat(item[0])
#     not_after = datetime.fromisoformat(item[1])
#     validity_days = (not_after - not_before).days  # 计算有效期天数
#     validity_list.append(validity_days)

# # 统计每种有效期出现的次数
# counter = Counter(validity_list)

# # 取前 5/10
# top10 = counter.most_common(20)

# for days, count in top10:
#     print(f"{days} days: {count}")

# exit(0)
