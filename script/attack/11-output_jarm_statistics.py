
import numpy as np
import matplotlib.pyplot as plt
import csv

# (0,5]
g_range = [
    (2, 3),
    (4, 5),
    (6, 10),
    (11, 20),
    (21, 30),
    (31, 50),
    (51, 70),
    (71, 100),
    (101, 500),
    (501, 10000000)
]

stat_dict = {}
for _range in g_range:
    stat_dict[_range] = []

def check_group(num):
    for i in range(len(g_range)):
        if g_range[i][0] <= num <= g_range[i][1]:
            return i

def dist(label):
    with open(rf"10-jarm_hit_percentage_{label}.csv", 'r', encoding='utf-8') as file:
        csv_reader = csv.reader(file)
        count = []
        for row in csv_reader:
            try:
                count.append(int(row[1]))
                group_index = check_group(int(row[1]))
                stat_dict[g_range[group_index]].append(float(row[2]))
            except Exception as e:
                # print(e)
                pass

    with open(rf"11-jarm_count_{label}.csv", 'w', encoding='utf-8', newline='') as file:
        writer = csv.writer(file)
        for i in sorted(count):
            if i > 1:
                writer.writerow([i])

    with open(rf"11-output_jarm_stat_{label}.csv", 'w', encoding='utf-8', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(g_range)
        max_length = 0
        for k, data in stat_dict.items():
            if len(data) > max_length:
                max_length = len(data)

        for i in range(max_length):
            row = []
            for k, data in stat_dict.items():
                try:
                    row.append(data[i])
                except IndexError:
                    row.append("")
            writer.writerow(row)

            # print(k, len(data))
            # mean_value = np.mean(data)
            # median_value = np.median(data)
            # percentile_25 = np.percentile(data, 25)
            # percentile_75 = np.percentile(data, 75)
            # writer.writerow([k, mean_value, percentile_25, median_value, percentile_75])

dist("nimbus")
dist("sabre")
