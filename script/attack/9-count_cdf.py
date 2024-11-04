
import numpy as np
import matplotlib.pyplot as plt
import csv

def dist(label):
    count_data = []
    with open(rf"related_domains_count_{label}.csv", 'r', encoding='utf-8') as file:
        csv_reader = csv.reader(file)
        for row in csv_reader:
            try:
                if int(row[1]) > 0:
                    count_data.append(int(row[1]))
            except:
                pass

    sorted_y = np.sort(count_data)
    cdf_y = np.arange(1, len(sorted_y) + 1) / len(sorted_y)

    with open(rf"9-count_cdf_{label}.csv", 'w', encoding='utf-8', newline='') as file:
        writer = csv.writer(file)
        for i in range(len(cdf_y)):
            writer.writerow([sorted_y[i], cdf_y[1]])

dist("nimbus")
dist("sabre")
