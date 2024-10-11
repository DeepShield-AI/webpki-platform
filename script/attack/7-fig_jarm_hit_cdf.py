
import numpy as np
import matplotlib.pyplot as plt
import csv

def draw_cdf(file_name, label, c):
    # 1 : 1
    related_domain_count_dict = {}
    with open(rf"D:/global_ca_monitor/script/attack/related_domains_count_{label}.csv", 'r', encoding='utf-8') as file:
        csv_reader = csv.reader(file)
        for row in csv_reader:
            related_domain_count_dict[row[0]] = row[1]

    cdf_data = []
    with open(file_name, 'r', encoding='utf-8') as file:
        data = csv.reader(file)
        for row in data:
            try:
                num_all = int(related_domain_count_dict[row[0]])
                num_hit = int(row[1])

                if num_hit < 0:
                    cdf_data.append(0)
                else:
                    cdf_data.append(num_hit / num_all)
            except KeyError:
                print(row)

    sorted_y = np.sort(cdf_data)
    cdf_y = np.arange(1, len(sorted_y) + 1) / len(sorted_y)
    plt.plot(sorted_y, cdf_y, color=c, label=label)

plt.figure(figsize=(5, 4))
draw_cdf(r'jarm_hit_nimbus.csv', 'nimbus', 'b')
draw_cdf(r'jarm_hit_sabre.csv', 'sabre', 'r')
plt.xlabel('Jarm Hit Percentage')
plt.ylabel('CDF')
plt.legend()
plt.savefig("jarm_hit_cdf.png")
plt.show()
