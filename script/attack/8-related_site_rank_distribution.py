
import csv
def dist(label):
    # 1 : 1
    related_domain_count_dict = {}
    with open(rf"related_domains_count_{label}.csv", 'r', encoding='utf-8') as file:
        csv_reader = csv.reader(file)
        for row in csv_reader:
            try:
                if int(row[1]) > 1:
                    related_domain_count_dict[row[0]] = row[1]
            except ValueError:
                pass

    with open(rf"8-rank_dist_{label}.csv", 'w', encoding='utf-8', newline='') as file:
        writer = csv.writer(file)
        for k, v in related_domain_count_dict.items():
            writer.writerow([k, v])
dist("nimbus")
dist("sabre")
