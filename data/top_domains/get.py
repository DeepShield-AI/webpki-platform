
import csv

input_filename = 'cisco-top-1m.csv'
output_filename = 'cisco-top-1m-new.csv'
limit = 1000000

with open(input_filename, 'r', newline='', encoding='utf-8') as infile, \
     open(output_filename, 'w', newline='', encoding='utf-8') as outfile:
    
    reader = csv.reader(infile)
    writer = csv.writer(outfile)
    
    for i, row in enumerate(reader):
        if i >= limit:
            break
        if len(row) >= 2:  # 确保行至少有2列
            writer.writerow([row[1]])  # 只写入第二项
            