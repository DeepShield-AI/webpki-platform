
import sys
sys.path.append(r"D:\pki-internet-platform")

import csv, time, json
from app.utils.gaode_api import get_location_by_address
from app.utils.json import custom_serializer

output_file = open("cn_soe_20241202_loc", "w", encoding='utf-8')

with open("soe.csv", "r", encoding='utf-8', newline="") as file:
    reader = csv.reader(file)

    for row in reader:
        name = row[0]
        loc_data = get_location_by_address(name, None)
        data = {
            "name" : name,
            "data" : loc_data
        }

        json_str = json.dumps(data, ensure_ascii=False, separators=(',', ':'), default=custom_serializer)
        print(json_str)
        output_file.write(json_str + '\n')
        time.sleep(0.35)
