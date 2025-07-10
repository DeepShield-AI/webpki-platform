
import sys
sys.path.append(r"D:\pki-internet-platform")

import csv, time, json, os
from app.utils.gaode_api import get_location_by_address
from app.utils.json import custom_serializer

output_file = open("cn_gov_20241203_loc_central", "w", encoding='utf-8')

def get(name):
    loc_data = get_location_by_address(name, None)
    data = {
        "name" : name,
        "data" : loc_data
    }

    json_str = json.dumps(data, ensure_ascii=False, separators=(',', ':'), default=custom_serializer)
    print(json_str)
    output_file.write(json_str + '\n')
    time.sleep(0.35)

for dir in os.scandir(r"."):
    if os.path.isdir(dir.path):
        if "central" in dir.path:

            for sub_dir in os.scandir(dir.path):
                if os.path.isdir(sub_dir.path):
                    for file in os.scandir(sub_dir.path):
                        if os.path.isfile(file.path):
                            with open(file.path, "r", encoding='utf-8', newline="") as file:
                                reader = csv.reader(file)

                                for row in reader:
                                    name = row[2]
                                    get(name)

        else:
            continue
            for file in os.scandir(dir.path):
                if os.path.isfile(file.path):
                    with open(file.path, "r", encoding='utf-8', newline="") as file:
                        reader = csv.reader(file)

                        for row in reader:
                            name = row[2]
                            get(name)
