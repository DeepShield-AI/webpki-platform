
import os
import csv, json
import IP2Location
from app.config.analysis_config import IP2LOCATIONDB1_DIR, IP2LOCATIONDB3_DIR, IP2LOCATIONASN_DIR

database = IP2Location.IP2Location(IP2LOCATIONDB3_DIR)
result = database.get_all("8.8.8.8")
print("Country Code:", result.country_short)
print("Country Name:", result.country_long)
print("Region Name:", result.region)
print("City Name:", result.city)

class IPCOUNT():

    def __init__(
            self,
            input_file : str = r"/data/ip_scan_data/Full_IPv4_20241124_zgrab2_country_to_ip",
            output_file : str = r"/data/ip_scan_data/Full_IPv4_20241124_zgrab2_country_result"
        ) -> None:

        self.input_file = input_file
        self.output_file = output_file
        self.result = {
            "same" : [],
            "different" : [],
            "cn_true" : [],
            "cn_false" : [],
            "not_cn" : []
        }

    def analyze(self):
        if os.path.isfile(self.input_file):
            # with open(self.input_file, "r", newline='', encoding='utf-8', errors='ignore') as file:
            with open(self.input_file, "r", newline='') as file:
                print(f"Reading file: {self.input_file}")
                reader = csv.reader(file)

                for row in reader:
                    # NUL bytes
                    # sed -i 's/\x0//g' Full_IPv4_20241124_zgrab2_domain_to_ip

                    country = row[0]
                    if country == "cn":
                        country = "CN"

                    for ip in row[1:]:
                        desired_country = database.get_all(ip).country_short

                        if country == desired_country:
                            self.result["same"].append(ip)
                            if country == "cn" or country == "CN":
                                self.result["cn_true"].append(ip)
                        elif country == "CN" and desired_country != "CN":
                            self.result["different"].append(ip)
                            self.result["not_cn"].append(ip)
                        elif country != "CN" and desired_country == "CN":
                            self.result["different"].append(ip)
                            self.result["cn_false"].append(ip)
                        
        print(len(self.result["cn_true"]))
        print(len(self.result["cn_false"]))
        print(len(self.result["not_cn"]))

        with open(self.output_file, "w") as f:
            json.dump(self.result, f, indent=4)
