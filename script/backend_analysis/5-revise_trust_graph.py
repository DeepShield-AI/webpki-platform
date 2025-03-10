
import sys
sys.path.append(r"/root/pki-internet-platform")

import os
import json

class Analyzer():

    def __init__(
            self,
            input_file : str = r"/data/zgrab2_scan_data/CiscoTop1M_20241110_ca_trust_graph",
            output_file : str = r"/data/zgrab2_scan_data/CiscoTop1M_20241110_ca_trust_graph_revised"
        ) -> None:

        self.input_file = input_file
        self.output_file = output_file
        self.graph_data = {"links": [], "nodes": []}

    def analyze(self):
        if os.path.isfile(self.input_file):
            with open(self.input_file, "r", encoding='utf-8') as file:
                print(f"Reading file: {self.input_file}")

                for line in file:
                    json_obj = json.loads(line.strip())
                    self.analyze_single(json_obj)

        with open(self.output_file, "w", encoding='utf-8') as f:
            json.dump(self.graph_data, f, indent=4)

    def analyze_single(self, entry):
        try:
            if entry["source"] == entry["target"]:
                return
            self.graph_data["links"].append(entry)
        except KeyError:
            self.graph_data["nodes"].append(entry)

if __name__ == "__main__":
    analyzer = Analyzer(
        input_file = r"/data/zgrab2_scan_data/CiscoTop1M_20241110_ca_trust_graph",
        output_file = r"/data/zgrab2_scan_data/CiscoTop1M_20241110_ca_trust_graph_revised"
    )
    analyzer.analyze()
