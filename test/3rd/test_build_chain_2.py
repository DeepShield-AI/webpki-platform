
import sys
sys.path.append(r"/root/pki-internet-platform")

import os
import json

class Analyzer():

    def __init__(
            self,
            # input_file : str = r"/data/self_scan_data/CN_GOV_20241201/CN_GOV_20241201_result_1"
            input_file : str = r"/data/self_scan_data/CN_EDU_20241201/CN_EDU_20241201_result"
        ) -> None:

        self.input_file = input_file
        self.domain_with_certs = 0
        self.domain_with_multiple_certs_across_ips = 0
        self.domain_with_zlint_errors = 0
        self.domain_with_invalid_chain = 0
        self.domain_with_cross_signs = 0
        self.domain_with_cross_signs_num = []

    def analyze(self):
        if os.path.isfile(self.input_file):
            with open(self.input_file, "r", encoding='utf-8') as file:
                print(f"Reading file: {self.input_file}")
                data = json.load(file)

                for domain, res in data.items():
                    has_cert = False
                    same_cert = True
                    has_error = False
                    valid_chain = True
                    cross_sign = False
                    cross_sign_num = 0

                    current_cert = None
                    for ip, val in res.items():

                        if (val["sha256"] == None) and current_cert != None:
                            same_cert = False

                        if val["sha256"] != None:
                            has_cert = True
                            if not current_cert:
                                current_cert = val["sha256"]
                            elif val["sha256"] != current_cert:
                                same_cert = False

                        if val["zlint"] != None:
                            if val["zlint"] > 0:
                                has_error = True

                        if val["valid_chain"] != None:
                            if not val["valid_chain"]:
                                valid_chain = False

                        if val["cross_sign"] != None:
                            if val["cross_sign"] > 0:
                                cross_sign = True
                            if cross_sign_num < val["cross_sign"]:
                                cross_sign_num = val["cross_sign"]

                    if has_cert:
                        self.domain_with_certs += 1
                    if not same_cert:
                        self.domain_with_multiple_certs_across_ips += 1
                    if has_error:
                        self.domain_with_zlint_errors += 1
                    if not valid_chain:
                        self.domain_with_invalid_chain += 1
                    if cross_sign:
                        self.domain_with_cross_signs += 1
                        self.domain_with_cross_signs_num.append(cross_sign_num)

if __name__ == "__main__":
    analyzer = Analyzer()
    analyzer.analyze()
    print(
        analyzer.domain_with_certs,
        analyzer.domain_with_multiple_certs_across_ips,
        analyzer.domain_with_zlint_errors,
        analyzer.domain_with_invalid_chain,
        analyzer.domain_with_cross_signs,
        analyzer.domain_with_cross_signs_num
    )
