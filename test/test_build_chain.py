
import sys
sys.path.append(r"/root/pki-internet-platform")

import re
import os
import json
import tempfile
import subprocess
from app.utils.cert import get_cert_sha256_hex_from_str
from app.analyzer.cert_analyze_chain import CertChainAnalyzer
from app.config.analysis_config import ZLINT_PATH

def get_error_fatal_count(data):
    # 使用正则表达式匹配 'error' 和 'fatal' 对应的数量
    counts = {"error": 0, "fatal": 0}
    
    # 匹配 LEVEL 和 OCCURRENCES 列的行
    pattern = r'\| (\S+) \| (\d+) \|'
    matches = re.findall(pattern, data)

    # 统计 error 和 fatal 的数量
    for level, count in matches:
        if level in counts:
            counts[level] = int(count)
    
    return counts

class Analyzer():

    def __init__(
            self,
            input_file : str = r"/data/self_scan_data/CN_GOV_20241201/CN_GOV_20241201_0_100000",
            output_file : str = r"/data/self_scan_data/CN_GOV_20241201/CN_GOV_20241201_result"
            # input_file : str = r"/data/self_scan_data/CN_EDU_20241201/CN_EDU_20241201_0_100000",
            # output_file : str = r"/data/self_scan_data/CN_EDU_20241201/CN_EDU_20241201_result"
        ) -> None:

        self.input_file = input_file
        self.output_file = output_file
        self.chain_analyzer = CertChainAnalyzer()
        self.data = {}

    def analyze(self):
        if os.path.isfile(self.input_file):
            with open(self.input_file, "r", encoding='utf-8') as file:
                print(f"Reading file: {self.input_file}")
                for line in file:
                    json_obj = json.loads(line.strip())
                    self.analyze_single(json_obj)

        with open(self.output_file, "w") as f:
            json.dump(self.data, f, indent=4)

    def analyze_single(self, json_obj):
        domain = json_obj["destination_host"]
        if domain not in self.data:
            self.data[domain] = {}

        ip = json_obj["destination_ip"]
        if ip not in self.data[domain]:
            self.data[domain][ip] = {
                "sha256" : None,
                "zlint" : None,
                "valid_chain" : None,
                "cross_sign" : None
            }

        cert_chain = json_obj["cert_chain"]
        if not cert_chain: return

        leaf_cert = cert_chain[0]
        # self.data[domain][ip]["sha256"] = get_cert_sha256_hex_from_str(leaf_cert)

        # zlint_result = self.get_cert_zlint(leaf_cert)
        # e_count = get_error_fatal_count(zlint_result)
        # self.data[domain][ip]["zlint"] = e_count['error'] + e_count['fatal']

        # valid_chain = self.chain_analyzer.verify_and_rebuild_cert_chain(cert_chain)
        # self.data[domain][ip]["valid_chain"] = valid_chain

        cross_sign = self.chain_analyzer.find_cross_sign_certs_from_store(leaf_cert)
        self.data[domain][ip]["cross_sign"] = cross_sign

    def get_cert_zlint(self, cert_pem):

        # 创建一个临时文件存储证书内容
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as temp_cert_file:
            temp_cert_file.write(cert_pem.encode())
            temp_cert_path = temp_cert_file.name

        try:
            # 调用 Zlint
            result = subprocess.run(
                [ZLINT_PATH, "-summary", temp_cert_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # 检查是否有错误输出
            if result.returncode != 0:
                raise RuntimeError(f"Zlint error: {result.stderr.strip()}")

            # 解析 JSON 输出
            zlint_output = result.stdout

        finally:
            # 删除临时文件
            try:
                import os
                os.unlink(temp_cert_path)
            except OSError:
                pass

        return zlint_output


if __name__ == "__main__":
    analyzer = Analyzer()
    analyzer.analyze()
