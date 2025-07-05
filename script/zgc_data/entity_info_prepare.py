
import os
import sys
import csv
import json
import signal
import threading
import tempfile
import subprocess

from urllib.parse import urlparse
from queue import PriorityQueue, Queue
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from backend.parser.pem_parser import PEMParser, PEMResult
from backend.config.path_config import ZLINT_PATH
from backend.utils.cert import get_cert_sha1_hex_from_str
from backend.utils.json import custom_serializer
from backend.logger.logger import primary_logger

output_file = open("certs.json", "w", encoding='utf-8')
output_file.write("[")
existing_domain = set()
existing_name = set()

# 全中国省份列表（简称）
PROVINCES = [
    "北京", "天津", "上海", "重庆",
    "河北", "山西", "辽宁", "吉林", "黑龙江",
    "江苏", "浙江", "安徽", "福建", "江西", "山东",
    "河南", "湖北", "湖南", "广东", "海南", "四川",
    "贵州", "云南", "陕西", "甘肃", "青海",
    "内蒙古", "广西", "西藏", "宁夏", "新疆",
    "香港", "澳门", "台湾"
]

# 部分主要城市（可扩充，越全越好）
CITIES = [
    # 直辖市
    "北京", "天津", "上海", "重庆",

    # 河北省
    "石家庄", "唐山", "秦皇岛", "邯郸", "邢台", "保定", "张家口", "承德", "沧州", "廊坊", "衡水",

    # 山西省
    "太原", "大同", "阳泉", "长治", "晋城", "朔州", "晋中", "运城", "忻州", "临汾", "吕梁",

    # 辽宁省
    "沈阳", "大连", "鞍山", "抚顺", "本溪", "丹东", "锦州", "营口", "阜新", "辽阳", "盘锦", "铁岭", "朝阳", "葫芦岛",

    # 吉林省
    "长春", "吉林", "四平", "辽源", "通化", "白山", "松原", "白城", "延边",

    # 黑龙江省
    "哈尔滨", "齐齐哈尔", "鸡西", "鹤岗", "双鸭山", "大庆", "伊春", "佳木斯", "七台河", "牡丹江", "黑河", "绥化", "大兴安岭",

    # 江苏省
    "南京", "无锡", "徐州", "常州", "苏州", "南通", "连云港", "淮安", "盐城", "扬州", "镇江", "泰州", "宿迁",

    # 浙江省
    "杭州", "宁波", "温州", "嘉兴", "湖州", "绍兴", "金华", "衢州", "舟山", "台州", "丽水",

    # 安徽省
    "合肥", "芜湖", "蚌埠", "淮南", "马鞍山", "淮北", "铜陵", "安庆", "黄山", "滁州", "阜阳", "宿州", "六安", "亳州", "池州", "宣城",

    # 福建省
    "福州", "厦门", "莆田", "三明", "泉州", "漳州", "南平", "龙岩", "宁德",

    # 江西省
    "南昌", "景德镇", "萍乡", "九江", "新余", "鹰潭", "赣州", "吉安", "宜春", "抚州", "上饶",

    # 山东省
    "济南", "青岛", "淄博", "枣庄", "东营", "烟台", "潍坊", "济宁", "泰安", "威海", "日照", "莱芜", "临沂", "德州", "聊城", "滨州", "菏泽",

    # 河南省
    "郑州", "开封", "洛阳", "平顶山", "安阳", "鹤壁", "新乡", "焦作", "濮阳", "许昌", "漯河", "三门峡", "南阳", "商丘", "信阳", "周口", "驻马店",

    # 湖北省
    "武汉", "黄石", "十堰", "宜昌", "襄阳", "鄂州", "荆门", "孝感", "荆州", "黄冈", "咸宁", "随州", "恩施",

    # 湖南省
    "长沙", "株洲", "湘潭", "衡阳", "邵阳", "岳阳", "常德", "张家界", "益阳", "郴州", "永州", "怀化", "娄底",

    # 广东省
    "广州", "深圳", "珠海", "汕头", "佛山", "韶关", "湛江", "肇庆", "江门", "茂名", "惠州", "梅州", "汕尾", "河源", "阳江", "清远", "东莞", "中山", "潮州", "揭阳", "云浮",

    # 海南省
    "海口", "三亚", "三沙",

    # 四川省
    "成都", "自贡", "攀枝花", "泸州", "德阳", "绵阳", "广元", "遂宁", "内江", "乐山", "南充", "眉山", "宜宾", "广安", "达州", "雅安", "巴中", "资阳",

    # 贵州省
    "贵阳", "六盘水", "遵义", "安顺", "毕节", "铜仁",

    # 云南省
    "昆明", "曲靖", "玉溪", "保山", "昭通", "丽江", "普洱", "临沧",

    # 陕西省
    "西安", "铜川", "宝鸡", "咸阳", "渭南", "延安", "汉中", "榆林", "安康", "商洛",

    # 甘肃省
    "兰州", "嘉峪关", "金昌", "白银", "天水", "武威", "张掖", "平凉", "酒泉", "庆阳", "定西", "陇南",

    # 青海省
    "西宁", "海东",

    # 内蒙古自治区
    "呼和浩特", "包头", "乌海", "赤峰", "通辽", "鄂尔多斯", "呼伦贝尔",

    # 广西壮族自治区
    "南宁", "柳州", "桂林", "梧州", "北海", "防城港", "钦州", "贵港", "玉林", "百色", "河池",

    # 西藏自治区
    "拉萨", "日喀则",

    # 宁夏回族自治区
    "银川", "石嘴山", "吴忠",

    # 新疆维吾尔自治区
    "乌鲁木齐", "克拉玛依", "吐鲁番", "哈密",

    # 香港特别行政区
    "香港",

    # 澳门特别行政区
    "澳门",

    # 台湾省
    "台北", "高雄", "台中"
]

# 地理级别优先级，数值越大优先级越高
LEVEL_PRIORITY = {
    "兴趣点": 50,
    "门址": 40,
    "街道": 30,
    "区": 20,
    "市": 10,
    "省": 5,
    "国家": 0
}


def extract_keywords_from_name(name):
    keywords = []
    for p in PROVINCES:
        if p in name:
            keywords.append(p)
    for c in CITIES:
        if c in name:
            keywords.append(c)
    return list(set(keywords))


def score_geo_code(name, geo_code):
    score = 0
    keywords = extract_keywords_from_name(name)

    # 省份匹配加分
    if any(kw in geo_code.get("province", "") for kw in keywords):
        score += 30
    # 城市匹配加分
    if any(kw in geo_code.get("city", "") for kw in keywords):
        score += 40
    # 行政区匹配稍微加分
    if any(kw in geo_code.get("district", "") for kw in keywords):
        score += 15

    # 级别加分
    score += LEVEL_PRIORITY.get(geo_code.get("level", ""), 0)

    # formatted_address中关键词匹配加分
    addr = geo_code.get("formatted_address", "")
    for kw in keywords:
        if kw in addr:
            score += 10

    return score


def select_best_geo_code(name, geo_codes):
    # 过滤有效数据
    valid_geo_codes = [
        gc for gc in geo_codes
        if gc.get("location") and gc.get("province") and gc.get("city")
    ]
    if not valid_geo_codes:
        return None

    scored_list = [(gc, score_geo_code(name, gc)) for gc in valid_geo_codes]
    scored_list.sort(key=lambda x: x[1], reverse=True)

    best_geo_code, best_score = scored_list[0]
    # 你可以根据分数阈值过滤，比如 score < 20 就认为无效
    if best_score < 20:
        return None
    return best_geo_code


class Analyzer():

    def __init__(
            self,
            _type : str = "政府",
            input_file : str = r"/data/self_scan_data/CN_GOV_20241201/CN_GOV_20241201_0_100000",
            geo_file : str = r"/root/pki-internet-platform/data/school_domains/cn/cn_edu_20241202_loc",
            domain_to_name_file : str = r"/root/pki-internet-platform/data/school_domains/cn/data20230918.csv",
        ) -> None:

        self._type = _type
        self.input_file = input_file
        self.geo_file = geo_file
        self.geo_data = {}

        self.domain_to_name_file = domain_to_name_file
        self.domain_to_name = {}
        self.data_queue = Queue()
        
        self.crtl_c_event = threading.Event()
        self.data_save_thread = threading.Thread(target=self.save_results)
        self.data_save_thread.start()

        with open(self.domain_to_name_file, "r", encoding='utf-8', newline='') as file:
            reader = csv.reader(file)
            for row in reader:

                if self._type == "高校":
                    # only keep 985 and 211 here
                    tag = row[3]
                    name = row[1]
                    if "985" in tag or "211" in tag:
                        urls = row[4].split(";")
                        urls.reverse()
                    else:
                        urls = []
                elif self._type == "政府":
                    name = row[2]
                    urls = row[3].split(";")
                elif self._type == "央企":
                    name = row[0]
                    urls = row[1].split(";")

                for url in urls:
                    parsed_url = urlparse(url)
                    if parsed_url.netloc:
                        print(parsed_url.netloc, name)
                        self.domain_to_name[parsed_url.netloc] = name
                        # only keep the first
                        break

        with open(self.geo_file, "r", encoding='utf-8') as file:
            for line in file:
                json_obj = json.loads(line.strip())
                if int(json_obj["data"]["status"]) == 1:
                    name = json_obj["name"]
                    geo_codes = json_obj["data"]["geocodes"]

                    best_geo = select_best_geo_code(name, geo_codes)

                    if best_geo:
                        loc = best_geo["location"].split(",")
                        simplified_geo_code = {
                            "latitude": loc[1],
                            "longitude": loc[0],
                            "region": [
                                best_geo["province"],
                                best_geo["city"],
                                best_geo["district"]
                            ]
                        }
                        self.geo_data[name] = simplified_geo_code


    def analyze(self):
        if os.path.isfile(self.input_file):
            with open(self.input_file, "r", encoding='utf-8') as file:
                primary_logger.info(f"Reading file: {self.input_file}")

                with ThreadPoolExecutor(max_workers=10) as executor:
                    for line in file:
                        # Check if there is signals
                        if self.crtl_c_event.is_set():
                            primary_logger.info("Ctrl + C detected, stoping allocating threads to the thread pool")
                            break

                        json_obj = json.loads(line.strip())
                        # self.analyze_single(json_obj)
                        executor.submit(self.analyze_single, json_obj)
                        # executor.submit(self.analyze_single, json_obj).result()

                    executor.shutdown(wait=True)
                    primary_logger.info("All threads finished.")

        # Wait for all elements in queue to be handled
        self.data_queue.join()

        # Send the poison pill to stop the saver thread
        self.data_queue.put(None)
        self.data_save_thread.join()


    def analyze_single(self, json_obj):
        domain = json_obj["destination_host"]
        ip = json_obj["destination_ip"]
        cert_chain = json_obj["ssl_result"]["peer_certs"]

        # Step 1: check if has cert
        try:
            cert :str = cert_chain[0]
            parsed : PEMResult = PEMParser.parse_pem_cert(cert)
            
            # Step 2: parse basic info
            subject_cn = parsed.subject_cn_list[0]
            try:
                issuer_country = parsed.issuer_country.upper()
            except Exception:
                issuer_country = "UN"

            not_before = parsed.not_before.replace("-", "").replace(":", "") + "Z"
            not_after = parsed.not_after.replace("-", "").replace(":", "") + "Z"
            sha1 = get_cert_sha1_hex_from_str(cert)

            # Step 3: check errors
            cert_error = False
            error_info = {
                "algo" : [],
                "deploy" : []
            }

            # 3.1 check expired certs
            date_obj = datetime.strptime(parsed.not_after, "%Y-%m-%d-%H-%M-%S")
            now = datetime.now()
            if date_obj < now:
                cert_error = True
                error_info["deploy"].append("过期")

            # 3.2 check sig and encrypt alg
            with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as temp_cert_file:
                temp_cert_file.write(cert.encode())
                temp_cert_path = temp_cert_file.name

            try:
                result = subprocess.run(
                    [
                        ZLINT_PATH,
                        "-includeNames=e_rsa_mod_less_than_2048_bits,e_dsa_shorter_than_2048_bits",
                        temp_cert_path
                        # "-includeNames=e_rsa_mod_less_than_2048_bits,w_rsa_mod_factors_smaller_than_752,e_dsa_shorter_than_2048_bits,e_old_sub_cert_rsa_mod_less_than_1024_bits"
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                if result.returncode != 0:
                    raise RuntimeError(f"Zlint error: {result.stderr.strip()}")

                zlint_output = json.loads(result.stdout)
                for name, result in zlint_output.items():
                    if result["result"] in ["warn", "error", "fatal"]:
                        cert_error = True
                        error_info["algo"].append("密钥长度过短")

                # next
                result = subprocess.run(
                    [
                        ZLINT_PATH,
                        "-includeNames=e_sub_cert_or_sub_ca_using_sha1,e_signature_algorithm_not_supported",
                        temp_cert_path
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                if result.returncode != 0:
                    raise RuntimeError(f"Zlint error: {result.stderr.strip()}")

                zlint_output = json.loads(result.stdout)
                for name, result in zlint_output.items():
                    if result["result"] in ["warn", "error", "fatal"]:
                        cert_error = True
                        error_info["algo"].append("弱哈希")

            except RuntimeError:
                cert_error = True
                error_info["algo"].append("证书格式错误")
            finally:
                try:
                    os.unlink(temp_cert_path)
                except OSError:
                    pass

            parsed_chain = [PEMParser.parse_pem_cert(cert) for cert in cert_chain]

            # 3.3 self-signed certs
            if len(cert_chain) == 1 and parsed.self_signed:
                cert_error = True
                error_info["deploy"].append("自签名")

            # 3.4 cert chain not verified
            if len(parsed_chain) == 1 and parsed.self_signed:
                pass
            else:
                leaf = parsed_chain[0]
                issuer = parsed_chain[1]
                if leaf.issuer_sha != issuer.subject_sha:
                    cert_error = True
                    error_info["deploy"].append("信任链建立失败")

            # if root is None:
            #     cert_error = True
            #     error_info["deploy"].append("信任链建立失败")
            # else:
            #     current = root
            #     for i in range(len(parsed_chain) - 1):
            #         found = False
            #         for cert in parsed_chain:
            #             cert : PEMResult
            #             if cert.issuer_sha == current.subject_sha and cert != root:
            #                 found = True
            #                 current = cert
            #                 break
            #         if not found:
            #             cert_error = True
            #             error_info["deploy"].append("信任链建立失败")
            #             break

            # 3.5 subject cn not match
            if domain not in parsed.subject_cn_list:
                domain : str
                wildcard_domain = ".".join(["*"] + domain.split(".")[1:])
                if wildcard_domain not in parsed.subject_cn_list:
                    cert_error = True
                    error_info["deploy"].append("网站与证书域名不匹配")

            cert_data = {
                "cn" : subject_cn,
                "error" : cert_error,
                "error_info" : error_info,
                "issuer_c" : issuer_country,
                "not_after" : not_after,
                "not_before" : not_before,
                "sha1" : sha1,
            }
            
            info_data = {
                "cert" : cert_data,
                "domain": domain,
                "entity_type": self._type,
                "has_cert": True
            }

        except IndexError:
            info_data = {
                "domain": domain,
                "entity_type": self._type,
                "has_cert": False
            }
        except Exception as e:
            primary_logger.error(e)
            info_data = {
                "domain": domain,
                "entity_type": self._type,
                "has_cert": False
            }
        finally:
            # Final step: append geo_data to here
            try:
                name = self.domain_to_name[domain]
                geo_code = self.geo_data[name]
                info_data["geo"] = geo_code

                final_data = info_data
                final_data["name"] = name
                self.data_queue.put(final_data)
            except KeyError as e:
                primary_logger.error(e)
                pass


    def save_results(self):
        data = {}
        while True:
            entry = self.data_queue.get()

            if entry is None:  # Poison pill to shut down the thread
                primary_logger.info("Poision detected")
                for e in data.values():
                    json_str = json.dumps(e, ensure_ascii=False, separators=(',', ':'), default=custom_serializer)
                    output_file.write(json_str + ',\n')
                self.data_queue.task_done()
                return

            try:
                if entry["domain"] in existing_domain and (not entry["has_cert"]):
                    self.data_queue.task_done()
                    continue
                existing_domain.add(entry["domain"])

                if entry["name"] in existing_name and (not entry["has_cert"]):
                    self.data_queue.task_done()
                    continue
                existing_name.add(entry["name"])

                data[entry["domain"]] = entry

            except Exception as e:
                primary_logger.error(f"Save {entry} failed, got exception {e}")
                pass

            self.data_queue.task_done()


if __name__ == "__main__":

    def signal_handler(sig, frame, analyzer : Analyzer):
        primary_logger.warning("Ctrl+C detected")
        analyzer.crtl_c_event.set()
        sys.exit(0)

    analyzer = Analyzer(
        _type = "高校",
        input_file = r"/home/tianyuz23/data/pki-internet-platform/data/school_domains/cn/CN_EDU_20250630",
        geo_file = r"/home/tianyuz23/data/pki-internet-platform/data/school_domains/cn/cn_edu_20241202_loc",
        domain_to_name_file = r"/home/tianyuz23/data/pki-internet-platform/data/school_domains/cn/data20230918.csv",
    )
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, analyzer))
    primary_logger.info("Crtl+C signal handler attached!")
    analyzer.analyze()

    analyzer = Analyzer(
        _type = "政府",
        input_file = r"/home/tianyuz23/data/pki-internet-platform/data/gov_domains/cn/CN_GOV_20250630",
        geo_file = r"/home/tianyuz23/data/pki-internet-platform/data/gov_domains/cn/cn_gov_20241203_loc_central",
        domain_to_name_file = r"/home/tianyuz23/data/pki-internet-platform/data/gov_domains/cn/cn_gov_20241106_map_central.csv",
    )
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, analyzer))
    primary_logger.info("Crtl+C signal handler attached!")
    analyzer.analyze()

    analyzer = Analyzer(
        _type = "央企",
        input_file = r"/home/tianyuz23/data/pki-internet-platform/data/enterprise_domains/cn/CN_SOE_20250630",
        geo_file = r"/home/tianyuz23/data/pki-internet-platform/data/enterprise_domains/cn/cn_soe_20241202_loc",
        domain_to_name_file = r"/home/tianyuz23/data/pki-internet-platform/data/enterprise_domains/cn/soe.csv"
    )
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, analyzer))
    primary_logger.info("Crtl+C signal handler attached!")
    analyzer.analyze()
    output_file.write("]")
