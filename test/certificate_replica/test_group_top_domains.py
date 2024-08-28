
import sys
sys.path.append(r"D:\global_ca_monitor")

from app.analyzer.certificate_replicas.group_top_domains import DataParser

analyzer = DataParser(load_dir=r'H:/sabre2024h1', save_dir=r'D:/global_ca_monitor/data/group_top_domains_200M')
analyzer.start()

analyzer = DataParser(load_dir=r'H:/sabre2024h2', save_dir=r'D:/global_ca_monitor/data/group_top_domains_200M')
analyzer.start()

analyzer = DataParser(load_dir=r'H:/sabre2025h1', save_dir=r'D:/global_ca_monitor/data/group_top_domains_200M')
analyzer.start()
