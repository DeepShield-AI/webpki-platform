
import sys
sys.path.append(r"D:\global_ca_monitor")

from app.analyzer.certificate_replicas.group_top_domains import DataParser

analyzer = DataParser()
analyzer.start()
