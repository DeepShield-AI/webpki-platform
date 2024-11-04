
import sys
sys.path.append(r"D:\global_ca_monitor")

from app.analyzer.certificate_replicas.parse_and_merge import ParseAndMerge

analyzer = ParseAndMerge()
analyzer.start()
