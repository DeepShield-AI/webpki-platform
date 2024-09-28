
import sys
sys.path.append(r"D:\global_ca_monitor")

from app.analyzer.certificate_replicas.group_top_domains import DataParser

parser = DataParser(log_name="nimbus2024", load_dir=r'H:/nimbus2024', save_dir=r'G:/group_top_domains_nimbus')
parser.start()

# parser = DataParser(log_name="sabre2024h1", load_dir=r'H:/sabre2024h1_compressed', save_dir=r'D:/global_ca_monitor/data/group_top_domains_sabre')
# parser.start()

# parser = DataParser(load_dir=r'H:/sabre2024h2_compressed', save_dir=r'D:/global_ca_monitor/data/group_top_domains_sabre')
# asyncio.run(parser.start())

# parser = DataParser(log_name="sabre2025h1", load_dir=r'H:/sabre2025h1_compressed', save_dir=r'D:/global_ca_monitor/data/group_top_domains_sabre')
# parser.start()

# parser = DataParser(log_name="sabre2025h2", load_dir=r'H:/sabre2025h2_compressed', save_dir=r'D:/global_ca_monitor/data/group_top_domains_sabre')
# parser.start()
