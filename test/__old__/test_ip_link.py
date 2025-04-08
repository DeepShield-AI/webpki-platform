
import sys
sys.path.append(r"/root/pki-internet-platform")

from backend.analyzer.ip_linking import IPSCANANALYSIS
from backend.analyzer.ip_linking_2 import IPCERTMATCH
from backend.analyzer.ip_linking_3 import IPCOUNT
from backend.config.analysis_config import IP2LOCATIONDB1_DIR, IP2LOCATIONDB3_DIR, IP2LOCATIONASN_DIR

if __name__ == "__main__":
    analyzer = IPCOUNT()
    analyzer.analyze()
