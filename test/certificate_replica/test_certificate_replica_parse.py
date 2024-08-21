
import sys
sys.path.append(r"E:\global_ca_monitor")

from app.analyzer.certificate_replicas.main import CertificateReplicas

analyzer = CertificateReplicas()
analyzer.start()
