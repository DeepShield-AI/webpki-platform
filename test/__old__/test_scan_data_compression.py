
import sys
sys.path.append(r"D:\global_ca_monitor")

import asyncio
from backend.utils.ct_scan_data_compression import CompressScanContent

compressor = CompressScanContent(
    load_dir=r'H:/sabre2024h2',
    save_dir=r'H:/sabre2024h2_compressed'
)
# compressor = CompressScanContent(
#     load_dir=r'H:/nimbus2024',
#     save_dir=r'H:/nimbus2024_compressed'
# )

# compressor = CompressScanContent()
asyncio.run(compressor.start())
