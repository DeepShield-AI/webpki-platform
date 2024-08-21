
import os
import json

from app import app, db
from ...parser.pem_parser import PEMParser, PEMResult
from sqlalchemy.dialects.mysql import insert
from ...models import CertificateReplicaEntry
from ...logger.logger import my_logger

class CertificateReplicas():

    def  __init__(self) -> None:
        self.load_dir = r'H:/ct_scan_raw'
        self.save_dir = r'H:/ct_scan_parsed'
        self.window = 1000
        self.count = 0


    def start(self):
        replica_data = []
        for filename in os.listdir(self.load_dir):
            file_path = os.path.join(self.load_dir, filename)
            if os.path.isfile(file_path):
                with open(file_path, "r") as file:
                    pem_result = self.fetch_cert_from_raw(file)
                    replica_data += pem_result
                    print(len(replica_data))
            
            if len(replica_data) >= self.window:
                self.save(replica_data)
                self.save_into_db(replica_data)
                self.count += len(replica_data)
                replica_data = []


    def fetch_cert_from_raw(self, fp):
        data = json.load(fp)
        my_logger.info(f"Length of file: {len(data.keys())}")
        cert_result = []
        for entry in data.values():
            if entry['leaf'] != None:
                cert_result.append(PEMParser.parse_pem_cert(entry['leaf']))
        return cert_result


    # data is json-formatted
    def save(self, data : PEMResult):
        my_logger.info("Save replica data to file")
        data = [PEMParser().convert_pem_result_to_json(d) for d in data]
        with open(os.path.join(self.save_dir, f"parsed_cert_{self.count}-{self.count + len(data)}"), 'w') as f:
            json.dump(data, f, indent=4)


    def save_into_db(self, data : PEMResult):
        my_logger.info("Save replica data to db")

        with app.app_context():
            cert_store_data_to_insert = []
            for result in data:
                result : PEMResult
                cert_store_data = {
                    'CERT_ID' : result.sha256,
                    'SIGNATURE' : result.signature,
                    'ISSUER_CN' : result.issuer_cn,
                    'ISSUER_ORG' : result.issuer_org,
                    'NOT_BEFORE' : result.not_before,
                    'NOT_AFTER' : result.not_after,
                    'SUBJECT' : result.subject,
                    'KEY_ALG' : result.pub_key_alg,
                    'KEY_ID' : result.pub_key_id,
                    'POLICY' : result.policy
                }
                cert_store_data_to_insert.append(cert_store_data)
                insert_cert_store_statement = insert(CertificateReplicaEntry).values(cert_store_data).prefix_with('IGNORE')
                # update_values = {key: insert_cert_store_statement.inserted[key] for key in cert_store_data.keys()}
                # update_values = {'FINGERPRINT': insert_cert_store_statement.inserted['FINGERPRINT']}
                # on_duplicate_key_statement = insert_cert_store_statement.on_duplicate_key_update(**update_values)
                # db.session.execute(on_duplicate_key_statement)
                db.session.execute(insert_cert_store_statement)
                db.session.commit()
