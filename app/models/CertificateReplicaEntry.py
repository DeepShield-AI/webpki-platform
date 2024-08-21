
from app import db
from datetime import datetime, timezone
from sqlalchemy import MetaData

class CertificateReplicaEntry(db.Model):

    __tablename__ = "CERTIFICATE_REPLICA_ENTRY"
    
    CERT_ID = db.Column(db.String(64, collation='gbk_chinese_ci'), primary_key=True, nullable=False, unique=True, index=True)
    SIGNATURE = db.Column(db.String(16, collation='gbk_chinese_ci'))
    ISSUER_CN = db.Column(db.String(128, collation='utf8mb4_unicode_ci'))
    ISSUER_ORG = db.Column(db.String(128, collation='utf8mb4_unicode_ci'))
    NOT_BEFORE = db.Column(db.String(32, collation='gbk_chinese_ci'))
    NOT_AFTER = db.Column(db.String(32, collation='gbk_chinese_ci'))

    SUBJECT = db.Column(db.JSON, nullable=False)
    KEY_ALG = db.Column(db.String(16, collation='gbk_chinese_ci'))
    KEY_ID = db.Column(db.String(64, collation='gbk_chinese_ci'))
    POLICY = db.Column(db.String(128, collation='gbk_chinese_ci'))


    # def to_json(self):
    #     return {
    #         'cert_id': self.CERT_ID,
    #         'cert_type': self.CERT_TYPE,
    #         'subject_cn': self.SUBJECT_CN,
    #         'issuer_cn': self.ISSUER_CN,
    #         'issuer_org': self.ISSUER_ORG,
    #         'issuer_country': self.ISSUER_COUNTRY,
    #         'key_size': self.KEY_SIZE,
    #         'key_type': self.KEY_TYPE,
    #         'not_valid_before_utc': self.NOT_VALID_BEFORE,
    #         'not_valid_after_utc': self.NOT_VALID_AFTER,
    #         'validation_period': self.VALIDATION_PERIOD,
    #         'fingerprint': self.FINGERPRINT
    #     }

    # def get_raw(self):
    #     return {
    #         'cert_id': self.CERT_ID,
    #         'raw': self.CERT_RAW
    #     }
    
    def get_id(self):
        return str(self.CERT_ID)

    def __repr__(self):
        return f"<CertificateReplicaEntry {self.CERT_ID}>"
