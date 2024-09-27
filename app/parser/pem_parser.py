# Use pem library to parse the certificates
# In case of any exception raised by cryptography library

import idna
import hashlib
from dataclasses import dataclass, asdict
from asn1crypto import pem, x509
from ..utils.cert import ordered_dict_to_dict

'''
    Keep the following infomation:
    tbs_certificate:
        ('signature', OrderedDict([('algorithm', 'sha256_rsa'), ('parameters', None)])), 
        ('issuer', OrderedDict([('country_name', 'US'), ('organization_name', "Let's Encrypt"), ('common_name', 'R3')])),
        ('validity', OrderedDict([('not_before', datetime.datetime(2023, 9, 22, 15, 2, 21, tzinfo=datetime.timezone.utc)), ('not_after', datetime.datetime(2023, 12, 21, 15, 2, 20, tzinfo=datetime.timezone.utc))])), 
        ('subject', OrderedDict([('common_name', '*.tsinghua.edu.cn')])),
        ('subject_public_key_info', OrderedDict([('algorithm', OrderedDict([('algorithm', 'rsa'), ('parameters', None)])),
        ('public_key', OrderedDict([('modulus', 730381675400275393179131451734351031023976797300948404760142786014857536852188944263899214555816536659341234870627048783657174590069418389311271920929996221489766888191628418376391708232217703009855101847069235933578181790566124224898469309988433269930367454893031276420210793234672320678387759884923506172748221954567624976924111337878225474241560033631876662221252576808398200682547205718993444835108538854588023920604740383030537224046475795008210044446465798111453877883423973179051416376926424134704068611211697276892251323662722719527201912163595631771246859597659816585112300947593433427797162884838138313424037677432167626450857533641520623554716829007584389117630184628349275940929011675161669795477833102073718221413712134865915775394279141639258803071738681262371631666357297503961454349044448349306949182013464689635818444961359944005142107622361029056560682343328762697366129057545410851472600995808378695732670120039375433615234028356821461694362520416896403856100239599465108935897082684042591922363518080804462002508981664835785142754464948733965351556365016476351203067850460795456406707171033163238228134103626125559722664014446757588531079133331427411022288703624343329986828517269220140774549010617459283278217843), ('public_exponent', 65537)]))])), 
        OrderedDict([('extn_id', 'key_identifier'), ('critical', False), ('extn_value', b'\x06l\r\xd0\xabA\xda\x11\xeb6a\xb5\xcf\x95\x0b\x0b"\x1c\xc8\xcb')]), 
        OrderedDict([('extn_id', 'authority_key_identifier'), ('critical', False), ('extn_value', OrderedDict([('key_identifier', b'\x14.\xb3\x17\xb7XV\xcb\xaeP\t@\xe6\x1f\xaf\x9d\x8b\x14\xc2\xc6'), ('authority_cert_issuer', None), ('authority_cert_serial_number', None)]))]), 
        OrderedDict([('extn_id', 'subject_alt_name'), ('critical', False), ('extn_value', ['*.card.tsinghua.edu.cn', '*.cic.tsinghua.edu.cn', '*.join-tsinghua.edu.cn', '*.net.edu.cn', '*.pt.tsinghua.edu.cn', '*.sem.tsinghua.edu.cn', '*.sysc.tsinghua.edu.cn', '*.syx.thcic.cn', '*.thcic.cn', '*.tsinghua.edu.cn', '*.tsinghua.org.cn', '*.zgclab.edu.cn'])]), 
        OrderedDict([('extn_id', 'certificate_policies'), ('critical', False), ('extn_value', [OrderedDict([('policy_identifier', '2.23.140.1.2.1'), ('policy_qualifiers', None)])])]), 
'''
@dataclass
class PEMResult():
    sha256 : str
    signature : str
    issuer_cn : str
    issuer_org : str
    not_before : str
    not_after : str
    subject : list
    pub_key_alg : str
    pub_key_id : str
    pub_key : dict
    policy : str


class PEMParser():

    def __init__(self) -> None:
        pass

    @classmethod
    def parse_native(self, pem_str : str):
        
        pem_bytes_str = pem_str.encode('utf-8')
        if pem.detect(pem_bytes_str):
            type_name, headers, der_bytes = pem.unarmor(pem_bytes_str)
            cert = x509.Certificate.load(der_bytes)
            return cert.native

    @classmethod
    def parse_native_pretty(self, pem_str : str):
        return ordered_dict_to_dict(self.parse_native(pem_str))

    @classmethod
    def parse_pem_cert(self, pem_str : str):

        pem_bytes_str = pem_str.encode('utf-8')
        sha256_hash = hashlib.sha256()
        sha256_hash.update(pem_bytes_str)

        if pem.detect(pem_bytes_str):
            type_name, headers, der_bytes = pem.unarmor(pem_bytes_str)
            cert = x509.Certificate.load(der_bytes)

            subject = []
            pub_key_id = b''
            policy = ''
            subject.append(cert['tbs_certificate']['subject'].native.get('common_name', None))
            extensions = cert['tbs_certificate']['extensions']

            for ext in extensions:
                ext_id = ext['extn_id'].native

                if ext_id == 'subject_alt_name':
                    try:
                        subject += ext['extn_value'].native
                        # print(subject)
                    except UnicodeError:
                        # print(ext['extn_value'])
                        # subject += [idna.encode(domain_unicode) for domain_unicode in ext['extn_value'].native]
                        pass

                if ext_id == 'key_identifier':
                    pub_key_id = ext['extn_value'].native
                    # print(pub_key_id)
                if ext_id == 'certificate_policies':
                    policy = ext['extn_value'].native[0].get('policy_identifier', None)
                    # print(policy)

            pem_result = PEMResult(
                sha256_hash.hexdigest(),
                cert['tbs_certificate']['signature']['algorithm'].native,
                cert['tbs_certificate']['issuer'].native.get('common_name', None),
                cert['tbs_certificate']['issuer'].native.get('organization_name', None),
                cert['tbs_certificate']['validity']['not_before'].native.strftime("%Y-%m-%d-%H-%M-%S"),
                cert['tbs_certificate']['validity']['not_after'].native.strftime("%Y-%m-%d-%H-%M-%S"),
                subject,
                cert['tbs_certificate']['subject_public_key_info']['algorithm']['algorithm'].native,
                pub_key_id.hex(),
                ordered_dict_to_dict(cert['tbs_certificate']['subject_public_key_info']['public_key'].native),
                policy
            )

            return pem_result
        
    @classmethod
    def parse_pem_cert_as_json(self, pem_str : str):
        return asdict(self.parse_pem_cert(pem_str))

    @classmethod
    def convert_pem_result_to_json(self, pem_result : PEMResult):
        return asdict(pem_result)
