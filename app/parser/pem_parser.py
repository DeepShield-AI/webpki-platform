# Use pem library to parse the certificates
# In case of any exception raised by cryptography library


from asn1crypto import pem, x509

certs = []
with open(r'../../test/test_certs/tsinghua.edu.cn_single.pem', 'rb') as f:
    der_bytes = f.read()
    if pem.detect(der_bytes):
        type_name, headers, der_bytes = pem.unarmor(der_bytes)

cert = x509.Certificate.load(der_bytes)
print(cert.native)

#     for type_name, headers, der_bytes in pem.unarmor(f.read(), multiple=True):
#         certs.append(x509.Certificate.load(der_bytes))
# print(certs)
