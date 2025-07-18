#!/bin/bash

source ../myenv/bin/activate
python3 3rd/test_cert_1.py supplement/cert/expired_leaf.pem
python3 3rd/test_cert_1.py supplement/cert/self_signed.pem
