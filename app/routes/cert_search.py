
import json
import tempfile
import subprocess
from ..blueprint import base
from ..models import CertStoreContent, CertScanMeta, CertStore
from ..config.analysis_config import ZLINT_PATH
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from ..parser.cert_parser_base import X509CertParser
from ..parser.pem_parser import PEMParser
from ..logger.logger import my_logger
from ..analyzer.cert_analyze_chain import CertScanChainAnalyzer


@base.route('/system/cert_search/list', methods=['GET'])
@login_required
def cert_search_list():
    my_logger.info(f"{request.args}")

    filters = []
    if 'certID' in request.args:
        filters.append(CertStore.CERT_ID == request.args['certID'])

    # if 'certID' in request.args:
    #     filters.append(CertStoreContent.CERT_ID == request.args['certID'])
    # if 'certDomain' in request.args:
    #     # filters.append(CertStoreContent.SUBJECT_CN == request.args['certDomain'])
    #     filters.append(CertStoreContent.SUBJECT_CN.like('%' + request.args['certDomain'] + '%'))

    # if 'params[beginNotValidBefore]' in request.args and 'params[endNotValidBefore]' in request.args:
    #     filters.append(CertStoreContent.NOT_VALID_BEFORE >= request.args['params[beginNotValidBefore]'])
    #     filters.append(CertStoreContent.NOT_VALID_BEFORE <= request.args['params[endNotValidBefore]'])
    # if 'params[beginNotValidAfter]' in request.args and 'params[beginNotValidAfter]' in request.args:
    #     filters.append(CertStoreContent.NOT_VALID_AFTER >= request.args['params[beginNotValidAfter]'])
    #     filters.append(CertStoreContent.NOT_VALID_AFTER <= request.args['params[beginNotValidAfter]'])

    # combined_query : Query
    # combined_query = union(cert_store_query, cert_scan_query)

    page = request.args.get('pageNum', 1, type=int)
    rows = request.args.get('pageSize', 30, type=int)
    pagination = CertStore.query.filter(*filters).paginate(
        page=page, per_page=rows, error_out=False)
    search_certs = pagination.items

    return jsonify({'msg': '操作成功', 'code': 200, "data": [search_cert.to_json() for search_cert in search_certs], "total" : pagination.total})


@base.route('/system/cert_retrive/<cert_id>', methods=['GET'])
@login_required
def get_cert_info(cert_id):

    cert_raw = CertStore.query.get(cert_id).get_raw()
    cert_parsed = PEMParser.parse_native_pretty(cert_raw)

    # filters = []
    # filters.append(CertScanMeta.CERT_ID == cert_id)
    # scan_metas = CertScanMeta.query.filter(*filters)

    return jsonify({'code': 200, 'msg': '操作成功', "cert_data" : cert_parsed, "scan_info" : []})
    # return jsonify({'code': 200, 'msg': '操作成功', "cert_data" : parser.to_json(), "scan_info" : [scan_meta.to_json() for scan_meta in scan_metas]})


@base.route('/system/zlint/<cert_id>', methods=['GET'])
@login_required
def get_cert_zlint(cert_id):

    cert_pem = CertStore.query.get(cert_id).get_raw()

    """
    调用 Zlint 验证证书。
    :param cert_pem: str, PEM 格式的证书字符串。
    :return: dict, Zlint 输出结果。
    """
    # 创建一个临时文件存储证书内容
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as temp_cert_file:
        temp_cert_file.write(cert_pem.encode())
        temp_cert_path = temp_cert_file.name

    try:
        # 调用 Zlint
        result = subprocess.run(
            [ZLINT_PATH, temp_cert_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # 检查是否有错误输出
        if result.returncode != 0:
            raise RuntimeError(f"Zlint error: {result.stderr.strip()}")

        # 解析 JSON 输出
        zlint_output = json.loads(result.stdout)

    finally:
        # 删除临时文件
        try:
            import os
            os.unlink(temp_cert_path)
        except OSError:
            pass

    return jsonify({'code': 200, 'msg': '操作成功', "zlint_result" : zlint_output})


@base.route('/system/build_cert_chain/', methods=['GET'])
@login_required
def get_cert_chain():
    pem_data = request.args.get('pemCert', '').strip()
    if not pem_data:
        return jsonify({'code': 400, 'msg': '缺少 PEM 数据'})
    try:
        analyzer = CertScanChainAnalyzer()
        pem_chain = analyzer.build_verified_chain(pem_data)
        parsed_chain = [PEMParser.parse_native_pretty(cert) for cert in pem_chain]

        my_logger.info(parsed_chain)
        return jsonify({'code': 200, 'msg': '操作成功', 'chain': parsed_chain})

    except ValueError as e:
        return jsonify({'code': 400, 'msg': f'证书处理错误: {str(e)}'})
    except TypeError as e:
        return jsonify({'code': 400, 'msg': f'未找到对应证书链', 'chain': None})
    except Exception as e:
        return jsonify({'code': 500, 'msg': f'内部错误: {str(e)}'})
