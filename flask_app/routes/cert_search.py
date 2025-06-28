
import base64
import json, math
from datetime import datetime
from flask import jsonify, request, Response
from flask_login import login_required, current_user

from flask_app.blueprint import base
from flask_app.config.db_pool import engine_cert, engine_tls
from flask_app.logger.logger import flask_logger    

from backend.parser.pem_parser import PEMParser
from backend.analyzer.celery_cert_security_task import _cert_security_analyze

@base.route('/cert/cert_search/search', methods=['GET'])
@login_required
def cert_search():
    flask_logger.info(f"{request.args}")

    # 参数获取
    cert_sha256 = request.args.get('sha256', "")
    subject = request.args.get('subject', "")
    begin_not_valid_before = request.args.get('params[beginNotValidBefore]', "")
    end_not_valid_before = request.args.get('params[endNotValidBefore]', "")
    begin_not_valid_after = request.args.get('params[beginNotValidAfter]', "")
    end_not_valid_after = request.args.get('params[endNotValidAfter]', "")

    page = request.args.get('pageNum', 1, type=int)
    page_size = request.args.get('pageSize', 30, type=int)
    offset = (page - 1) * page_size

    where_clauses = []
    params = []

    if cert_sha256:
        where_clauses.append("sha256 = %s")
        params.append(cert_sha256)

    if subject:
        where_clauses.append("JSON_CONTAINS(subject_cn_list, '\"%s\"')" % subject)

    if begin_not_valid_before:
        where_clauses.append("not_valid_before >= %s")
        params.append(begin_not_valid_before)

    if end_not_valid_before:
        where_clauses.append("not_valid_before <= %s")
        params.append(end_not_valid_before)

    if begin_not_valid_after:
        where_clauses.append("not_valid_after >= %s")
        params.append(begin_not_valid_after)

    if end_not_valid_after:
        where_clauses.append("not_valid_after <= %s")
        params.append(end_not_valid_after)

    where_sql = " AND ".join(where_clauses)
    if where_sql:
        where_sql = "WHERE " + where_sql

    conn = engine_cert.raw_connection()
    with conn.cursor() as cursor:
        # 总数
        count_query = f"SELECT COUNT(*) FROM cert_search_basic {where_sql}"
        cursor.execute(count_query, tuple(params))
        total = cursor.fetchone()[0]

        # 数据查询
        data_query = f"""
            SELECT * FROM cert_search_basic
            {where_sql}
            LIMIT %s OFFSET %s
        """
        cursor.execute(data_query, tuple(params + [page_size, offset]))
        rows = cursor.fetchall()

        columns = [desc[0] for desc in cursor.description]
        result = [dict(zip(columns, row)) for row in rows]

    return jsonify({
        'code': 200,
        'msg': 'success',
        'total': total,
        'data': result
    })

    '''
        TODO: for some tables that has complicated search queries, try to use Flask-SQLAlchemy
    '''

    # filters = []
    # if 'certID' in request.args:
    #     filters.append(CertStore.CERT_ID == request.args['certID'])

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

    # page = request.args.get('pageNum', 1, type=int)
    # rows = request.args.get('pageSize', 30, type=int)
    # pagination = CertStore.query.filter(*filters).paginate(
    #     page=page, per_page=rows, error_out=False)
    # search_certs = pagination.items

    # return jsonify({'msg': '操作成功', 'code': 200, "data": [search_cert.to_json() for search_cert in search_certs], "total" : pagination.total})


@base.route('/cert/cert_retrieve/<cert_sha256>', methods=['GET'])
@login_required
def get_cert_info(cert_sha256):

    flask_logger.info(f"{request.args}")

    conn = engine_cert.raw_connection()
    with conn.cursor() as cursor:
        query = """
            SELECT * FROM cert
            WHERE cert_hash = %s
        """
        cursor.execute(query, (cert_sha256,))
        row = cursor.fetchone()

    # print(row)
    if not row:
        return jsonify({'msg': 'No Such Cert', 'code': 404})

    cert_parsed = PEMParser.parse_native_pretty(row[1])
    analyze_result = _cert_security_analyze(row, "/")

    modulus = cert_parsed['tbs_certificate']['subject_public_key_info']['public_key']['modulus']
    modulus = hex(modulus).upper().replace('0X', '')
    cert_parsed['tbs_certificate']['subject_public_key_info']['public_key']['modulus'] = modulus

    def json_default(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode('utf-8')  # 将 bytes 转换为 Base64 编码的字符串
        if isinstance(obj, bytearray):
            return base64.b64encode(obj).decode('utf-8')

        # 可以扩展支持其他类型
        return str(obj)  # fallback: 转成字符串

    return Response(
        json.dumps({
            'msg': 'Success',
            'code': 200,
            'cert_data': cert_parsed,
            'cert_security': analyze_result
        }, default=json_default),
        mimetype='application/json'
    )

    # return jsonify({'msg': 'Success', 'code': 200, "cert_data": cert_parsed, "cert_security" : analyze_result})


# @deprecated
# @base.route('/cert/zlint/<cert_id>', methods=['GET'])
# @login_required
# def get_cert_zlint(cert_id):

#     cert_pem = CertStore.query.get(cert_id).get_raw()

#     """
#     调用 Zlint 验证证书。
#     :param cert_pem: str, PEM 格式的证书字符串。
#     :return: dict, Zlint 输出结果。
#     """
#     # 创建一个临时文件存储证书内容
#     with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as temp_cert_file:
#         temp_cert_file.write(cert_pem.encode())
#         temp_cert_path = temp_cert_file.name

#     try:
#         # 调用 Zlint
#         result = subprocess.run(
#             [ZLINT_PATH, temp_cert_path],
#             stdout=subprocess.PIPE,
#             stderr=subprocess.PIPE,
#             text=True
#         )

#         # 检查是否有错误输出
#         if result.returncode != 0:
#             raise RuntimeError(f"Zlint error: {result.stderr.strip()}")

#         # 解析 JSON 输出
#         zlint_output = json.loads(result.stdout)

#     finally:
#         # 删除临时文件
#         try:
#             import os
#             os.unlink(temp_cert_path)
#         except OSError:
#             pass

#     return jsonify({'code': 200, 'msg': '操作成功', "zlint_result" : zlint_output})

@base.route('/cert/cert_retrieve/<cert_sha256>/deploy', methods=['GET'])
@login_required
def get_cert_deploy_info(cert_sha256):

    flask_logger.info(f"{request.args}")

    conn = engine_tls.raw_connection()
    with conn.cursor() as cursor:
        query = """
            SELECT t.*
            FROM tlshandshake t
            JOIN (
                SELECT destination_host, destination_ip
                FROM tlshandshake
                WHERE JSON_CONTAINS(cert_hash_list, %s)
                GROUP BY destination_host, destination_ip
                LIMIT 200
            ) AS limited_hosts
            ON t.destination_host = limited_hosts.destination_host
            AND t.destination_ip = limited_hosts.destination_ip
            WHERE JSON_CONTAINS(t.cert_hash_list, %s);
        """
        cursor.execute(query, (json.dumps([cert_sha256]), json.dumps([cert_sha256])))
        rows = cursor.fetchall()

        print(rows)
        if not rows:
            return jsonify({'msg': 'No Host Found', 'code': 404})

        columns = [desc[0] for desc in cursor.description]
        result = [dict(zip(columns, row)) for row in rows]

    return jsonify({'msg': 'Success', 'code': 200, "deploy_hosts": result})
