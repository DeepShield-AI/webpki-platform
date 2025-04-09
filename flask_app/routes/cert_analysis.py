
import json
import subprocess
from ..blueprint import base
from ..models import CertAnalysisStats, CertChainRelation, DomainTrustRelation
from datetime import datetime
from flask_app import Blueprint, jsonify, request
from flask_login import login_required, current_user
from ..logger.logger import primary_logger

PYTHON_PATH = r"/root/pki-internet-platform/myenv/bin/python3"

@base.route('/system/web_analysis', methods=['GET'])
@login_required
def web_analysis():
    domain = request.args.get('domain').strip()
    if not domain:
        return jsonify({'msg': '域名不能为空', 'code': 400})
    
    try:
        command = [
            PYTHON_PATH, "-m",
            "sslyze",
            # "--json_out=-",  # 输出 JSON 格式到标准输出
            domain
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        analysis_data = json.loads(result.stdout)
        return jsonify({'msg': '操作成功', 'code': 200, "data": analysis_data})

    except subprocess.CalledProcessError as e:
        return jsonify({'msg': f"SSLyze 执行错误: {e.stderr}", 'code': 500})
    except json.JSONDecodeError:
        return jsonify({'msg': "解析 SSLyze 输出时出错", 'code': 500})
    

@base.route('/system/cert_analysis/timeline', methods=['GET'])
@login_required
def get_domain_trust_timeline():

    root_domain = request.args.get('rootDomain', '')
    date_time_str = request.args.get('selectedDate', '')

    # Parse date_time to datetime object if provided
    date_time = None
    if date_time_str:
        try:
            date_time = datetime.strptime(date_time_str, '%Y-%m-%d')  # Adjust the format as necessary
        except ValueError:
            # Handle invalid date format
            pass

    # Set up filters
    filters = []
    if root_domain:
        filters.append(DomainTrustRelation.DOMAIN.like(f'%.{root_domain}'))
    if date_time:
        filters.append(DomainTrustRelation.NOT_VALID_BEFORE <= date_time)
        filters.append(DomainTrustRelation.NOT_VALID_AFTER >= date_time)

    # Query with filters
    domain_group = DomainTrustRelation.query.filter(*filters).all()

    # Check if the number of matching items exceeds 500
    if len(domain_group) > 500:
        return jsonify({'code': 200, 'msg': "Too many matching items. Please refine your search."})

    # Step 2: Extract all DOMAIN and CERT_ID values from the query results
    domains = [item.DOMAIN for item in domain_group]
    cert_ids = [item.CERT_ID for item in domain_group]

    # Step 3: Query CertChainRelation using the CERT_IDs to get CERT_PARENT_IDs
    cert_parent_ids = CertChainRelation.query.filter(
        CertChainRelation.CERT_ID.in_(cert_ids)
    ).with_entities(CertChainRelation.CERT_ID, CertChainRelation.CERT_PARENT_ID).all()

    cert_parent_map = {}
    for cert_id, parent_id in cert_parent_ids:
        if cert_id not in cert_parent_map:
            cert_parent_map[cert_id] = []
        cert_parent_map[cert_id].append(parent_id)

    # `domains` now contains all DOMAINs
    # `cert_parent_ids` contains all CERT_PARENT_IDs corresponding to the CERT_IDs from DomainTrustRelation
    # build result
    data = []
    for i in range(len(domains)):
        data.append({
            "domain": domains[i],
            "cert_id": cert_ids[i]
        })

    # 生成 Graph 数据结构
    graph_data = {"links": [], "nodes": []}

    # 生成 nodes 部分
    for item in data:
        domain_node = {
            "id": item["domain"],
            "root": "true" if item["domain"] == root_domain else "false",
            "status": "Good",
            "type": "domain"
        }
        cert_node = {
            "id": item["cert_id"],
            "type": "certificate"
        }
        if domain_node not in graph_data["nodes"]:
            graph_data["nodes"].append(domain_node)
        if cert_node not in graph_data["nodes"]:
            graph_data["nodes"].append(cert_node)

    for child, parents in cert_parent_map:
        cert_node = {
            "id": item["cert_id"],
            "type": "certificate"
        }
        parent_cert_node = {
            "id": item["parent_id"],
            "type": "certificate"
        }
        if cert_node not in graph_data["nodes"]:
            graph_data["nodes"].append(cert_node)
        if parent_cert_node not in graph_data["nodes"]:
            graph_data["nodes"].append(parent_cert_node)


    # 生成 links 部分
    for item in data:
        uses_link = {
            "source": item["domain"],
            "target": item["cert_id"],
            "type": "uses"
        }
        sans_link = {
            "source": item["cert_id"],
            "target": item["domain"],
            "type": "sans"
        }
        if uses_link not in graph_data["links"]:
            graph_data["links"].append(uses_link)
        if sans_link not in graph_data["links"]:
            graph_data["links"].append(sans_link)

    for child, parents in cert_parent_map:
        chain_link = {
            "source": item["parent_id"],
            "target": item["cert_id"],
            "type": "uses"
        }
        if chain_link not in graph_data["links"]:
            graph_data["links"].append(chain_link)



    print(json.dumps(graph_data, indent=4))
    return jsonify({'msg': '操作成功', 'code': 200, "data": graph_data})






@base.route('/system/cert_analysis/trust', methods=['GET'])
@login_required
def get_root_trust_tree():

    root_domain = request.args.get('rootDomain', '')
    date_time_str = request.args.get('selectedDate', '')

    # Parse date_time to datetime object if provided
    date_time = None
    if date_time_str:
        try:
            date_time = datetime.strptime(date_time_str, '%Y-%m-%d')  # Adjust the format as necessary
        except ValueError:
            # Handle invalid date format
            pass

    # Set up filters
    filters = []
    if root_domain:
        filters.append(DomainTrustRelation.DOMAIN.like(f'%.{root_domain}'))
    if date_time:
        filters.append(DomainTrustRelation.NOT_VALID_BEFORE <= date_time)
        filters.append(DomainTrustRelation.NOT_VALID_AFTER >= date_time)

    # Query with filters
    domain_group = DomainTrustRelation.query.filter(*filters).all()

    # Check if the number of matching items exceeds 500
    if len(domain_group) > 500:
        return jsonify({'code': 200, 'msg': "Too many matching items. Please refine your search."})

    # Step 2: Extract all DOMAIN and CERT_ID values from the query results
    domains = [item.DOMAIN for item in domain_group]
    cert_ids = [item.CERT_ID for item in domain_group]

    # Step 3: Query CertChainRelation using the CERT_IDs to get CERT_PARENT_IDs
    cert_parent_ids = CertChainRelation.query.filter(
        CertChainRelation.CERT_ID.in_(cert_ids)
    ).with_entities(CertChainRelation.CERT_ID, CertChainRelation.CERT_PARENT_ID).all()

    cert_parent_map = {}
    for cert_id, parent_id in cert_parent_ids:
        if cert_id not in cert_parent_map:
            cert_parent_map[cert_id] = []
        cert_parent_map[cert_id].append(parent_id)

    # `domains` now contains all DOMAINs
    # `cert_parent_ids` contains all CERT_PARENT_IDs corresponding to the CERT_IDs from DomainTrustRelation
    # build result
    data = []
    for i in range(len(domains)):
        data.append({
            "domain": domains[i],
            "cert_id": cert_ids[i]
        })

    # 生成 Graph 数据结构
    graph_data = {"links": [], "nodes": []}

    # 生成 nodes 部分
    for item in data:
        domain_node = {
            "id": item["domain"],
            "root": "true" if item["domain"] == root_domain else "false",
            "status": "Good",
            "type": "domain"
        }
        cert_node = {
            "id": item["cert_id"],
            "type": "certificate"
        }
        if domain_node not in graph_data["nodes"]:
            graph_data["nodes"].append(domain_node)
        if cert_node not in graph_data["nodes"]:
            graph_data["nodes"].append(cert_node)

    for item in trust_relation:
        cert_node = {
            "id": item["cert_id"],
            "type": "certificate"
        }
        parent_cert_node = {
            "id": item["parent_id"],
            "type": "certificate"
        }
        if cert_node not in graph_data["nodes"]:
            graph_data["nodes"].append(cert_node)
        if parent_cert_node not in graph_data["nodes"]:
            graph_data["nodes"].append(parent_cert_node)


    # 生成 links 部分
    for item in data:
        uses_link = {
            "source": item["domain"],
            "target": item["cert_id"],
            "type": "uses"
        }
        sans_link = {
            "source": item["cert_id"],
            "target": item["domain"],
            "type": "sans"
        }
        if uses_link not in graph_data["links"]:
            graph_data["links"].append(uses_link)
        if sans_link not in graph_data["links"]:
            graph_data["links"].append(sans_link)

    for item in trust_relation:
        chain_link = {
            "source": item["parent_id"],
            "target": item["cert_id"],
            "type": "uses"
        }
        if chain_link not in graph_data["links"]:
            graph_data["links"].append(chain_link)



    print(json.dumps(graph_data, indent=4))
    return jsonify({'msg': '操作成功', 'code': 200, "data": graph_data})
