
import json
from ..blueprint import base
from ..models import CertAnalysisStats, CertChainRelation, DomainTrustRelation
from datetime import datetime
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from ..logger.logger import my_logger


@base.route('/system/cert_analysis/list', methods=['GET'])
@login_required
def cert_analysis_list():

    # my_logger.info(f"{request.args}")
    filters = []
    if 'name' in request.args:
        filters.append(CertAnalysisStats.SCAN_ID.like('%' + request.args['name'] + '%'))
    cert_analysis_stats = CertAnalysisStats.query.filter(*filters)

    return jsonify({'msg': '操作成功', 'code': 200, "data": [cert_analysis_stat.metadata_to_json() for cert_analysis_stat in cert_analysis_stats]})


@base.route('/system/cert_analysis/trust', methods=['GET'])
@login_required
def get_root_trust_tree():

    print(request.args)

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

    # Step 2: Extract all DOMAIN and CERT_ID values from the query results
    domains = [item.DOMAIN for item in domain_group]
    cert_ids = [item.CERT_ID for item in domain_group]

    # Step 3: Query CertChainRelation using the CERT_IDs to get CERT_PARENT_IDs
    cert_parent_ids = CertChainRelation.query.filter(
        CertChainRelation.CERT_ID.in_(cert_ids)
    ).with_entities(CertChainRelation.CERT_PARENT_ID).all()

    # Optional: Flatten the CERT_PARENT_ID list if you need it in a simple list format
    cert_parent_ids = [parent_id[0] for parent_id in cert_parent_ids]

    # `domains` now contains all DOMAINs
    # `cert_parent_ids` contains all CERT_PARENT_IDs corresponding to the CERT_IDs from DomainTrustRelation
    # build result
    data = []
    for i in range(len(domains)):
        data.append({
            "domain": domains[i],
            "cert_id": cert_ids[i],
            # "parent_id": cert_parent_ids[i]
        })

    # 生成 Graph 数据结构
    graph_data = {"links": [], "nodes": []}

    # 生成 nodes 部分
    domain_status = {"Good": ["domain"], "No Host": ["domain"]}  # 可根据需要扩展 status
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

    print(json.dumps(graph_data, indent=4))
    return jsonify({'msg': '操作成功', 'code': 200, "data": graph_data})
