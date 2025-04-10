
from ..blueprint import base
from ..models import ScanStatus
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from requests import Request
import threading
from backend.utils.type import ScanType
from backend.config.scan_config import ScanConfig, InputScanConfig, CTScanConfig

def create_scan_config_from_frontend_request(request: Request, scan_type: ScanType) -> ScanConfig:
    common_args = {
        'scan_process_name': request.json.get('scan_process_name'),
        'storage_dir': request.json.get('storage_dir'),
        'max_threads_alloc': int(request.json.get('max_threads_alloc')),
        'thread_workload': int(request.json.get('thread_workload')),
        'scan_timeout': int(request.json.get('scan_timeout')),
        'max_retry': int(request.json.get('max_retry')),
        'proxy_host': request.json.get('proxy_host', '127.0.0.1'),
        'proxy_port': int(request.json.get('proxy_port', 33210)),
    }
    if scan_type == ScanType.SCAN_BY_INPUT:
        return InputScanConfig(
            **common_args,
            input_domain_list_file=request.json.get('input_domain_list_file'),
            domain_index_start=int(request.json.get('domain_index_start', 0)),
            num_domain_scan=int(request.json.get('num_domain_scan', 100)),
        )
    elif scan_type == ScanType.SCAN_BY_CT:
        return CTScanConfig(
            **common_args,
            ct_log_name=request.json.get('ct_log_name'),
            ct_log_address=request.json.get('ct_log_address'),
            entry_start=int(request.json.get('entry_start', 0)),
            entry_end=int(request.json.get('entry_end', 1000)),
            window_size=int(request.json.get('window_size', 10)),
        )
    else:
        raise ValueError(f"Unsupported scan_type: {scan_type}")

@base.route('/system/scan_process/list', methods=['GET'])
@login_required
def scan_process_list():
    # build db select filter from search options
    # note options might not exist, so do check for any exceptions
    filters = []
    if 'scanProcessName' in request.args:
        filters.append(ScanStatus.NAME.like('%' + request.args['scanProcessName'] + '%'))
    if 'scanStatus' in request.args:
        filters.append(ScanStatus.STATUS == request.args['scanStatus'])
    if 'params[beginTime]' in request.args:
        filters.append(ScanStatus.START_TIME >= request.args['params[beginTime]'])
    if 'params[endTime]' in request.args:
        filters.append(ScanStatus.START_TIME <= request.args['params[endTime]'])
        # both are ok
        # scan_date = datetime.strptime(request.args['params[endTime]'], '%Y-%m-%d')
        # filters.append(func.DATE(ScanStatus.START_TIME) <= scan_date.date())

    data = {}
    total = {}
    filters.append(None)
    for value in ScanType.__members__.values():
        data[value.value] = []
        total[value.value] = 0

    for value in ScanType.__members__.values():
        page = request.args.get(f'pageNum[{value.value}]', 1, type=int)
        rows = request.args.get('pageSize', 10, type=int)
        filters[-1] = ScanStatus.TYPE == value.value
        pagination = ScanStatus.query.filter(*filters).paginate(
            page=page, per_page=rows, error_out=False)

        scan_processes = pagination.items
        for scan_process in scan_processes:
            data[value.value].append(scan_process.to_json())
            total[value.value] += 1

    return jsonify({'msg': '操作成功', 'code': 200, "data": data, 'total': total})


@base.route('/system/scan_process', methods=['POST'])
@login_required
def scan_process_start():

    scan_type = ScanType(int(request.json['scanType']))
    config = create_scan_config_from_frontend_request(request, scan_type)
    # task_id = manager.register(config)
    # threading.Thread(target=manager.start, args=(task_id,)).start()
    return jsonify({'code': 200, 'msg': '操作成功'})
