
import dns.resolver
from typing import Dict, Tuple, List
from ..logger.logger import my_logger

def get_host_dns_records(
        host : str = "www.tsinghua.edu.cn",
        dns_servers = [
            '1.1.1.1',  # Cloudflare DNS
            '8.8.8.8',  # Google DNS
            '9.9.9.9',  # Quad9 DNS
        ],
        record_types = [
            'A',
            'AAAA',
            'CNAME',
        ],
        lifetime : float = 10.0,
        timeout : float = 2.0
    ) -> dict:

    resolver = dns.resolver.Resolver()
    resolver.nameservers = dns_servers
    resolver.timeout = timeout  # 单个查询的超时时间
    resolver.lifetime = lifetime  # 整个查询过程的最大时长
    record_types = record_types

    record_result = {}
    for record_type in record_types:
        try:
            record_result[record_type] = []
            answer = resolver.resolve(host, record_type)
            for rdata in answer:
                record_result[record_type].append(rdata.address)
        except dns.resolver.NoAnswer:
            # my_logger.warning(f"No {record_type} record found for {host}.")
            my_logger.debug(f"No {record_type} record found for {host}.")
        except dns.resolver.NXDOMAIN:
            my_logger.warning(f"{host} does not exist.")
        except dns.resolver.Timeout:
            # my_logger.warning(f"DNS query for {host} timed out.")
            my_logger.debug(f"DNS query for {host} timed out.")
        except dns.resolver.NoNameservers:
            my_logger.warning(f"No DNS servers available to resolve {host}.")
        except dns.resolver.NoAnswer:
            my_logger.debug(f"No DNS records found for {host}")
        except Exception as e:
            my_logger.debug(f"Error: {e}")
    return record_result


def resolve_host_dns(
        host : str = "www.tsinghua.edu.cn",
        dns_servers = [
            '1.1.1.1',  # Cloudflare DNS
            '8.8.8.8',  # Google DNS
            '9.9.9.9',  # Quad9 DNS
        ],
        lifetime : float = 10.0,
        timeout : float = 5.0
) -> tuple[list, list]:
    
    record_dict = get_host_dns_records(host, dns_servers, ['A', 'AAAA'], lifetime, timeout)
    return (record_dict['A'], record_dict['AAAA'])
