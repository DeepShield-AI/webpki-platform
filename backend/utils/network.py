
import dns.resolver
from typing import Dict, Tuple, List
from ..logger.logger import primary_logger

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
        # the thu server behaves really badly on resolving dns...
        lifetime : float = 20.0,
        timeout : float = 10.0
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
            primary_logger.debug(f"No {record_type} record found for {host}.")
        except dns.resolver.NXDOMAIN as e:
            primary_logger.warning(f"{host} does not exist: {e}")
        except dns.resolver.Timeout:
            # my_logger.warning(f"DNS query for {host} timed out.")
            primary_logger.debug(f"DNS query for {host} timed out.")
        except dns.resolver.NoNameservers:
            primary_logger.warning(f"No DNS servers available to resolve {host}.")
        except dns.resolver.NoAnswer:
            primary_logger.debug(f"No DNS records found for {host}")
        except Exception as e:
            primary_logger.debug(f"Error: {e}")
    return record_result


def resolve_host_dns(
        host : str = "www.tsinghua.edu.cn",
        dns_servers = [
            '114.114.114.114',
            '114.114.115.115',
            '1.1.1.1',  # Cloudflare DNS
            '8.8.8.8',  # Google DNS
            '9.9.9.9',  # Quad9 DNS
            '223.5.5.5',
            '11.11.1.2',
            '11.11.1.1',
            '11.11.1.3'
        ],
        lifetime : float = 20.0,
        timeout : float = 10.0
) -> tuple[list, list]:
    
    record_dict = get_host_dns_records(host, dns_servers, ['A', 'AAAA'], lifetime, timeout)
    return (record_dict['A'], record_dict['AAAA'])
