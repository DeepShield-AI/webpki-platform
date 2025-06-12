
import request from '@/utils/request'

export function getHostSecurityStats(query) {
  return request({
    url: '/system/host_analysis/host_security_stats',
    method: 'get',
    params: query
  })
}


export function getTotalHosts(query) {
  return request({
    url: '/system/host_analysis/hosts_total',
    method: 'get',
    params: query
  })
}
