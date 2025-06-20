
import request from '@/utils/request'

export function getHostSecurityStats(query) {
  return request({
    url: '/host/host_analysis/host_security_stats',
    method: 'get',
    params: query
  })
}


export function getTotalHosts(query) {
  return request({
    url: '/host/host_analysis/hosts_total',
    method: 'get',
    params: query
  })
}

export function getSubCag(query) {
  return request({
    url: '/host/host_analysis/sub_cag',
    method: 'get',
    params: query
  })
}
