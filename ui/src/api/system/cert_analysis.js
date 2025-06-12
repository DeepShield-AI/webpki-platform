
import request from '@/utils/request'

export function getCertSecurityStats(query) {
  return request({
    url: '/system/cert_analysis/cert_security_stats',
    method: 'get',
    params: query
  })
}


export function getTotalCerts(query) {
  return request({
    url: '/system/cert_analysis/certs_total',
    method: 'get',
    params: query
  })
}

export function getSubCag(query) {
  return request({
    url: '/system/cert_analysis/sub_cag',
    method: 'get',
    params: query
  })
}
