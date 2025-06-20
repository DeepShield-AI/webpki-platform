
import request from '@/utils/request'

export function getCertSecurityStats(query) {
  return request({
    url: '/cert/cert_analysis/cert_security_stats',
    method: 'get',
    params: query
  })
}


export function getTotalCerts(query) {
  return request({
    url: '/cert/cert_analysis/certs_total',
    method: 'get',
    params: query
  })
}

