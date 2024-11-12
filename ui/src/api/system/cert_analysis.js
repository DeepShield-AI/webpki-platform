
import request from '@/utils/request'

export function listCertAnalysisResult(query) {
  return request({
    url: '/system/cert_analysis/list',
    method: 'get',
    params: query
  })
}

export function getDomainTrustRelation(query) {
  return request({
    url: '/system/cert_analysis/trust',
    method: 'get',
    params: query
  })
}
