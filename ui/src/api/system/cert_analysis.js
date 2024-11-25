
import request from '@/utils/request'

export function getWebAnalysisResult(query) {
  return request({
    url: '/system/web_analysis',
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
