
import request from '@/utils/request'

export function getCaStats(query) {
  return request({
    url: '/ca/ca_analysis/ca_stats',
    method: 'get',
    params: query
  })
}
