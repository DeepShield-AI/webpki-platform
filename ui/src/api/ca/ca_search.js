
import request from '@/utils/request'

export function searchCa(query) {
  return request({
    url: '/ca/ca_search/search',
    method: 'get',
    params: query
  })
}

export function getCaInfo(caName) {
  return request({
    url: '/ca/ca_retrieve/' + caName,
    method: 'get'
  })
}
