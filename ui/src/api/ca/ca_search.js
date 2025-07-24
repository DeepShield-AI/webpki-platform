
import request from '@/utils/request'

export function searchCa(query) {
  return request({
    url: '/ca/ca_search/search',
    method: 'get',
    params: query
  })
}

export function getCaInfo(caId) {
  return request({
    url: '/ca/ca_retrieve/' + caId,
    method: 'get'
  })
}

export function getCaCag(caId) {
  return request({
    url: '/ca/ca_retrieve/' + caId + '/get_cag',
    method: 'get',
  })
}
