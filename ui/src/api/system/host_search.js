
import request from '@/utils/request'

export function getHostInfo(host) {
  return request({
    url: '/system/host_retrieve/' + host,
    method: 'get'
  })
}
