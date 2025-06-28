
import request from '@/utils/request'

export function getHostInfo(host) {
  return request({
    url: '/host/host_retrieve/' + host,
    method: 'get'
  })
}
