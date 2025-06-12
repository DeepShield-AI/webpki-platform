
import request from '@/utils/request'

// export function listCert(query) {
//   return request({
//     url: '/system/cert_search/list',
//     method: 'get',
//     params: query
//   })
// }


export function getCertInfo(certSha256) {
  return request({
    url: '/system/cert_retrieve/' + certSha256,
    method: 'get'
  })
}


// export function getCertZlintInfo(certId) {
//   return request({
//     url: '/system/zlint/' + certId,
//     method: 'get'
//   })
// }


// export function getCertChain(query) {
//   return request({
//     url: '/system/build_cert_chain/',
//     method: 'get',
//     params: query
//   })
// }

