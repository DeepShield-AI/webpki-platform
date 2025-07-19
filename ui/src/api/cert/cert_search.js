
import request from '@/utils/request'

export function searchCert(query) {
  return request({
    url: '/cert/cert_search/search',
    method: 'get',
    params: query
  })
}

export function getCertInfo(certId) {
  return request({
    url: '/cert/cert_retrieve/' + certId,
    method: 'get'
  })
}

export function getCertDeployInfo(certId) {
  return request({
    url: '/cert/cert_retrieve/' + certId + '/deploy',
    method: 'get'
  })
}

export function getCertRevocationRecords(certId) {
  return request({
    url: '/cert/cert_retrieve/' + certId + '/revoke',
    method: 'get'
  })
}

export function checkRevoke(type, certId, distPoint) {
  return request({
    url: '/cert/cert_retrieve/' + certId + '/get_revoke',
    method: 'get',
    params: {
      "type" : type,
      "dist_point" : distPoint
    }
  })
}

export function getCertCag(certId) {
  return request({
    url: '/cert/cert_retrieve/' + certId + '/get_cag',
    method: 'get',
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

