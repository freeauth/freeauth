import request from '@/utils/request'

export function login(username, password) {
  return request({
    url: '/api/login',
    method: 'post',
    data: {
      username,
      password
    }
  })
}

export function getRegisterInfo(info) {
  return request({
    url: '/api/emailVerification',
    method: 'post',
    data: {
      info
    },
    headers: {
      'Content-Type': 'application/json'
    }
  })
}

export function getProcessDisplay(){
  return request({
    url:'/api/process',
  method:'get',
  headers: {
    'Content-Type': 'application/json'
  }
  })
}
export function getProcessFlow(){
    return request({
    url:'/api/processFlow',
    method:'get',
    headers: {
      'Content-Type': 'application/json'
    }
    })
}

export function getCredentialInfo(){
  return request({
  url:'/api/getCredentialInfo',
  method:'get',
  headers: {
    'Content-Type': 'application/json'
  }
  })
}