import axios from 'axios'

// import store from '../store'

// 创建axios实例，构建了dev_server，以解决跨域问题
const service = axios.create({
  baseURL: '/api', // api的base_url
  timeout: 15000 // 请求超时时间
})

// request拦截器,对于oauth可以开启，处理来自网页服务器的复杂响应
// service.interceptors.request.use(config => {
// // 后续可添加消息头，其中包含用户token
//   return config
// }, error => {
//   // Do something with request error
//   console.log(error) // for debug
//   Promise.reject(error)
// })

// respone拦截器,对整体的响应错误进行拦截
// service.interceptors.response.use(
//   response => {
// //  登录响应错误抛错，根据响应的回复code判断
//     const res = response.data
//     if (res.status!=200 ) {
//       Message({
//         message: res.message,
//         type: 'error',
//         duration: 5 * 1000
//       })
//       return Promise.reject('error')
//     } else {
//       return response.data
//     }
//   },
//   error => {
//     console.log('err' + error)// for debug
//     Message({
//       message: error.message,
//       type: 'error',
//       duration: 5 * 1000
//     })
//     return Promise.reject(error)
//   }
// )

export default service
