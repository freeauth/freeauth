import { createRouter, createWebHashHistory } from 'vue-router'
// import LoginView from '@/views/Login/index.vue'
import RgisterView from '@/views/Register/index.vue'

const routes = [
  {
    path: '/',
    name: 'root',
    component: RgisterView
  },
  {
    path: '/UserLogin',
    name: 'login',
  },
  {
    path: '/Register',
    name: 'Register',
    component: RgisterView
  },
]

const router = createRouter({
  history:createWebHashHistory(),
  routes
})

export default router
