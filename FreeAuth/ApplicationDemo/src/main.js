import { createApp } from 'vue'
import ElementPlus from 'element-plus'
import axios from 'axios'
import 'element-plus/dist/index.css'
import * as ElementPlusIconsVue from '@element-plus/icons-vue'
import vue3GoogleLogin from 'vue3-google-login'
import App from './App.vue'
import router from './router'
import store from './store'

const app=createApp(App);
for (const [key, component] of Object.entries(ElementPlusIconsVue)) {
    app.component(key, component)
}
app.use(router);
app.use(store);
app.use(ElementPlus);
app.use(vue3GoogleLogin, {
    clientId: '251431201738-lkd104nevk4fc22cqjccg90kpq78d6tu.apps.googleusercontent.com'
  });
app.config.globalProperties.$http=axios;
app.mount('#app');
