<template>
  <el-container class="login-container">
    <div class="block">
      <div style="display: flex; align-items: center;justify-content: center;margin-bottom: 20px;">
        <img class="svg-placeholder" :src="require('@/assets/mail_logo.svg')" alt="Mail Icon">
        <h1 style="margin-left:5px;">FreeAuth: Email Verification Demo</h1>
      </div>
      <div style=" align-items: center">
        <emailAuth v-if="curPage == 0" @submit-success="handleSubmitSuccess" />
        <processDisplay v-if="curPage == 1" @verify-success="handleShowCredential" @verify-failed="handleGoBack"/>
        <showCredential v-if="curPage == 2" />
      </div>
    </div>
  </el-container>
</template>

<script>

import showCredential from '@/components/showCredential.vue';
import emailAuth from '@/components/emailAuth.vue'
import processDisplay from '@/components/processDisplay.vue'

import { ref } from 'vue';
export default {
  name: 'RegisterPage',
  setup() {
    const curPage = ref(0);
    const handleSubmitSuccess = () => {
      curPage.value = 1;
    }
    const handleShowCredential = () => {
      curPage.value = 2;
    }
    const handleGoBack = () => curPage.value = 0;
    return {
      handleSubmitSuccess,
      handleShowCredential,
      curPage,
      handleGoBack,
    }
  },
  components: {
    emailAuth,
    processDisplay,
    showCredential
  },
}


</script>

<style scoped>
.login-container {
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100vh;
}

.block {
  position: relative;
  margin: 0 auto;
  /* 水平居中 */
  font-size: 16px;
  /* 文字大小 */
  color: #333;
  /* 文字颜色 */
  font-weight: bold;
  /* 文字加粗 */
  text-align: center;
  /* 文字居中 */
}

.svg-placeholder {
  height: 55px;
  /* 或根据实际SVG图片的大小调整 */
  width: 55px;
  margin-top: 10px;
  margin-bottom: 10px;
  /* 与标题的间距 */
  /* margin-left: 100px; */

}

.register {
  text-align: right;
}
</style>
