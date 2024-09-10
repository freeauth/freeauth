<template>
  <el-container class="login-container">
    <div class="block">
      
     
        <img  class="svg-placeholder"  :src="require('../../assets/mail_logo.svg')" alt="Mail Icon">
      
      <div class="inter-box">
        
        <el-form @submit.prevent="handleLogin" ref="loginForm" :model="credentials" class="login-form">
          <div class="form-item">
            <h1>Login</h1> 
          </div>
          <div class="form-item">
            <label for="username" class="form-label">Username</label>
            <el-form-item prop="username">
              <el-input id="username" v-model="credentials.username" autocomplete="username"></el-input>
            </el-form-item>
          </div>
          <div class="form-item">
            <label for="password" class="form-label">Password</label>
            <el-form-item prop="password">
            <el-input id="password" type="password" v-model="credentials.password" autocomplete="current-password" ></el-input>
            </el-form-item>
            <div class="forgot-password">
              <el-link @click="forgotPassword">Forgot Password?</el-link>
            </div>
          </div>
          <el-form-item>
            <el-button type="primary" class="login-button" @click="handleLogin">Login</el-button>
          </el-form-item>
          <el-form-item>
            <el-button  class="login-button" @click="navigateToRegister">Create New Account</el-button>
          </el-form-item>
        </el-form>
      </div>
    </div>
  </el-container>
</template>

<script>
export default {
  name: 'LoginPage',
  data() {
    return {
      credentials: {
        username: '',
        password: ''
      }
    };
  },
  methods: {
    handleLogin() {
      // 实现登录逻辑
      // if正确则跳转主页面,没写
      console.log('Login attempt with:', this.credentials);
    },
    navigateToRegister() {
      this.$router.push({ name: 'Register' });
    },
    forgotPassword() {
      // 导航到忘记密码页面或打开忘记密码对话框，没写
      console.log('Navigate to forgot password functionality');
    }
  }
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
  box-shadow: var(--el-box-shadow-light);
  height: 500px;
  width: 600px;
  margin: 0 auto; /* 水平居中 */
  background-color: #b9d7f4; /* 背景颜色 */
  border: 1px solid #ccc; /* 边框 */
  border-radius: 10px; /* 边框圆角 */
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); /* 阴影效果 */
  padding: 20px; /* 内边距 */
  font-size: 16px; /* 文字大小 */
  color: #333; /* 文字颜色 */
  font-weight: bold; /* 文字加粗 */
  text-align: center; /* 文字居中 */
}
.inter-box {
  position: absolute;
  background-color:white; 
  display: flex; /* 应用Flexbox布局 */
  justify-content:center; /* 水平居中 */
  align-items: center; /* 垂直居中 */
  border-radius: 8px;
  height: 350px;
  width: 590px; 
  margin-left:7px; 
}
.svg-placeholder {
  height: 70px; /* 或根据实际SVG图片的大小调整 */
  width: 70px;
  margin-top: 30px;
  margin-bottom: 30px; /* 与标题的间距 */
}

.form-item {
  margin-bottom: 20px; /* 表单项间距 */
}

.form-label {
  display: block;
  color: gray;
  text-align: left;
  font-size: 14px;
  margin-bottom: 5px;
}

.el-input {
  width:300px;
  border-color: #dcdfe6;
}

.el-input.is-success {
  border-color: #67c23a;
}

.el-input__suffix {
  color: #67c23a;
}

.login-button {
  width: 100%;
}

.register {
  text-align: right;
}
.forgot-password {
  text-align: right;
}
</style>
