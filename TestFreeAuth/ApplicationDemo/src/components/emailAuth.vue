<template>
  <div class="inter-box">
    <el-form @submit.prevent="handleSubmit" :rules="rules" ref="registerForm" :model="credentials">
      <div>
        <span class="form-header">Email Info</span>
        <el-divider style="margin-top: 3px;"></el-divider>
      </div>
      <div class="form-item" style="display: flex; justify-content: space-between;">
        <div>
          <label for="email" class="form-label"> Email Address</label>
          <el-form-item prop="email">
            <el-input id="email" v-model="credentials.email"></el-input>
          </el-form-item>
        </div>
        <div style="margin-left: 20px;">
          <label for="code" class="form-label">Auth Code</label>
          <el-form-item prop="code">
            <el-input id="code" v-model="credentials.code"></el-input>
            <el-tooltip placement="top">
              <template #content>OAuth2 authentication method<br />should be left empty</template>
              <el-icon style="margin-left: 6px;">
                <QuestionFilled />
              </el-icon>
            </el-tooltip>
          </el-form-item>
        </div>
      </div>

      <div>
        <span class="form-header">SMTP Server</span>
        <el-divider style="margin-top: 3px;"></el-divider>
      </div>

      <div class="form-item" style="display: flex; justify-content: space-between;">
        <div>
          <label for="hostname" class="form-label">Hostname</label>
          <el-form-item prop="hostname">
            <el-input id="hostname" style="width: 380px;" v-model="credentials.hostname"></el-input>
          </el-form-item>
        </div>
        <div>
          <label for="port" class="form-label">Port</label>
          <el-form-item class="form-input" prop="port">
            <el-input-number style="width: 100px;" v-model="credentials.port" :min="1" :max="65535"
              controls-position="right" />
          </el-form-item>
        </div>
      </div>
      <div class="form-item" style="display: flex; justify-content: space-between;">
        <div>
          <label for="connectmethod" class="form-label">Connect Security</label>
          <el-form-item prop="connectmethod">
            <el-select class='el-select' v-model="credentials.connectmethod">
              <el-option v-for="item in securityOptions" :key="item.value" :label="item.label" :value="item.value" />
            </el-select>
          </el-form-item>
        </div>
        <div>
          <label for="authmethod" class="form-label">Authentication Method</label>
          <el-form-item prop="authmethod">
            <el-select class='el-select' v-model="credentials.authmethod">
              <el-option v-for="item in authOptions" :key="item.value" :label="item.label" :value="item.value" />
            </el-select>
          </el-form-item>
        </div>
      </div>

      <div>
        <span class="form-header">FreeAuth Verifier Server</span>
        <el-divider style="margin-top: 3px;"></el-divider>
      </div>

      <div class="form-item" style="display: flex; justify-content: space-between;">
        <div>
          <label for="v_hostname" class="form-label">Verifier Address</label>
          <el-form-item prop="v_hostname">
            <el-input id="v_hostname" style="width: 380px;" v-model="credentials.v_hostname"></el-input>
          </el-form-item>
        </div>
        <div>
          <label for="v_port" class="form-label">Verifier Port</label>
          <el-form-item class="form-input" prop="v_port">
            <el-input-number style="width: 100px;" v-model="credentials.v_port" :min="1" :max="65535"
              controls-position="right" />
          </el-form-item>
        </div>
      </div>
      <el-button class="continue-button" @click="handleSubmit">Submit</el-button>
    </el-form>
  </div>
</template>
<script>

import { ref, reactive } from 'vue';
import { googleSdkLoaded } from "vue3-google-login"
import { ElLoading, ElMessage } from 'element-plus';

export default {
  setup(props, { emit }) {
    const credentials = reactive({
      email: '',
      code: '',
      port: 465,
      v_port: 18389,
      v_hostname: '127.0.0.1',
      connectmethod: 'TLS/SSL',
      authmethod: 'PLAIN',
    });
    let emailvalue = false;
    let loadingInstance = null;
    const validateEmail = (rule, value, callback) => {
      const regex = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
      if (!value || !regex.test(value)) {
        callback(new Error('Please input valid address'))
        emailvalue = false
        return false
      } else {
        callback();
        emailvalue = true
        credentials.hostname = 'smtp.' + value.split("@")[1]
        return true
      }
    };

    const rules = reactive({
      email: [
        { validator: validateEmail, trigger: 'blur' }
      ]
    });

    const securityOptions = ref([
      { value: 'TLS/SSL', label: 'TLS/SSL' },
      // { value: 'STARTTLS', label: 'STARTTLS' }
    ]);

    const authOptions = ref([
      { value: 'LOGIN', label: 'LOGIN' },
      { value: 'PLAIN', label: 'PLAIN' },
      { value: 'OAuth2', label: 'Google OAuth2' }
    ]);
    const handleSubmit = () => {
      if (!emailvalue) {
        return;
      } else {
        if (credentials.authmethod == 'OAuth2') {
          loadingInstance = ElLoading.service({
            lock: true,
            text: 'Waiting for Google...',
            background: 'rgba(0, 0, 0, 0.7)',
          });
          let redirect_uri = "app://Register";
          if (process.env.WEBPACK_DEV_SERVER_URL) {
            redirect_uri = process.env.WEBPACK_DEV_SERVER_URL + "/Register";
          }
          
         googleSdkLoaded(google => {
            google.accounts.oauth2
              .initTokenClient({
                client_id:
                  "251431201738-lkd104nevk4fc22cqjccg90kpq78d6tu.apps.googleusercontent.com",
                scope: "https://mail.google.com/",
                redirect_uri: redirect_uri,
                callback: (response) => {
                  if (response.access_token) {
                    loadingInstance.close();
                    credentials.code = response.access_token;
                    sendFormToBackend();
                  } 
                },
                error_callback: (errorResponse)=>{
                  loadingInstance.close();
                    ElMessage({
                      message: 'Oops, get access token wrong.',
                      type: 'error',
                      plain: true,
                    })
                  console.log(errorResponse);
                }
                
              }).requestAccessToken();
          });

        } else {
          sendFormToBackend();
        }
      }
      console.log('handleSubmit finished');
    };

    const sendFormToBackend = () => {
      loadingInstance = ElLoading.service({
        lock: true,
        text: 'Waiting for Server...',
        background: 'rgba(0, 0, 0, 0.7)',
      });
      window.electron.nativeStarter(JSON.stringify(credentials));
      window.electron.onStartSuccessListener(() => {
        loadingInstance.close();
        emit('submit-success');
      });
      window.electron.onStartFailListener((_, error) => {
        loadingInstance.close();
        ElMessage({
          message: 'Error: Can not start native verify process.',
          type: 'error',
          plain: true,
        })
        console.log(error);
      });
     
    };

    return {
      credentials,
      rules,
      securityOptions,
      authOptions,
      handleSubmit,
    };
  }
}
</script>

<style scoped>
.inter-box {
  background-color: white;
  box-shadow: var(--el-box-shadow-light);
  display: flex;
  justify-content: center;
  align-items: center;
  border-radius: 8px;
  height: 500px;
  width: 590px;
  margin-left: 4px;
}

.form-item {
  margin-bottom: 1px;
}


.form-label {
  display: block;
  color: gray;
  text-align: left;
  font-size: 14px;
  margin-bottom: 5px;
}

.form-header {
  display: block;
  color: black;
  text-align: left;
  font-size: 16px;
}

.el-input {
  width: 250px;
  border-color: #dcdfe6;
}

.el-select {
  width: 250px;
  border-color: #dcdfe6;
}

.continue-button {
  color: white;
  background-color: #67c23a;
  width: 100%;
}

.register {
  text-align: right;
}
</style>
