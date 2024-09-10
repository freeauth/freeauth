<template>
  <div class="code-flow">

    <el-card class="inter-box">
      <el-steps direction="vertical" :active="curstate" style="height: 300px;" finish-status="success">
        <el-step title="Connect to verifier"></el-step>
        <el-step title="Preproc handshake circuits"></el-step>
        <el-step title="Run three party handshake, connect to SMTP server"></el-step>
        <el-step title="Preproc AES-GCM-128 related circuits"></el-step>
        <el-step title="Run SMTP protocol authentication process"></el-step>
        <el-step title="Commit Email address and addition account factor to verifier"></el-step>
      </el-steps>
    </el-card>
  </div>
  <div v-loading="bottom_view.isLoading" element-loading-text="bottom_message" style="margin-top: 20px; height: 90px;" >
    <div v-if="bottom_view.isOk" class="bottom-view-div">
      <el-icon :size="45" color="#67C23A">
        <SuccessFilled />
      </el-icon>
      <div style="height: 10px;" />
    </div>
    <div v-if="bottom_view.isErr" class="bottom-view-div">
      <el-icon :size="45" color="#F56C6C">
        <CircleCloseFilled />
      </el-icon>
      <div style="height: 10px;" />
      <el-button type="danger" plain @click="goBack">Go Back</el-button>
    </div>
  </div>
</template>
<script>

import { ref, onMounted, onBeforeUnmount } from 'vue';
import { vstatus } from '@/utils/vcode';
import { ElMessage } from 'element-plus';

export default {
  name: 'processDisplay',
  components: {
  },
  emits: ['verify-success'],
  setup(_, ctx) {
    const curstate = ref(0);
    const bottom_view = ref({
      isLoading: true,
      isOk: false,
      isErr: false
    });
    const bottom_message = ref("Running verification, please wait...");

    const onStateReturned = (_, state) => {
      if (state == curstate.value) {
        return;
      }

      if(state != vstatus.STATE_ERROR)
        curstate.value = state;

      console.log(state);
      if (state == vstatus.STATE_COMPLETE) {
        bottom_view.value.isLoading = false;
        bottom_view.value.isOk = true;
        ElMessage({
          message: 'Verification process has been successfully completed',
          type: 'success',
          plain: true,
          showClose: true,
          duration: 0
        })
      } else if (state == vstatus.STATE_ERROR) {
        bottom_view.value.isLoading = false;
        bottom_view.value.isErr = true;
        ElMessage({
          message: 'Email address authentication failed, please try again',
          type: 'error',
          plain: true,
          showClose: true,
          duration: 0
        })
      }
    };

    onMounted(() => {
      window.electron.bindStateChangeListener(onStateReturned);
    });


    onBeforeUnmount(() => {
      window.electron.unbindStateChangeListener();
      ElMessage.closeAll();
    });

    const onShowCredential = () => {
      ctx.emit('verify-success');
    };

    const goBack = () => {
      ctx.emit('verify-failed');
    };

    return {
      curstate,
      bottom_message,
      bottom_view,
      onShowCredential,
      goBack
    };
  }
}
</script>

<style scoped>
.code-flow-block {
  background-color: white;
  max-width: 600px;
  margin: auto;
}

.inter-box {
  background-color: white;
  border-radius: 8px;
  height: 350px;
  width: 590px;
  margin-left: 4px;
}

.bottom-view-div {
  display: flex;
  flex-direction: column;
  align-items: center;
}

</style>