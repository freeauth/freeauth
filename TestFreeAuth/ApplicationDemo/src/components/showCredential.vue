<template>
    <el-card class="inter-box">
        <div>
            <span class="form-header">Claim</span>
            <el-divider style="margin-top: 3px;"></el-divider>
        </div>
        <div>
            <p>{{ credential.claim }}</p>
        </div>
        <div>
            <span class="form-header">Signature</span>
            <el-divider style="margin-top: 3px;"></el-divider>
        </div>
        <div>
            <p>{{ credential.signature }}</p>
        </div>
    </el-card>
</template>
<script>
import { onMounted, ref } from 'vue';
export default {
    name: 'showCredential',
    setup() {
        const credential = ref({
            claim: '',
            signature: '',
        });
        const showCredentialInfo = async () => {
            try {
                // const response = await getCredentialInfo();
                credential.value.claim = 'I am bob';
                credential.value.signature = 'jkashayudgysuagdytgftya';
            } catch (error) {
                console.error('Error fetching code flow:', error);
            }
        }
        onMounted(() => {
            showCredentialInfo();
        })
        return {
            credential,
        }
    }
}   
</script>
<style scoped>
.inter-box {
    background-color: white;
    border-radius: 8px;
    height: 350px;
    width: 590px;
    margin-left: 4px;
}
</style>