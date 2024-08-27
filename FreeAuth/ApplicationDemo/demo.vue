<script>
import {getProcessDisplay} from '@/api/register'
import { ref,watch,onMounted,nextTick,onBeforeUnmount} from 'vue';
  export default {
    name: 'processDisplay',
  components: {
  },
  setup() {
    const codeContent = ref(''); // 用于存储后端代码运行的文本内容
    const scrollbar = ref(null); // 用于访问 el-scrollbar 组件

    const progress = ref({
      percentage: 0,
      progress: 'exception',
    });

    const totalLines = ref(0); // 用于存储后端代码总行数
    let intervalId = null; // 用于存储定时器ID

    const fetchCodeFlow = async () => {
      try {
        const response =await getProcessDisplay();
        console.log(response.data);
        const data =response.json();
        totalLines.value = data.totalLines;
        updateCodeContent();
      } catch (error) {
        console.error('Error fetching code flow:', error);
      }
    };

    const updateCodeContent = () => {
      intervalId = setInterval(() => {
        if (progress.value.percentage >= 100) {
          clearInterval(intervalId);
        } else {
          fetchNextLine();
        }
      }, 100);
    };

    const fetchNextLine = async () => {
      try {
        const response =await getProcessDisplay();
        const data = await response.json();
        if (data.line) {
          codeContent.value += data.line + '\n';
          progress.value.percentage = (codeContent.value.split('\n').length / totalLines.value) * 100;
          // 滚动到最新的内容
          nextTick(() => {
            const { scrollHeight, clientHeight } = scrollbar.value.$el.querySelector('.el-scrollbar__wrap');
            scrollbar.value.$el.querySelector('.el-scrollbar__wrap').scrollTop = scrollHeight - clientHeight;
          });
        }
      } catch (error) {
        console.error('Error fetching next line:', error);
      }
    };

    onMounted(() => {
      fetchCodeFlow();
    });

    // 组件销毁前清除定时器
    onBeforeUnmount(() => {
      clearInterval(intervalId);
    });

    // 监听 codeContent 的变化，当有新数据时自动滚动到底部
    watch(codeContent, () => {
      nextTick(() => {
        const { scrollHeight, clientHeight } = scrollbar.value.$el.querySelector('.el-scrollbar__wrap');
        scrollbar.value.$el.querySelector('.el-scrollbar__wrap').scrollTop = scrollHeight - clientHeight;
      });
    });

    return {
      codeContent,
      scrollbar,
      progress,
      totalLines
    };
  }
}
  </script>



<div class="flow-progress">
  <el-progress
    :percentage=percentage
    :stroke-width="15"
    status="warning"
    striped
    striped-flow
  />
  </div>