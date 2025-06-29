<template>
  <div class="app-container main">
    <h2 style="text-align: center; font-size: 36px; color: #303133; margin-bottom: 20px;">
      CA 详情: {{ caName }}
    </h2>

    <el-tabs :value="activeTab" @input="handleTabChange" type="card">

      <!-- Tab 1：CA 证书列表 -->
      <el-tab-pane label="CA 拥有证书" name="certs">
        <el-row :gutter="20">
          <el-col :sm="24" :lg="24" style="padding-left: 20px">
            <h2>CA Certificates Owned</h2>

            <div v-if="caCerts.length">
              <ul style="padding-left: 10px;">
                <li
                  v-for="(sha, index) in caCerts"
                  :key="index"
                  style="margin: 6px 0;"
                >
                  <router-link
                    :to="'/cert/cert_view/' + sha"
                    class="link-type"
                  >
                    {{ sha }}
                  </router-link>
                </li>
              </ul>
            </div>
            <div v-else style="color: #999;">
              No CA certificates found.
            </div>
          </el-col>
        </el-row>
      </el-tab-pane>

      <!-- Tab 2：CA 颁发行为分析 -->
      <el-tab-pane label="证书签发情况" name="issuing">
        <el-row>
          <el-col :span="24" style="padding: 20px;">
            <h2>证书签发行为分析</h2>
            <!-- 这里填充你的颁发数量、比例、FP 统计图等组件 -->
            <p style="color: #999;">（待补充图表或分析结果）</p>
          </el-col>
        </el-row>
      </el-tab-pane>

      <!-- Tab 3：CA 服务信息 -->
      <el-tab-pane label="服务信息" name="service">
        <el-row>
          <el-col :span="24" style="padding: 20px;">
            <h2>CA Service Link</h2>
            <!-- 链接、跳转、CA 的运营方介绍等 -->
            <p style="color: #999;">（待补充 CA 服务相关信息）</p>
          </el-col>
        </el-row>
      </el-tab-pane>

    </el-tabs>
  </div>
</template>

<script>
import { getCaInfo } from "@/api/ca/ca_search";
import RecursiveDict from '@/components/RecursiveDict';  // 路径根据你实际文件结构调整

export default {
  components: {
    RecursiveDict
  },
  name: "CaView",
  dicts: ['sys_cert_type', 'sys_key_type'],
  data() {
    return {
      loading: true,
      activeTab: 'certs',
      caName: this.$route.params.caName,
      caCerts: [],
      caFps: [],
    };
  },
  created() {
    this.getCa();
  },
  methods: {
    getCa() {
      this.loading = true;
      // return jsonify({'msg': 'Success', 'code': 200, "ca_certs": ca_certs, "issuing_cert_fps" : []})
      getCaInfo(this.caName).then(response => {
        console.log(response.ca_certs);
        this.caCerts = response.ca_certs;
        this.caFps = response.issuing_cert_fps;
        this.loading = false;
      });
    },
    handleTabChange(val) {
      this.activeTab = val;

      // 可选：根据 tab 加载对应模块的数据
      // if (val === 'issuing') this.loadIssuingStats();
    }
  }
};
</script>


<style scoped lang="scss">
.main {
  blockquote {
    padding: 10px 20px;
    margin: 0 0 20px;
    font-size: 17.5px;
    border-left: 5px solid #eee;
  }
  hr {
    margin-top: 20px;
    margin-bottom: 20px;
    border: 0;
    border-top: 1px solid #eee;
  }
  .col-item {
    margin-bottom: 20px;
  }

  ul {
    padding: 0;
    margin: 0;
  }

  font-family: "open sans", "Helvetica Neue", Helvetica, Arial, sans-serif;
  font-size: 13px;
  color: #676a6c;
  overflow-x: hidden;

  ul {
    list-style-type: none;
  }

  h4 {
    margin-top: 0px;
  }

  h2 {
    margin-top: 10px;
    font-size: 26px;
    font-weight: 100;
  }

  p {
    margin-top: 10px;

    b {
      font-weight: 700;
    }
  }
  .link-type {
    color: #409EFF;
    text-decoration: underline;
    word-break: break-all; /* 避免 SHA 太长撑出页面 */
  }
  .link-type:hover {
    color: #66b1ff;
  }
}
</style>

