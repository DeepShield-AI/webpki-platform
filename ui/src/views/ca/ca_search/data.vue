<template>
  <div class="app-container main">
    <h2 style="text-align: center; font-size: 36px; color: #303133; margin-bottom: 20px;">
      CA 详情: {{ caId }}
    </h2>

    <el-tabs :value="activeTab" @input="handleTabChange" type="card">

      <!-- Tab 1：CA 证书列表 -->
      <el-tab-pane label="CA Basic Info" name="certs">

        <el-row :gutter="20" v-if="caInfo && caInfo.subject">
          <el-col :sm="24" :lg="24" style="padding-left: 20px">
            <h2>CA详情</h2>
            <el-card>
              <RecursiveDict :data="caInfo.subject" />
            </el-card>
          </el-col>
        </el-row>

        <el-row :gutter="20" v-if="caInfo && caInfo.subject">
          <el-col :sm="24" :lg="24" style="padding-left: 20px">
            <h2>CA详情</h2>
            <el-card>
              <RecursiveDict :data="caInfo.spki" />
            </el-card>
          </el-col>
        </el-row>

        <el-row :gutter="20" v-if="caInfo && caInfo.subject">
          <el-col :sm="24" :lg="24" style="padding-left: 20px">
            <h2>CA Certificates Owned</h2>

            <div v-if="caInfo.certs.length">
              <ul style="padding-left: 10px;">
                <li
                  v-for="(sha, index) in caInfo.certs"
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
      <el-tab-pane label="CA资源关系图" name="graph">  
        <el-row :gutter="20">
          <el-col :sm="24" :lg="24" style="padding-left: 20px">
            <h2>CA资源关系图</h2>
          </el-col>
        </el-row>

        <el-card style="width: 67%; margin: 0 auto;">
          <cag :graph-data="caGraphData" />
        </el-card>
      </el-tab-pane>

      <!-- Tab 3：CA 颁发行为分析 -->
      <el-tab-pane label="证书签发情况" name="issuing">
        <el-row>
          <el-col :span="24" style="padding: 20px;">
            <h2>证书签发行为分析</h2>
            <!-- 这里填充你的颁发数量、比例、FP 统计图等组件 -->
            <p style="color: #999;">（待补充图表或分析结果）</p>
          </el-col>
        </el-row>
      </el-tab-pane>

      <!-- Tab 4：CA 服务信息 -->
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
import { getCaInfo, getCaCag } from "@/api/ca/ca_search";
import RecursiveDict from '@/components/RecursiveDict';  // 路径根据你实际文件结构调整
import Cag from '@/views/host/host_analysis/cag';
import EChart from 'vue-echarts';

export default {
  components: {
    RecursiveDict, Cag, 'v-chart': EChart
  },
  name: "CaView",
  dicts: ['sys_cert_type', 'sys_key_type'],
  data() {
    return {
      loading: true,
      activeTab: 'certs',
      caId: this.$route.params.caId,
      caInfo: {},
      caFps: [],
      caGraphData: {}
    };
  },
  created() {
    this.getCa();
  },
  methods: {
    getCa() {
      this.loading = true;
      // return jsonify({'msg': 'Success', 'code': 200, "ca_certs": ca_certs, "issuing_cert_fps" : []})
      getCaInfo(this.caId).then(response => {
        console.log(response.data);
        this.caInfo = response.data;
        this.loading = false;
      });
    },
    getCag(){
      this.loading = true;
      getCaCag(this.caId).then(response => {
        this.caGraphData = response.data;
        this.loading = false;
      });
    },
    handleTabChange(val) {
      this.activeTab = val;
      if (val === 'graph' && Object.keys(this.caGraphData).length === 0) {
        this.getCag();
      }
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

