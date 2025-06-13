<template>
  <div class="app-container">

    <!-- totalHostNum  -->
    <el-card shadow="always" style="text-align: center;">
      <div style="font-size: 32px; font-weight: bold; color: #409EFF;">{{ totalHostNum }}</div>
      <div style="font-size: 16px; color: #666;">总 TLS 数量</div>
    </el-card>

    <!-- <el-row :gutter="20">
      <el-col :span="6">
        <el-card shadow="hover" style="background: #f0f9eb;">
          <div style="display: flex; align-items: center;">
            <el-icon size="36" style="color: #67c23a;">
              <i class="el-icon-document" />
            </el-icon>
            <div style="margin-left: 12px;">
              <div style="font-size: 14px; color: #909399;">总证书数量</div>
              <div style="font-size: 24px; font-weight: bold;">{{ totalHostNum }}</div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row> -->

    <!-- hostSecurityStat -->

    <!-- 1. 错误占比文字展示 -->
    <el-card class="stat-card">
      <div class="error-ratio-box">
        <div class="ratio-title">Host 错误占比</div>
        <div class="ratio-value">{{ errorPercentage }}%</div>
        <div class="ratio-desc">共 {{ hostSecurityStat.total_hosts }} 个 Host, 其中 {{ hostSecurityStat.hosts_without_error }} 个无错误</div>
      </div>
    </el-card>

    <!-- 2. 错误代码饼图展示 -->
    <el-row :gutter="20" style="margin-top: 20px;">
      <el-col
        v-for="(count, code) in hostSecurityStat.error_statistics"
        :key="code"
        :span="24"
      >
        <el-card shadow="hover" style="margin-bottom: 20px;">
          <div slot="header">
            <strong>{{ code }}</strong> 错误占比
          </div>
          <v-chart
            :options="getPieOption(code, count)"
            autoresize
            style="height: 300px;"
          />
        </el-card>
      </el-col>
    </el-row>

    <el-divider />

    <!-- CAG -->
    <el-form :model="queryParams" ref="queryForm" size="small" :inline="true" v-show="showSearch">
      <el-form-item label="根域名" prop="rootDomain">
        <el-input
          v-model="queryParams.rootDomain"
          placeholder="请输入查询根域名组"
          clearable
        />
      </el-form-item>

      <el-form-item>
        <el-button type="primary" icon="el-icon-search" size="mini" @click="handleQuery">搜索</el-button>
        <el-button icon="el-icon-refresh" size="mini" @click="resetQuery">重置</el-button>
      </el-form-item>
    </el-form>

    <!-- main stuff here -->
    <cag :graph-data="certGraphData" />

  </div>
</template>

<script>
import { getTotalHosts, getHostSecurityStats, getSubCag } from "@/api/system/host_analysis";
import Treeselect from "@riophae/vue-treeselect";
import "@riophae/vue-treeselect/dist/vue-treeselect.css";
import Cag from '@/views/system/host_analysis/cag';
import EChart from 'vue-echarts';
// import Cag from "./cag.vue";

export default {
  name: "HostAnalysis",
  dicts: ['sys_normal_disable'],
  components: { Treeselect, Cag, 'v-chart': EChart },
  data() {
    return {
      // 遮罩层
      loading: true,
      // 显示搜索条件
      showSearch: true,
      // 弹出层标题
      title: "",
      // 是否显示弹出层
      open: false,
      // 是否展开，默认全部展开
      isExpandAll: true,
      // 重新渲染表格状态
      refreshTable: true,

      // host analysis
      totalHostNum: 0,
      errorPercentage: 0,
      hostSecurityStat: {
        type: Object, // 👈 dict 类型
        required: true,
      },

      certGraphData: {
        type: Object, // 👈 dict 类型
        required: true,
      },

      // 查询参数
      queryParams: {
        rootDomain: undefined,
      },
    };
  },
  created() {
    this.getTotalNum();
    this.getSecurityStats();
    this.getCag();
  },
  methods: {
    getTotalNum(){
      this.loading = true;
      // return jsonify({'msg': 'Success', 'code': 200, 'data': count})
      getTotalHosts().then(response => {
        this.totalHostNum = response.data;
        this.loading = false;
      });
    },
    getSecurityStats(){
      this.loading = true;
      // return jsonify({'msg': 'Success', 'code': 200, 'data': result})
      getHostSecurityStats().then(response => {
        this.hostSecurityStat = response.data;
        this.errorPercentage = (1 - (this.hostSecurityStat.hosts_without_error / this.hostSecurityStat.total_hosts)) * 100;
        this.loading = false;
      })
    },
    getCag(){
      this.loading = true;
      // return jsonify({'msg': 'Success', 'code': 200, "data": graph_data})
      getSubCag().then(response => {
        this.certGraphData = response.data;
        this.loading = false;
      });
    },

    getPieOption(code, count) {
      const total = this.hostSecurityStat.total_hosts;
      return {
        title: {
          text: `${((count / total) * 100).toFixed(1)}%`,
          left: 'center',
          top: '40%',
          textStyle: {
            fontSize: 20
          }
        },
        tooltip: {
          trigger: 'item'
        },
        series: [
          {
            name: code,
            type: 'pie',
            radius: ['50%', '70%'],
            avoidLabelOverlap: false,
            label: { show: false },
            emphasis: {
              label: {
                show: true,
                fontSize: '16',
                fontWeight: 'bold'
              }
            },
            labelLine: { show: false },
            data: [
              { value: count, name: code },
              { value: total - count, name: '其他' }
            ]
          }
        ]
      };
    },

    /** 搜索按钮操作 */
    handleQuery() {
      // currently pass
    },
    /** 重置按钮操作 */
    resetQuery() {
      this.resetForm("queryForm");
      this.handleQuery();
    },
  }
};
</script>


<style scoped>
.stat-card {
  padding: 20px;
  text-align: center;
}
.error-ratio-box {
  display: flex;
  flex-direction: column;
  align-items: center;
}
.ratio-title {
  font-size: 16px;
  color: #909399;
}
.ratio-value {
  font-size: 40px;
  font-weight: bold;
  color: #F56C6C;
}
.ratio-desc {
  font-size: 14px;
  margin-top: 5px;
  color: #666;
}
.chart-card {
  padding: 10px;
}
</style>
