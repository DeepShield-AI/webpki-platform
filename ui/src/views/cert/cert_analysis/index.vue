<template>
  <div class="app-container">

    <!-- totalCertNum  -->
    <el-card shadow="always" style="text-align: center;">
      <div style="font-size: 32px; font-weight: bold; color: #409EFF;">{{ totalCertNum }}</div>
      <div style="font-size: 16px; color: #666;">总证书数量</div>
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
              <div style="font-size: 24px; font-weight: bold;">{{ totalCertNum }}</div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row> -->

    <!-- certSecurityStat -->
    <div slot="header">Cert Analysis Result</div>

    <!-- 1. 错误占比文字展示 -->
    <el-card class="stat-card">
      <div class="error-ratio-box">
        <div class="ratio-title">证书错误占比</div>
        <div class="ratio-value">{{ errorPercentage }}%</div>
        <div class="ratio-desc">共 {{ certSecurityStat.total_certificates }} 个证书，其中 {{ certSecurityStat.certificates_without_error }} 个无错误</div>
      </div>
    </el-card>

    <!-- 2. 错误代码饼图展示 -->
    <el-row :gutter="20" style="margin-top: 20px;">
      <el-col
        v-for="(count, code) in certSecurityStat.error_statistics"
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

  </div>
</template>

<script>
import { getTotalCerts, getCertSecurityStats } from "@/api/cert/cert_analysis";
import Treeselect from "@riophae/vue-treeselect";
import "@riophae/vue-treeselect/dist/vue-treeselect.css";
import EChart from 'vue-echarts';

export default {
  name: "CertAnalysis",
  dicts: ['sys_normal_disable'],
  components: { Treeselect, 'v-chart': EChart },
  data() {
    return {
      // 遮罩层
      loading: true,
      // 显示搜索条件
      showSearch: true,
      // 表格树数据
      certResultList: [],
      // 部门树选项
      deptOptions: [],
      // 弹出层标题
      title: "",
      // 是否显示弹出层
      open: false,
      // 是否展开，默认全部展开
      isExpandAll: true,
      // 重新渲染表格状态
      refreshTable: true,

      totalCertNum: 0,
      errorPercentage: 0,
      certSecurityStat: {
        type: Object, // 👈 dict 类型
        required: true,
      },
    };
  },
  created() {
    this.getTotalNum();
    this.getSecurityStats();
  },
  methods: {
    getTotalNum(){
      this.loading = true;
      // return jsonify({'msg': 'Success', 'code': 200, 'data': count})
      getTotalCerts().then(response => {
        this.totalCertNum = response.data;
        this.loading = false;
      });
    },
    getSecurityStats(){
      this.loading = true;
      // return jsonify({'msg': 'Success', 'code': 200, 'data': result})
      getCertSecurityStats().then(response => {
        this.certSecurityStat = response.data;
        this.errorPercentage = (1 - (this.certSecurityStat.certificates_without_error / this.certSecurityStat.total_certificates)) * 100;
        this.loading = false;
      })
    },
    getPieOption(code, count) {
      const total = this.certSecurityStat.total_certificates;
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
    }
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
