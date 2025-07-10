<template>
  <div class="app-container">

    <!-- FIRST PART CA -->
    <h2 style="text-align: center; font-size: 36px; color: #303133; margin-bottom: 20px;">CA 总览</h2>
      
    <!-- totalCaNum  -->
    <el-card shadow="always" style="text-align: center;">
      <div style="font-size: 32px; font-weight: bold; color: #409EFF;">{{ totalCaNum }}</div>
      <div style="font-size: 16px; color: #666;">总 CA 数量</div>
    </el-card>

    <!-- caMarket -->
    <el-card shadow="hover" style="margin-bottom: 20px; margin-top: 20px;">
      <div slot="header">
        <strong>CA 市场占比</strong>
      </div>
      <v-chart
        :options="getCaPieOption(caMarket)"
        autoresize
        style="width: 100%; height: 600px;"
      />
    </el-card>

    <el-divider />

    <!-- SECOND PART HOST -->
    <h2 style="text-align: center; font-size: 36px; color: #303133; margin-bottom: 20px;">Web 总览</h2>
      
    <!-- totalHostNum  -->
    <el-card shadow="always" style="text-align: center;">
      <div style="font-size: 32px; font-weight: bold; color: #409EFF;">{{ totalHostNum }}</div>
      <div style="font-size: 16px; color: #666;">总 TLS 数量</div>
    </el-card>

    <!-- hostSecurityStat -->

    <!-- 1. 错误占比文字展示 -->
    <el-card class="stat-card">
      <div class="error-ratio-box">
        <div class="ratio-title">Host 错误占比</div>
        <div class="ratio-value">{{ errorHostPercentage }}%</div>
        <div class="ratio-desc">共 {{ hostSecurityStat.total_hosts }} 个 Host, 其中 {{ hostSecurityStat.hosts_without_error }} 个无错误</div>
      </div>
    </el-card>

    <!-- 2. 错误代码饼图展示 -->
    <el-row :gutter="20" style="margin-top: 20px;">
      <el-col
        v-for="(count, code) in hostSecurityStat.error_statistics"
        :key="code"
        :xs="24"
        :sm="12"
        :md="8"
        :lg="6"
        :xl="4"
      >
        <el-card shadow="hover" style="margin-bottom: 20px;">
          <div slot="header"><strong>{{ code }}</strong> 错误比率</div>
          <div style="display: flex; justify-content: center; align-items: center; height: 250px;">
            <v-chart
              :options="getPieOption(code, count)"
              autoresize
              style="width: 100%; height: 100%; max-width: 250px;"
            />
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-divider />

    <!-- THIRD PART CERT -->
    <h2 style="text-align: center; font-size: 36px; color: #303133; margin-bottom: 20px;">证书总览</h2>

    <!-- totalCertNum  -->
    <el-card shadow="always" style="text-align: center;">
      <div style="font-size: 32px; font-weight: bold; color: #409EFF;">{{ totalCertNum }}</div>
      <div style="font-size: 16px; color: #666;">总证书数量</div>
    </el-card>

    <!-- certSecurityStat -->

    <!-- 1. 错误占比文字展示 -->
    <el-card class="stat-card">
      <div class="error-ratio-box">
        <div class="ratio-title">证书错误占比</div>
        <div class="ratio-value">{{ errorCertPercentage }}%</div>
        <div class="ratio-desc">共 {{ certSecurityStat.total_certificates }} 个证书，其中 {{ certSecurityStat.certificates_without_error }} 个无错误</div>
      </div>
    </el-card>

    <!-- 2. 错误代码饼图展示 -->
    <el-row :gutter="20" style="margin-top: 20px;">
      <el-col
        v-for="(count, code) in certSecurityStat.error_statistics"
        :key="code"
        :xs="24"
        :sm="12"
        :md="8"
        :lg="6"
        :xl="4"
      >
        <el-card shadow="hover" style="margin-bottom: 20px;">
          <div slot="header"><strong>{{ code }}</strong> 错误比率</div>
          <div style="display: flex; justify-content: center; align-items: center; height: 250px;">
            <v-chart
              :options="getPieOption(code, count)"
              autoresize
              style="width: 100%; height: 100%; max-width: 250px;"
            />
          </div>
        </el-card>
      </el-col>
    </el-row>

  </div>
</template>

<script>
import { getTotalCerts, getCertSecurityStats } from "@/api/cert/cert_analysis";
import { getTotalHosts, getHostSecurityStats } from "@/api/host/host_analysis";
import { getCaStats } from "@/api/ca/ca_analysis";
import Treeselect from "@riophae/vue-treeselect";
import "@riophae/vue-treeselect/dist/vue-treeselect.css";
import EChart from 'vue-echarts';

export default {
  name: "Dashboard",
  dicts: ['sys_normal_disable'],
  components: { Treeselect, 'v-chart': EChart },
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

      totalCaNum: 0,
      caMarket: {
        type: Object, // 👈 dict 类型
        required: true,
      },

      // host analysis
      totalHostNum: 0,
      errorHostPercentage: 0,
      hostSecurityStat: {
        type: Object, // 👈 dict 类型
        required: true,
      },

      totalCertNum: 0,
      errorCertPercentage: 0,
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

      getCaStats().then(response => {
        const rawData = response.data;

        // 排序并提取前10
        const entries = Object.entries(rawData).sort((a, b) => b[1] - a[1]);
        const top10 = entries.slice(0, 10);
        const other = entries.slice(10);

        const otherCount = other.reduce((acc, [_, val]) => acc + val, 0);

        const pieData = top10.map(([name, value]) => ({ name, value }));
        if (otherCount > 0) {
          pieData.push({ name: 'Other', value: otherCount });
        }

        this.caMarket = pieData;

        // 总量
        this.totalCaNum = Object.keys(rawData).length;
        this.loading = false;
      }).catch(error => {
        console.error("Failed to fetch CA stats:", error);
        this.loading = false;
      });


      // return jsonify({'msg': 'Success', 'code': 200, 'data': count})
      getTotalHosts().then(response => {
        this.totalHostNum = response.data;
      });
      getTotalCerts().then(response => {
        this.totalCertNum = response.data;
      });
      this.loading = false;
    },

    getSecurityStats(){
      this.loading = true;
      // return jsonify({'msg': 'Success', 'code': 200, 'data': result})
      getHostSecurityStats().then(response => {
        this.hostSecurityStat = response.data;
        this.errorHostPercentage = (1 - (this.hostSecurityStat.hosts_without_error / this.hostSecurityStat.total_hosts)) * 100;
      })
      getCertSecurityStats().then(response => {
        this.certSecurityStat = response.data;
        this.errorCertPercentage = (1 - (this.certSecurityStat.certificates_without_error / this.certSecurityStat.total_certificates)) * 100;
      })
      this.loading = false;
    },

    getCaPieOption(data) {
      return {
        title: {
          text: 'CA 市场占比',
          left: 'center'
        },
        tooltip: {
          trigger: 'item',
          formatter: '{b}: {c} ({d}%)'
        },
        legend: {
          orient: 'vertical',
          left: 'right'
        },
        series: [
          {
            name: 'CA',
            type: 'pie',
            radius: ['40%', '70%'], // 环形图
            avoidLabelOverlap: false,
            label: {
              show: true,
              formatter: '{b}: {d}%'
            },
            labelLine: {
              show: true
            },
            data: data
          }
        ]
      };
    },

    getPieOption(code, count) {
      const total = this.hostSecurityStat.total_hosts;
      return {
        title: {
          text: `${((count / total) * 100).toFixed(1)}%`,
          left: 'center', // 居中标题
          top: '45%',
          textStyle: {
            fontSize: 14
          }
        },
        tooltip: { trigger: 'item' },
        series: [
          {
            name: code,
            type: 'pie',
            radius: ['30%', '50%'],
            center: ['50%', '50%'], // 确保图表居中
            avoidLabelOverlap: false,
            label: { show: false },
            emphasis: {
              label: {
                show: true,
                fontSize: 12,
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
