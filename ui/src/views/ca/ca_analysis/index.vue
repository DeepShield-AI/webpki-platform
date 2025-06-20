<template>
  <div class="app-container">

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
        :options="getPieOption(caMarket)"
        autoresize
        style="width: 50%; height: 800px;"
      />
    </el-card>

  </div>
</template>

<script>
import { getCaStats } from "@/api/ca/ca_analysis";
import Treeselect from "@riophae/vue-treeselect";
import "@riophae/vue-treeselect/dist/vue-treeselect.css";
import EChart from 'vue-echarts';

export default {
  name: "CaAnalysis",
  dicts: ['sys_normal_disable'],
  components: { Treeselect, 'v-chart': EChart },
  data() {
    return {
      loading: true,
      totalCaNum: 0,
      caMarket: {
        type: Object, // 👈 dict 类型
        required: true,
      },
    };
  },
  created() {
    this.getStats();
  },
  methods: {
    getStats() {
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
        this.totalCaNum = pieData.reduce((sum, item) => sum + item.value, 0);
        this.loading = false;
      }).catch(error => {
        console.error("Failed to fetch CA stats:", error);
        this.loading = false;
      });
    },
    getPieOption(data) {
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
