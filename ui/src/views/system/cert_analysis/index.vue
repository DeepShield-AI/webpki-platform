<template>
  <div class="app-container">

    <el-form :model="webQueryParams" ref="webQueryForm" size="small" :inline="true" v-show="showSearch">
      <el-form-item label="网站" prop="domain">
        <el-input
          v-model="webQueryParams.domain"
          placeholder="请输入分析网站域名"
          clearable
        />
      </el-form-item>

      <el-form-item>
        <el-button type="primary" icon="el-icon-search" size="mini" @click="handleWebQuery">分析</el-button>
        <el-button icon="el-icon-refresh" size="mini" @click="resetWebQuery">重置</el-button>
      </el-form-item>
    </el-form>


    <el-card>
      <div slot="header">Web Analysis Result</div>
      <div class="web-result-item">

        <div class="indent">
          <div v-for="(value, key) in webData" :key="key">

            <strong style="display: inline-block;"> {{ key }}:</strong>

            <template v-if="isObject(value)" class="indent">
              <div v-for="(subValue, subKey) in value" :key="subKey">
                <strong style="display: inline-block;">{{ subKey }}:</strong>
                <span v-if="checkKeyInDict(subKey)[0]" style="display: inline-block;">
                  <dict-tag :options="checkKeyInDict(subKey)[1]" :value="subValue"/>
                </span>
                <span v-else>
                  <code class="code-block">{{ subValue }}</code>
                </span>
              </div>
            </template>

            <template v-else>
              <span v-if="checkKeyInDict(key)[0]" style="display: inline-block;">
                <dict-tag :options="checkKeyInDict(key)[1]" :value="value"/>
              </span>
              <span v-else>
                <code class="code-block">{{ value }}</code>
              </span>
            </template>

          </div>
        </div>

      </div>
    </el-card>

    <el-divider />

    <el-form :model="queryParams" ref="queryForm" size="small" :inline="true" v-show="showSearch">
      <el-form-item label="根域名" prop="rootDomain">
        <el-input
          v-model="queryParams.rootDomain"
          placeholder="请输入查询根域名组"
          clearable
        />
      </el-form-item>

      <el-form-item label="日期" prop="selectedDate">
        <el-date-picker
          v-model="queryParams.selectedDate"
          style="width: 240px"
          value-format="yyyy-MM-dd"
          type="date"
          placeholder="选择日期"
        ></el-date-picker>
      </el-form-item>

      <el-form-item>
        <el-button type="primary" icon="el-icon-search" size="mini" @click="handleQuery">搜索</el-button>
        <el-button icon="el-icon-refresh" size="mini" @click="resetQuery">重置</el-button>
      </el-form-item>
    </el-form>

    <cert-graph v-loading="loading" :graphData = this.certGraphData />

    <!-- <el-table-column prop="cert_id" label="证书ID" width="200">
      <template slot-scope="scope">
        <router-link :to="'/system/cert_view/' + scope.row.cert_id" class="link-type">
          <span>{{ scope.row.cert_id }}</span>
        </router-link>
      </template>
    </el-table-column> -->

      <!-- <el-row :gutter="10" class="mb8">
      <el-col :span="1.5">
        <el-button
          type="primary"
          plain
          icon="el-icon-plus"
          size="mini"
          @click="handleAdd"
          v-hasPermi="['system:cert:add']"
        >新增进程</el-button>
      </el-col>
      <el-col :span="1.5">
        <el-button
          type="info"
          plain
          icon="el-icon-sort"
          size="mini"
          @click="toggleExpandAll"
        >展开/折叠</el-button>
      </el-col>
      <right-toolbar :showSearch.sync="showSearch" @queryTable="getAnalysisResult"></right-toolbar>
    </el-row> -->

    <!-- <el-table v-loading="loading" :data="certResultList" @selection-change="handleSelectionChange"> -->
    <!-- <el-table
      v-if="refreshTable"
      v-loading="loading"
      :data="scanList"
      row-key="scanId"
      :default-expand-all="isExpandAll"
      :tree-props="{children: 'children', hasChildren: 'hasChildren'}"
      > -->
      <!-- <el-table-column prop="scan_id" label="扫描ID" width="100"></el-table-column>
      <el-table-column prop="scanned_cert_num" label="扫描证书数量(去重后)" width="100"></el-table-column>
      <el-table-column prop="expired_percent" label="证书过期比例" width="100"></el-table-column>

      <el-table-column prop="chartDataList" label="图表" width="1000">
        
        <template slot-scope="{ row }">
          <div>
            <multi-e-charts-pie-chart :chartDataList="row.chartDataList"></multi-e-charts-pie-chart>
          </div>
        </template>
        
      </el-table-column> -->

      <!-- <el-table-column prop="issuer_count" label="证书签发者统计" width="500">
        <div>
          <e-charts-pie-chart :chartData="myChartData" :chartOptions="myChartOptions"></e-charts-pie-chart>
        </div>
      </el-table-column>

      <el-table-column prop="key_type_count" label="证书密钥类型统计" width="500">
        <div>
          <e-charts-pie-chart :chartData="myChartData" :chartOptions="myChartOptions"></e-charts-pie-chart>
        </div>
      </el-table-column>
      <el-table-column prop="key_size_count" label="证书密钥长度统计" width="500">
        <div>
          <e-charts-pie-chart :chartData="myChartData" :chartOptions="myChartOptions"></e-charts-pie-chart>
        </div>
      </el-table-column>
      <el-table-column prop="validation_period_count" label="证书有效时长统计" width="500">
        <div>
          <e-charts-pie-chart :chartData="myChartData" :chartOptions="myChartOptions"></e-charts-pie-chart>
        </div>
      </el-table-column> -->
      
    <!-- </el-table> -->

  </div>
</template>

<script>
import { getWebAnalysisResult, getDomainTrustRelation } from "@/api/system/cert_analysis";
import Treeselect from "@riophae/vue-treeselect";
import "@riophae/vue-treeselect/dist/vue-treeselect.css";
import MultiEChartsPieChart from '../components/piechart/MultiPieChart';
import CertGraph from './certGraph.vue';
// import CertGraph from '@/views/system/cert_analysis/certGraph.vue';

export default {
  name: "CertAnalysis",
  dicts: ['sys_normal_disable'],
  components: { Treeselect, MultiEChartsPieChart, CertGraph },

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
      // 查询参数
      queryParams: {
        rootDomain: undefined,
        selectedDate: undefined
      },
      // CertGraph Data
      certGraphData: undefined,
      // web check data
      webData: undefined,
      webQueryParams: {
        domain: undefined
      },
      // Pie Chart data
      myChartData: {
        labels: ['Label 1', 'Label 2', 'Label 3'],
        data: [15, 80, 5],
      },
      myChartOptions: {
        title: {
          subtext: 'Custom Subtitle',
        },
      }
    };
  },
  created() {
    // this.getAnalysisResult();
    // this.startAutoRefresh();
  },
  beforeDestroy() {
    this.stopAutoRefresh();
  },

  methods: {
    /** 搜索按钮操作 */
    handleWebQuery() {
      this.analyzeWeb();
    },
    /** 重置按钮操作 */
    resetWebQuery() {
      this.resetForm("webQueryForm");
      // this.handleQuery();
    },
    analyzeWeb() {
      this.loading = true;
      getWebAnalysisResult(this.webQueryParams).then(response => {
        this.webData = response.data;
        this.loading = false;
      });
    },
    /** 搜索按钮操作 */
    handleQuery() {
      this.getDomainTrustRelation();
    },
    /** 重置按钮操作 */
    resetQuery() {
      this.resetForm("queryForm");
      // this.handleQuery();
    },
    getDomainTrustRelation() {
      this.loading = true;
      console.log(this.queryParams)

      getDomainTrustRelation(this.queryParams).then(response => {
        this.certGraphData = response.data;
        this.loading = false;
      });
    },
    getAnalysisResult() {
      this.loading = true;
      listCertAnalysisResult(this.queryParams).then(response => {
        // this.scanList = this.handleTree(response.data, "scanId");
        // this.certResultList = response.data;

        this.certResultList = response.data.map(item => {
          try {
                // console.log(typeof(item.issuer_count))
                // console.log(typeof(item.key_size_count))
                // console.log(typeof(item.key_type_count))
                // console.log(typeof(item.validation_period_count))
                const issuerCountData = item.issuer_count ? item.issuer_count : "{}";
                const keySizeCountData = item.key_size_count ? item.key_size_count : "{}";
                const keyTypeCountData = item.key_type_count ? item.key_type_count : "{}";
                const validationPeriodCountData = item.validation_period_count ? item.validation_period_count : "{}";

                // 构建 chartData 列表
                const chartDataList = [
                  { labels: Object.keys(issuerCountData), data: Object.values(issuerCountData) },
                  { labels: Object.keys(keySizeCountData), data: Object.values(keySizeCountData) },
                  { labels: Object.keys(keyTypeCountData), data: Object.values(keyTypeCountData) },
                  { labels: Object.keys(validationPeriodCountData), data: Object.values(validationPeriodCountData) },
                ];

                // 返回新的对象，包括原有的属性和新构建的 chartDataList
                console.log(chartDataList)
                return { ...item, chartDataList };

              } catch (error) {
                console.error("Error parsing JSON:", error);
              }
        });

        this.loading = false;
      });
    },
    /** 定时刷新表格数据 */
    startAutoRefresh() {
      this.autoRefreshTimer = setInterval(() => {
        // this.getAnalysisResult();
      }, 5000);
    },
    stopAutoRefresh() {
      // 停止定时器的逻辑
      clearInterval(this.autoRefreshTimer);
    },
    updateChartData() {
      // 从外部更新数据和选项
      this.myChartData = {
        labels: ['Updated Label 1', 'Updated Label 2', 'Updated Label 3'],
        data: [40, 30, 30],
      };
      this.myChartOptions = {
        title: {
          subtext: 'Updated Subtitle',
        },
        // Add any other custom options
      };
    },
  },
};
</script>
