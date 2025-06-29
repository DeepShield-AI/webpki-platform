<template>
  <div class="app-container">
    <el-form :model="queryParams" ref="queryForm" size="small" :inline="true" v-show="showSearch">

      <!-- <el-form-item label="证书SHA256" prop="sha256">
        <el-input
          v-model="queryParams.sha256"
          placeholder="请输入证书SHA256"
          clearable
          @keyup.enter.native="handleQuery"
        />
      </el-form-item> -->

      <el-form-item label="证书查询" prop="subject">
        <el-input
          v-model="queryParams.subject"
          placeholder="请输入域名或者 IP"
          clearable
          @keyup.enter.native="handleQuery"
        />
      </el-form-item>
      
      <!-- <el-form-item label="有效起始日期范围" prop="notValidBeforeRange">
        <el-date-picker
          v-model="notValidBeforeRange"
          style="width: 240px"
          value-format="yyyy-MM-dd"
          type="daterange"
          range-separator="-"
          start-placeholder="开始日期"
          end-placeholder="结束日期"
        ></el-date-picker>
      </el-form-item>

      <el-form-item label="有效终止日期范围" prop="notValidAfterRange">
        <el-date-picker
          v-model="notValidAfterRange"
          style="width: 240px"
          value-format="yyyy-MM-dd"
          type="daterange"
          range-separator="-"
          start-placeholder="开始日期"
          end-placeholder="结束日期"
        ></el-date-picker>
      </el-form-item> -->

      <el-form-item>
        <el-button type="primary" icon="el-icon-search" size="mini" @click="handleQuery">搜索</el-button>
        <el-button icon="el-icon-refresh" size="mini" @click="resetQuery">重置</el-button>
      </el-form-item>
    </el-form>

    <el-table
      v-if="refreshTable"
      v-loading="loading"
      :data="searchResult"
      row-key="sha256"
      :default-expand-all="isExpandAll"
      :tree-props="{children: 'children', hasChildren: 'hasChildren'}"
      >
      
      <el-table-column prop="sha256" label="证书 Sha256" width="275"></el-table-column>

      <el-table-column prop="subject_cn_list" label="主体名称" align="center" width="225">
        <template #default="scope">
          <div>
            <div
              v-for="(item, index) in parsedSubjectCNList(scope).slice(0, 5)"
              :key="index"
              style="white-space: normal;"
            >
              {{ item }}
            </div>
            <div v-if="parsedSubjectCNList(scope).length > 5" style="color: #999;">
              剩余 {{ parsedSubjectCNList(scope).length - 5 }} 个未显示
            </div>
          </div>
        </template>
      </el-table-column>

      <el-table-column prop="subject_org" label="所属机构" align="center" width="225"></el-table-column>

      <el-table-column label="签发者" align="center" width="225">
        <template #default="scope">
          <div align="left">CN: {{ scope.row.issuer_cn || '-' }}</div>
          <div align="left">O: {{ scope.row.issuer_org || '-' }}</div>
          <div align="left">C: {{ scope.row.issuer_country || '-' }}</div>
        </template>
      </el-table-column>

      <el-table-column prop="not_valid_before" label="有效期开始时间" align="center" width="160">
        <!-- <template slot-scope="scope">
          <span>{{ parseTime(scope.row.startTime) }}</span>
        </template> -->
      </el-table-column>
      <el-table-column prop="not_valid_after" label="有效期截止时间" align="center" width="160">
        <!-- <template slot-scope="scope">
          <span>{{ parseTime(scope.row.startTime) }}</span>
        </template> -->
      </el-table-column>
      
      <el-table-column label="Cert Link" align="center" width="100">
        <template slot-scope="scope">
          <router-link :to="'/cert/cert_view/' + scope.row.sha256" class="link-type">
            <span>{{ "See Details" }}</span>
          </router-link>
        </template>
      </el-table-column>
      
    </el-table>

    <pagination
      v-show="total>0"
      :total="total"
      :page.sync="queryParams.pageNum"
      :limit.sync="queryParams.pageSize"
      @pagination="handleQuery"
    />

    <el-divider />



  </div>
</template>


<script>
import { searchCert } from "@/api/cert/cert_search";
import Treeselect from "@riophae/vue-treeselect";
import "@riophae/vue-treeselect/dist/vue-treeselect.css";

export default {
  name: "CertSearch",
  dicts: ['sys_cert_type'],
  components: { Treeselect },
  data() {
    return {
      // 遮罩层
      loading: true,
      // 显示搜索条件
      showSearch: true,
      // 表格树数据
      searchResult: [],
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
        pageNum: 1,
        pageSize: 10,
        sha256: undefined,
        subject: undefined
      },
      notValidBeforeRange: [],
      notValidAfterRange: [],
      // 总条数
      total: 0,
    };
  },
  created() {
    this.loading = false;
  },
  methods: {
    handleQuery() {
      this.loading = true;
      let queryParams = this.addDateRange(this.queryParams, this.notValidBeforeRange, "NotValidBefore")
      let finalQueryParams = this.addDateRange(queryParams, this.notValidAfterRange, "NotValidAfter")
      console.log(finalQueryParams)

      searchCert(finalQueryParams).then(response => {
        this.searchResult = response.data;
        this.total = response.total;
        this.loading = false;
      });
    },
    resetQuery() {
      this.resetForm("queryForm");
    },
    parsedSubjectCNList(scope) {
      try {
        return JSON.parse(scope.row.subject_cn_list || '[]');
      } catch {
        return [];
      }
    }
  },
};
</script>
