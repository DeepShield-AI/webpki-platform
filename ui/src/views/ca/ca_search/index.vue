<template>
  <div class="app-container">
    <el-form :model="queryParams" ref="queryForm" size="small" :inline="true" v-show="showSearch">

      <el-form-item label="CA Name" prop="name">
        <el-input
          v-model="queryParams.name"
          placeholder="请输入 CA Name"
          clearable
          @keyup.enter.native="handleQuery"
        />
      </el-form-item>
      
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
      
      <el-table-column prop="id" label="CA ID" align="center" width="100"></el-table-column>
      <el-table-column prop="subject.common_name" label="Common Name" align="center" width="300" />
      <el-table-column prop="subject.country_name" label="Country" align="center" width="100" />
      <el-table-column prop="subject.organization_name" label="Organization" align="center" width="200" />
            
      <el-table-column label="Link" align="center" width="100">
        <template slot-scope="scope">
          <router-link :to="'/ca/ca_view/' + scope.row.id" class="link-type">
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

</div>
</template>


<script>
import { searchCa } from "@/api/ca/ca_search";
import Treeselect from "@riophae/vue-treeselect";
import "@riophae/vue-treeselect/dist/vue-treeselect.css";

export default {
  name: "CaSearch",
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
      // 是否展开，默认全部展开
      isExpandAll: true,
      // 重新渲染表格状态
      refreshTable: true,
      // 查询参数
      queryParams: {
        pageNum: 1,
        pageSize: 10,
        name: undefined
      },
      total: 0,
    };
  },
  created() {
    this.loading = false;
    this.handleQuery();
  },
  methods: {
    handleQuery() {
      this.loading = true;
      searchCa(this.queryParams).then(response => {
        const data = response.data;

        // 👇 对 subject 做 JSON.parse（如果是字符串）
        data.forEach(row => {
          if (typeof row.subject === 'string') {
            try {
              row.subject = JSON.parse(row.subject);
            } catch (e) {
              row.subject = {};
            }
          }
        });

        this.searchResult = data;
        this.total = response.total;
        this.loading = false;
      });
    },
    resetQuery() {
      this.resetForm("queryForm");
    },
  },
};
</script>
