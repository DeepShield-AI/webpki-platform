<template>
  <div class="app-container main">
    <el-tabs :value="activeTab" @input="handleTabChange" type="card">
      <!-- 证书详情 -->
      <el-tab-pane label="证书详情" name="detail">
        <el-row :gutter="20">
          <el-col :sm="24" :lg="24" style="padding-left: 20px">
            <h2>证书详情</h2>
            <el-card>
              <RecursiveDict :data="certData" />
            </el-card>
          </el-col>
        </el-row>
      </el-tab-pane>

      <!-- 证书安全分析 -->
      <el-tab-pane label="证书安全分析" name="security">
        <el-row :gutter="20">
          <el-col :sm="24" :lg="24" style="padding-left: 20px">
            <h2>证书安全分析</h2>
          </el-col>
        </el-row>

        <el-table
          v-if="refreshTable"
          v-loading="loading"
          :data="certSecurity"
          :default-expand-all="isExpandAll"
          :tree-props="{ children: 'children', hasChildren: 'hasChildren' }"
          style="width: 100%"
        >
          <el-table-column label="错误代码">
            <template slot-scope="scope">
              <el-tag type="danger" class="tag-item">
                {{ scope.row.error_code }}
              </el-tag>
            </template>
          </el-table-column>

          <el-table-column label="错误详情">
            <template slot-scope="scope">
              <el-tag type="success" v-if="scope.row.error_info === 'Pass'">Pass</el-tag>
              <el-tag type="danger" v-else-if="typeof scope.row.error_info === 'string'">
                {{ scope.row.error_info }}
              </el-tag>
              <div v-else-if="Array.isArray(scope.row.error_info)">
                <div
                  v-for="(item, idx) in scope.row.error_info"
                  :key="idx"
                  style="color: red; line-height: 1.5;"
                >
                  {{ item }}
                </div>
              </div>
              <div
                v-else-if="typeof scope.row.error_info === 'object' && scope.row.error_info !== null"
              >
                <div
                  v-for="(val, key) in scope.row.error_info"
                  :key="key"
                  style="color: red; line-height: 1.5;"
                >
                  <strong>{{ key }}:</strong> {{ formatInfo(val) }}
                </div>
              </div>
              <div v-else>
                <el-tag type="danger">FAILED</el-tag>
              </div>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane label="证书资源关系图" name="graph">  
        <el-row :gutter="20">
          <el-col :sm="24" :lg="24" style="padding-left: 20px">
            <h2>证书资源关系图</h2>
          </el-col>
        </el-row>

        <el-card>
          <cag :graph-data="certGraphData" />
        </el-card>
      </el-tab-pane>

      <!-- 证书部署位置 -->
      <el-tab-pane label="证书部署位置" name="deploy">
        <el-row :gutter="20">
          <el-col :xs="24" :sm="24" :md="24" :lg="24">
            <h2>证书部署位置</h2>
          </el-col>
        </el-row>

        <el-table
          v-if="refreshTable"
          v-loading="loading"
          :data="deployedHosts"
          :default-expand-all="isExpandAll"
          :tree-props="{ children: 'children', hasChildren: 'hasChildren' }"
        >
          <el-table-column label="Domain" width="300">
            <template slot-scope="{ row }">
              <router-link :to="`/host/host_view/${row.destination_host}`" style="color: #409EFF;">
                {{ row.destination_host }}
              </router-link>
            </template>
          </el-table-column>

          <el-table-column label="IP" width="160">
            <template slot-scope="{ row }">
              <router-link :to="`/host/host_view/${row.destination_ip}`" style="color: #409EFF;">
                {{ row.destination_ip }}
              </router-link>
            </template>
          </el-table-column>

          <el-table-column prop="tls_version" label="TLS Version" width="120" />
          <el-table-column prop="tls_cipher" label="TLS Cipher" width="160" />

          <el-table-column label="证书指纹 (SHA256 List)" width="550">
            <template slot-scope="{ row }">
              <ul style="padding-left: 16px; margin: 0;">
                <li
                  v-for="(sha, shaIdx) in Array.isArray(row.cert_hash_list)
                    ? row.cert_hash_list
                    : JSON.parse(row.cert_hash_list || '[]')"
                  :key="shaIdx"
                >
                  <router-link :to="`/cert/cert_view/${sha}`" style="color: #409EFF;">
                    {{ sha }}
                  </router-link>
                </li>
              </ul>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script>
import { getCertInfo, getCertDeployInfo } from "@/api/cert/cert_search";
import { getSubCag } from "@/api/host/host_analysis";
import Treeselect from "@riophae/vue-treeselect";
import "@riophae/vue-treeselect/dist/vue-treeselect.css";
import RecursiveDict from '@/components/RecursiveDict';  // 路径根据你实际文件结构调整
import Cag from '@/views/host/host_analysis/cag';
import EChart from 'vue-echarts';

export default {
  components: {
    RecursiveDict, Treeselect, Cag, 'v-chart': EChart
  },
  name: "CertView",
  dicts: ['sys_cert_type', 'sys_key_type'],

  data() {
    return {
      // 遮罩层
      loading: true,
      refreshTable: true,
      isExpandAll: true,
      // 弹出层标题
      title: "",
      // 是否显示弹出层
      open: false,

      activeTab: 'detail',
      certData: {
        type: Object, // 👈 dict 类型
        required: true,
      },
      certSecurity: [],
      deployedHosts: [],
      certGraphData: {
        type: Object, // 👈 dict 类型
        required: true,
      },

      // static error key info
      totalErrorKeyInfo: {
        "expired": "证书已过期",
        "validity_too_long": "证书有效期过长",
        "weak_rsa": "RSA 密钥强度过低",
        "weak_hash": "使用了弱哈希算法 (如 MD5 或 SHA1)",
        "not_asn1": "证书格式非标准 ASN.1 编码",
        "self_signed": "自签名证书（未受信任）",
        "abuse_ip": "证书部署在恶意 IP (AbuseIPDB) 上",
        "DROP": "证书被主动丢弃或列入黑名单",
        "wrong_version": "TLS/SSL 版本不符合规范",
        "wrong_key_usage": "证书密钥用途错误或缺失",
        "no_revoke": "证书未提供撤销信息 (CRL 或 OCSP)",
        "no_sct": "缺少透明度日志 (SCT) 信息"
      }
    };
  },
  created() {
    const certSha256 = this.$route.params && this.$route.params.certSha256;
    this.getCert(certSha256);
    this.getCag(certSha256);
    this.getHost(certSha256);
  },
  methods: {
    getCert(certSha256) {
      this.loading = true;
      // {'msg': 'Success', 'code': 200, "cert_data": cert_parsed, "cert_security" : analyze_result}
      getCertInfo(certSha256).then(response => {
        console.log(response.cert_data);
        this.certData = response.cert_data;

        // 转换为表格需要的数组形式
        console.log(response.cert_security);
        this.certSecurity = Object.keys(this.totalErrorKeyInfo).map(code => {
          const info = response.cert_security.error_info[code];

          const isPass =
            info === undefined ||
            info === null ||
            info === "Pass" ||
            (Array.isArray(info) && info.length === 0) ||
            (typeof info === "object" && Object.keys(info).length === 0);

          return {
            error_code: this.totalErrorKeyInfo[code],  // ✅ 中文名
            error_info: isPass ? "Pass" : info         // ✅ 保留原始结构
          };
        });

        this.loading = false;
      });
    },
    getCag(certSha256){
      this.loading = true;
      const query = {
        "cert_sha256" : certSha256
      };
      // return jsonify({'msg': 'Success', 'code': 200, "data": graph_data})
      getSubCag(query).then(response => {
        this.certGraphData = response.data;
        this.loading = false;
      });
    },
    getHost(certSha256) {
      this.loading = true;
      // return jsonify({'msg': 'Success', 'code': 200, "web_security" : final_result})
      getCertDeployInfo(certSha256).then(response => {
        this.deployedHosts = response.deploy_hosts;
        this.loading = false;
      });
    },
    isObject(value) {
      return value !== null && typeof value === 'object';
    },
    handleTabChange(val) {
      this.activeTab = val;
      // 你可以在这里根据 tab 切换执行额外逻辑
      // if (val === 'security') this.loadSecurityAnalysis();
    },
    formatInfo(val) {
      if (Array.isArray(val)) {
        return val.join(", ");
      }
      return val;
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

  .update-log {
    ol {
      display: block;
      list-style-type: decimal;
      margin-block-start: 1em;
      margin-block-end: 1em;
      margin-inline-start: 0;
      margin-inline-end: 0;
      padding-inline-start: 40px;
    }
  }
  .certificate-item {
  margin-bottom: 8px;
  }
  strong {
    font-family: 'Courier New', monospace;
    background-color: #f4f4f4;
    padding: 2px 2px;
    border-radius: 4px;
    display: inline-block;
    line-height: 2.5;
  }
  .code-block {
    font-family: 'Courier New', monospace;
    padding: 2px 4px;
    border-radius: 4px;
    display: inline-block;
  }

  .tag-item {
    margin: 2px;
  }
  .error-info-item {
    margin-bottom: 4px;
    line-height: 1.4;
  }

}
</style>

