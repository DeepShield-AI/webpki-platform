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
          <el-table-column label="错误代码" width="200">
            <template slot-scope="scope">
              <el-tag type="info" class="tag-item">
                {{ scope.row.error_code }}
              </el-tag>
            </template>
          </el-table-column>

          <el-table-column label="代码解释" width="400">
            <template slot-scope="scope">
                {{ scope.row.code_info }}
            </template>
          </el-table-column>

          <el-table-column label="错误详情" width="300">
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

        <el-card style="width: 67%; margin: 0 auto;">
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
          <el-table-column label="域名" width="300">
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

          <el-table-column prop="tls_version" label="TLS 版本" width="120">
            <template #default="{ row }">
              {{ formatTLSVersion(row.tls_version) }}
            </template>
          </el-table-column>
          <el-table-column prop="tls_cipher" label="TLS 密钥算法" width="220" />

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
      loading: true,
      refreshTable: true,
      isExpandAll: true,

      activeTab: 'detail',
      certData: {},
      certSecurity: [],
      certGraphData: {},
      deployedHosts: [],

      // static error key info
      errorKeyInfo: {
        "expired": "证书已超过其 “Not Valid After” 字段指定的有效期",
        "validity_too_long": "证书有效期超过了 398 天的推荐上限",
        "weak_rsa": "RSA 或 DSA 密钥长度低于安全建议的 2048 比特",
        "weak_hash": "使用了不安全的哈希算法，如 MD5 或 SHA1",
        "not_asn1": "证书格式不符合标准的 ASN.1 编码规范",
        "self_signed": "证书为自签名证书，未被受信任的根机构签发",
        "abuse_ip": "证书被发现部署在 AbuseIPDB 收录的恶意 IP 上",
        "DROP": "证书被部署在 DROP 黑名单中的 IP 上",
        "wrong_version": "证书版本不是符合规范的 v3 版本",
        "wrong_key_usage": "证书缺少签名或服务器身份认证所需的密钥用途",
        "no_revoke": "证书未包含撤销信息，如 CRL 或 OCSP 数据",
        "no_sct": "证书缺少 Signed Certificate Timestamp (SCT) 信息"
      }
    };
  },
  created() {
    this.certSha256 = this.$route.params && this.$route.params.certSha256;
    this.getCert(this.certSha256);
  },
  methods: {
    getCert(certSha256) {
      this.loading = true;
      // {'msg': 'Success', 'code': 200, "cert_data": cert_parsed, "cert_security" : analyze_result}
      getCertInfo(certSha256).then(response => {
        console.log(response.cert_data);
        this.certData = response.cert_data;

        // 转换为表格需要的数组形式
        this.certSecurity = Object.keys(this.errorKeyInfo).map(code => {
          const info = response.cert_security.error_info[code];

          const isPass =
            info === undefined ||
            info === null ||
            info === "Pass" ||
            (Array.isArray(info) && info.length === 0) ||
            (typeof info === "object" && Object.keys(info).length === 0);

          return {
            error_code: code,                           // 当前错误代码字符串
            code_info: this.errorKeyInfo[code] || "",   // 错误详细描述
            error_info: isPass ? "Pass" : info          // 额外信息
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
      if (val === 'graph' && Object.keys(this.certGraphData).length === 0) {
        this.getCag(this.certSha256);
      }
      if (val === 'deploy' && this.deployedHosts.length === 0) {
        this.getHost(this.certSha256);
      }
    },
    formatInfo(val) {
      if (Array.isArray(val)) {
        return val.join(", ");
      }
      return val;
    },
    formatTLSVersion(version) {
      const versionMap = {
        768: 'TLS 1.0',
        769: 'TLS 1.1',
        770: 'TLS 1.2',
        771: 'TLS 1.2',
        772: 'TLS 1.3',
      };
      return versionMap[version] || version;
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

