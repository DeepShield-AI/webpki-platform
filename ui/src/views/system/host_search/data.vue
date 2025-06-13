<template>
  <div class="app-container main">
    <el-row :gutter="20">
      <el-col :sm="24" :lg="24" style="padding-left: 20px">
        <h2>Host Security Analysis</h2>
      </el-col>
    </el-row>

    <el-row :gutter="20" v-if="hostSecurity && hostSecurity.length">
      <el-col :span="24" v-for="(item, index) in hostSecurity" :key="index" style="margin-bottom: 20px;">
        <el-card shadow="hover">
          <div>
            <p><strong>Domain:</strong> {{ item.domain }}</p>
            <p><strong>IP:</strong> {{ item.ip }}</p>
            <p><strong>TLS Version:</strong> {{ item.tls_version }}</p>
            <p><strong>TLS Cipher:</strong> {{ item.tls_cipher }}</p>

            <p><strong>错误代码:</strong>
              <el-tag
                v-for="(code, idx) in item.error_code"
                :key="idx"
                type="danger"
                style="margin-right: 5px;"
              >
                {{ code }}
              </el-tag>
            </p>

            <p><strong>错误信息:</strong></p>
            <div
              v-if="Object.keys(item.error_info || {}).length === 0"
              style="margin-left: 10px; color: #999;"
            >
              — 无
            </div>
            <div v-else style="margin-left: 10px;">
              <p
                v-for="(val, key) in item.error_info"
                :key="key"
                style="margin-bottom: 4px;"
              >
                <strong>{{ key }}:</strong> <span>{{ formatInfo(val) }}</span>
              </p>
            </div>

            <p><strong>证书指纹 (SHA256 List):</strong></p>
            <ul style="margin-left: 20px;">
              <li
                v-for="(sha, shaIdx) in item.cert_hash_list"
                :key="shaIdx"
              >
                <router-link
                  :to="`/system/cert_view/${sha}`"
                  style="color: #409EFF;"
                >
                  {{ sha }}
                </router-link>
              </li>
            </ul>
          </div>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script>
import { getHostInfo } from "@/api/system/host_search";
import RecursiveDict from '@/components/RecursiveDict';  // 路径根据你实际文件结构调整

export default {
  components: {
    RecursiveDict
  },
  name: "HostView",
  // dicts: ['sys_cert_type', 'sys_key_type'],
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
      hostSecurity: {
        type: Object, // 👈 dict 类型
        required: true,
        loading: false
      },
    };
  },
  created() {
    const targetHost = this.$route.params && this.$route.params.host;
    this.getHost(targetHost);
  },
  methods: {
    getHost(host) {
      this.loading = true;
      // return jsonify({'msg': 'Success', 'code': 200, "web_security" : final_result})
      getHostInfo(host).then(response => {
        this.hostSecurity = response.host_security;
        this.loading = false;
      });
    },
    formatInfo(val) {
      if (Array.isArray(val)) {
        return val.join(', ');
      } else if (typeof val === 'object' && val !== null) {
        return JSON.stringify(val);
      } else {
        return String(val);
      }
    },
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

