<template>
  <div class="app-container main">
    <el-row :gutter="20">
      <el-col :sm="24" :lg="24" style="padding-left: 20px">
        <el-card>
          <div slot="header">Certificate Information</div>
            <RecursiveDict :data="certData" />
        </el-card>
      </el-col>
    </el-row>

    <el-divider />

    <el-row :gutter="20">
      <el-col :sm="24" :lg="24" style="padding-left: 20px">
        <h2>Certificate Security Analysis</h2>
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
        <template #default="scope">
          <el-tag type="danger" class="tag-item">
            {{ scope.row.error_code }}
          </el-tag>
        </template>
      </el-table-column>

      <el-table-column label="错误详情">
        <template #default="scope">
          <!-- ✅ 情况 1：通过，显示绿色 -->
          <el-tag type="success" v-if="scope.row.error_info === 'Pass'">
            Pass
          </el-tag>

          <!-- ✅ 情况 2：字符串类型，显示为红色 -->
          <el-tag type="danger" v-else-if="typeof scope.row.error_info === 'string'">
            {{ scope.row.error_info }}
          </el-tag>

          <!-- ✅ 情况 3：数组类型，逐行显示 -->
          <div v-else-if="Array.isArray(scope.row.error_info)">
            <div
              v-for="(item, idx) in scope.row.error_info"
              :key="idx"
              style="color: red; line-height: 1.5;"
            >
              {{ item }}
            </div>
          </div>

          <!-- ✅ 情况 4：对象类型，逐键显示 -->
          <div v-else-if="typeof scope.row.error_info === 'object' && scope.row.error_info !== null">
            <div
              v-for="(val, key) in scope.row.error_info"
              :key="key"
              style="color: red; line-height: 1.5;"
            >
              <strong>{{ key }}:</strong> {{ formatInfo(val) }}
            </div>
          </div>

          <!-- ❓ 情况 5：空或未知类型 -->
          <span v-else style="color: #999;">—</span>
        </template>
      </el-table-column>

    </el-table>

    <!-- <el-divider />

    <el-row :gutter="20">
      <el-col :sm="24" :lg="24" style="padding-left: 20px">
        <h2>证书链关系</h2>
      </el-col>
    </el-row>

    <el-divider />

    <el-row :gutter="20">
      <el-col :xs="24" :sm="24" :md="24" :lg="24">
        <h2>证书吊销状态</h2>
      </el-col>
    </el-row> -->
  </div>

</template>

<script>
import { getCertInfo } from "@/api/cert/cert_search";
import RecursiveDict from '@/components/RecursiveDict';  // 路径根据你实际文件结构调整

export default {
  components: {
    RecursiveDict
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
      // 证书信息
      certData: {
        type: Object, // 👈 dict 类型
        required: true,
      },
      certSecurity: [],

      // static error key
      totalErrorKeys: [
        "expired",
        "validity_too_long",
        "weak_rsa",
        "weak_hash",
        "not_asn1",
        "self_signed",
        "abuse_ip",
        "DROP",
        "wrong_version",
        "wrong_key_usage",
        "no_revoke",
        "no_sct"
      ]
    };
  },
  created() {
    const certSha256 = this.$route.params && this.$route.params.certSha256;
    this.getCert(certSha256);
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
        this.certSecurity = this.totalErrorKeys.map(code => {
          const info = response.cert_security.error_info[code];

          const isPass =
            info === undefined ||
            info === null ||
            info === "Pass" ||
            (Array.isArray(info) && info.length === 0) ||
            (typeof info === "object" && Object.keys(info).length === 0);

          return {
            error_code: code,
            error_info: isPass ? "Pass" : info
          };
        });

        this.loading = false;
      });
    },
    isObject(value) {
      return value !== null && typeof value === 'object';
    },
    // checkKeyInDict(key) {
    //   if (key === "cert_type") {
    //     return [true, this.dict.type.sys_cert_type || ''];
    //   } else if (key === "subject_pub_key_algo") {
    //     return [true, this.dict.type.sys_key_type || ''];
    //   } else {
    //     return [false, ''];
    //   }
    // },
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

