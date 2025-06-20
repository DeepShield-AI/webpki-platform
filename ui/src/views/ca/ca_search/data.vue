<template>
  <div class="app-container main">

    <!-- Issuing num and ratio -->
    <!-- <el-row :gutter="20">
      <el-col :sm="24" :lg="24" style="padding-left: 20px">
        <el-card>
          <div slot="header">CA Information</div>
            <RecursiveDict :data="certData" />
        </el-card>
      </el-col>
    </el-row>

    <el-divider /> -->

    <!-- CA Certs SHA -->
    <el-row :gutter="20">
      <el-col :sm="24" :lg="24" style="padding-left: 20px">
        <h2>CA Certificates Owned</h2>

        <div v-if="caCerts.length">
          <ul style="padding-left: 10px;">
            <li
              v-for="(sha, index) in caCerts"
              :key="index"
              style="margin: 6px 0;"
            >
              <router-link
                :to="'/cert/cert_view/' + sha"
                class="link-type"
              >
                {{ sha }}
              </router-link>
            </li>
          </ul>
        </div>
        
        <div v-else style="color: #999;">
          No CA certificates found.
        </div>
      </el-col>
    </el-row>

    <!-- Cert Issuing FP count -->
  </div>

</template>

<script>
import { getCaInfo } from "@/api/ca/ca_search";
import RecursiveDict from '@/components/RecursiveDict';  // 路径根据你实际文件结构调整

export default {
  components: {
    RecursiveDict
  },
  name: "CaView",
  dicts: ['sys_cert_type', 'sys_key_type'],
  data() {
    return {
      loading: true,
      caCerts: [],
      caFps: [],
    };
  },
  created() {
    const caName = this.$route.params && this.$route.params.caName;
    this.getCa(caName);
  },
  methods: {
    getCa(caName) {
      this.loading = true;
      // return jsonify({'msg': 'Success', 'code': 200, "ca_certs": ca_certs, "issuing_cert_fps" : []})
      getCaInfo(caName).then(response => {
        console.log(response.ca_certs);
        this.caCerts = response.ca_certs;
        this.caFps = response.issuing_cert_fps;
        this.loading = false;
      });
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
  .link-type {
    color: #409EFF;
    text-decoration: underline;
    word-break: break-all; /* 避免 SHA 太长撑出页面 */
  }
  .link-type:hover {
    color: #66b1ff;
  }
}
</style>

