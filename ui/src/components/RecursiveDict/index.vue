<template>
  <div :style="{ paddingLeft: depth * 12 + 'px' }" class="recursive-container">
    <div v-for="(value, key) in orderedData" :key="key" class="dict-item">
      <span class="recursive-key">{{ key }}:</span>

      <!-- ✅ 对象递归 -->
      <template v-if="isObject(value)">
        <RecursiveDict :data="value" :depth="depth + 1" :fieldOrder="fieldOrder" />
      </template>

      <!-- ✅ List of dicts -->
      <template v-else-if="isListOfObjects(value)">
        <div v-for="(item, index) in value" :key="index" class="indent">
          <RecursiveDict :data="item" :depth="depth + 1" :fieldOrder="fieldOrder" />
        </div>
      </template>

      <!-- ✅ 普通数组 -->
      <template v-else-if="isArray(value)">
        <code class="recursive-value">{{ value.join(', ') }}</code>
      </template>

      <!-- ✅ 字符串/值/链接 -->
      <template v-else>
        <code v-if="isURL(value)" class="recursive-link">
          <a :href="value" target="_blank" rel="noopener noreferrer">{{ value }}</a>
        </code>
        <code v-else class="recursive-value">{{ value }}</code>
      </template>
    </div>
  </div>
</template>

<script>
export default {
  name: "RecursiveDict",
  props: {
    data: {
      type: Object,
      required: true
    },
    depth: {
      type: Number,
      default: 0
    },
    fieldOrder: {
      type: Array,
      default: () => [
                'Version', 'Serial Number', 'Signature Algorithm',
                'Issuer', 'Validity', 'Subject', 'Subject Public Key Info',
                'X509v3 extensions', 'Signature Algorithm (again)', 'Signature'
              ]
    }
  },
  computed: {
    orderedData() {
      if (!this.fieldOrder.length) return this.data;
      const ordered = {};
      for (const key of this.fieldOrder) {
        if (key in this.data) ordered[key] = this.data[key];
      }
      for (const key in this.data) {
        if (!(key in ordered)) ordered[key] = this.data[key];
      }
      return ordered;
    }
  },
  methods: {
    isObject(obj) {
      return obj && typeof obj === 'object' && !Array.isArray(obj);
    },
    isArray(val) {
      return Array.isArray(val);
    },
    isListOfObjects(arr) {
      return Array.isArray(arr) && arr.every(i => typeof i === 'object' && i !== null);
    },
    isURL(val) {
      return typeof val === 'string' && /^https?:\/\/[\w.-]+/.test(val);
    }
  }
};
</script>

<style scoped>
.recursive-container {
  font-family: 'Courier New', Courier, monospace;
  font-size: 14px;
  color: #2d2d2d;
  white-space: pre-wrap;
}

.recursive-key {
  color: #003366;
  font-weight: bold;
  display: inline-block;
  margin-right: 4px;
}

.recursive-value {
  color: #333;
}

.recursive-link a {
  color: #1a73e8;
  text-decoration: underline;
}

.indent {
  margin-left: 12px;
}

.dict-item {
  margin: 2px 0;
}
</style>
