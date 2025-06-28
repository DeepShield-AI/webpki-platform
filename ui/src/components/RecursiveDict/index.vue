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
        <div
          v-for="(item, index) in value"
          :key="index"
          class="indent"
          style="margin-bottom: 16px;"
        >
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
        <code v-else class="recursive-value">{{ formatValue(key, value) }}</code>
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
      try {
        new URL(val);
        return true;
      } catch {
        return false;
      }
      return typeof val === 'string' && /^https?:\/\/[^\s]+$/.test(val);
    },
    formatValue(key, value) {
      // 显示 serial_number 的完整十进制
      if (key === 'serial_number' && typeof value === 'number') {
        return BigInt(value).toString(); // 防止科学计数法
      }

      // 显示 modulus 的十六进制格式
      if (key === 'modulus') {
        if (!value) return '';
        const clean = value.replace(/\s+/g, '').toUpperCase(); // 清除空白并统一大写

        // 按两个字符（1 字节）分组
        const bytes = clean.match(/.{1,2}/g) || [];

        // 每 16 字节（32 hex 位）为一行
        const lines = [''];
        for (let i = 0; i < bytes.length; i += 16) {
          const line = bytes.slice(i, i + 16).join(':');
          lines.push('    ' + line); // 缩进
        }

        return lines.join('\n');
      }

      // 其他值默认显示（避免科学计数法）
      if (typeof value === 'number' && !Number.isFinite(value)) {
        return String(value); // 处理 Infinity、NaN
      }

      if (typeof value === 'number') {
        return value.toLocaleString('fullwide', { useGrouping: false }); // 全部数字显示出来
      }

      return value;
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
