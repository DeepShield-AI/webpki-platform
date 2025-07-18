<template>
  <div :style="{ paddingLeft: depth * 18 + 'px' }" class="recursive-container">
    <div v-for="(value, key) in data" :key="key" class="dict-item">

      <!-- 特殊处理 extensions -->
      <template v-if="key === 'extensions' && Array.isArray(value)">
        <div class="extensions-container">
          <div class="recursive-key">X509v3 Extensions:</div>

          <div
            v-for="(extension, idx) in value"
            :key="idx"
            class="extension-item"
          >
            <div class="extension-header">
              <span class="extension-name">
                {{ mapExtensionName(extension['extn_id']) }}:
              </span>
              <span
                v-if="extension.critical !== undefined"
                class="extension-critical"
              >
                {{ extension.critical ? 'critical' : 'non-critical' }}
              </span>
            </div>

            <div class="extension-value">
              <template v-if="isArray(extension['extn_value'])">
                <div
                  v-for="(item, index) in extension['extn_value']"
                  :key="index"
                  class="extension-value-item"
                >
                  <RecursiveDict
                    v-if="isObject(item)"
                    :data="item"
                    :depth="depth + 2"
                    :fieldOrder="fieldOrder"
                  />
                  <code v-else class="extension-value extension-plain-value">{{ formatValue(index, item) }}</code>
                </div>
              </template>

              <template v-else-if="isObject(extension['extn_value'])">
                <RecursiveDict
                  :data="extension['extn_value']"
                  :depth="depth + 2"
                  :fieldOrder="fieldOrder"
                />
              </template>

              <template v-else>
                <div class="extension-value extension-plain-value">
                  {{ formatValue("key", extension['extn_value']) }}
                </div>
              </template>
            </div>
          </div>
        </div>
      </template>

      <!-- Object 类型 -->
      <template v-else-if="isObject(value) && value !== null">
        <div class="dict-child">
          <span class="recursive-key">{{ formatKey(key) }}:</span>
          <RecursiveDict
            :data="value"
            :depth="depth + 1"
            :fieldOrder="fieldOrder"
          />
        </div>
      </template>

      <!-- Array 类型 -->
      <template v-else-if="isArray(value) && value !== null">
        <div class="recursive-array">
          <span class="recursive-key">{{ formatKey(key) }}:</span>
          <div
            v-for="(item, index) in value"
            :key="index"
            class="recursive-array-item"
          >
            <RecursiveDict
              v-if="isObject(item)"
              :data="item"
              :depth="depth + 1"
              :fieldOrder="fieldOrder"
            />
            <code v-else class="recursive-value">{{ formatValue(index, item) }}</code>
          </div>
        </div>
      </template>

      <!-- 基础类型 -->
      <template v-else-if="value !== null">
        <div class="recursive-item">
          <span class="recursive-key">{{ formatKey(key) }}:</span>
          <code v-if="isURL(value)" class="recursive-link">
            <a :href="value" target="_blank" rel="noopener noreferrer">{{ value }}</a>
          </code>
          <code v-else class="recursive-value">{{ formatValue(key, value) }}</code>
        </div>
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
      default: () => []
    }
  },
  methods: {
    mapExtensionName(extnId) {
      if (!extnId) return '';
      const map = {
        authority_key_identifier: 'X509v3 Authority Key Identifier',
        key_identifier: 'X509v3 Key Identifier',
        subject_alt_name: 'X509v3 Subject Alternative Name',
        subject_alternative_name: 'X509v3 Subject Alternative Name',
        certificate_policies: 'X509v3 Certificate Policies',
        key_usage: 'X509v3 Key Usage',
        extended_key_usage: 'X509v3 Extended Key Usage',
        crl_distribution_points: 'X509v3 CRL Distribution Points',
        authority_information_access: 'X509v3 Authority Information Access',
        basic_constraints: 'X509v3 Basic Constraints',
        signed_certificate_timestamp_list: 'X509v3 Signed Certificate Timestamps'
      };
      return map[extnId.toLowerCase()] || extnId;
    },
    isURL(value) {
      return typeof value === 'string' && value.startsWith('http');
    },
    isObject(value) {
      return value && typeof value === 'object' && !Array.isArray(value);
    },
    isArray(value) {
      return Array.isArray(value);
    },
    formatKey(key) {
      return key
        .replace(/_/g, ' ')
        .replace(/\b\w/g, l => l.toUpperCase());
    },
    formatValue(key, value) {
      if (key === 'serial_number' && typeof value === 'number') {
        return BigInt(value).toString(); // 避免科学计数法
      }

      if (key === 'modulus' && typeof value === 'string') {
        const clean = value.replace(/\s+/g, '').toUpperCase();
        const bytes = clean.match(/.{1,2}/g) || [];
        const lines = [];
        for (let i = 0; i < bytes.length; i += 16) {
          lines.push(bytes.slice(i, i + 16).join(':'));
        }
        return lines.join('\n');
      }

      if (typeof value === 'string') {
        // 如果字符串很长，分行显示（每64字符换行）
        const maxLen = 64;
        if (value.length > maxLen) {
          const regex = new RegExp(`.{1,${maxLen}}`, 'g');
          return value.match(regex).join('\n');
        }
      }

      if (typeof value === 'number') {
        return Number.isFinite(value)
          ? value.toLocaleString('fullwide', { useGrouping: false })
          : String(value);
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
  white-space: nowrap;
}

.dict-item {
  margin: 2px 0;
}

.recursive-key {
  color: #003366;
  font-weight: bold;
  min-width: 160px;
  display: inline-block;
  white-space: nowrap;
  margin-right: 6px;
}

.recursive-item {
  display: flex;
  align-items: flex-start;
}

.recursive-value,
.recursive-link {
  white-space: pre-wrap;
  font-family: inherit;
}

.recursive-link a {
  color: #1a73e8;
  text-decoration: underline;
}

.dict-child {
  margin-bottom: 10px;
}

.recursive-array-item {
  margin-bottom: 6px;
  border-left: 2px solid #eee;
}

.extensions-container {
  margin-top: 6px;
  margin-bottom: 12px;
}

.extension-item {
  margin-left: 36px;
  margin-bottom: 10px;
}

.extension-header {
  display: inline;
  align-items: center;
}

.extension-name {
  font-weight: 600;
  color: #004080;
}

.extension-critical {
  color: #d9534f;
  /* font-style: italic; */
}

.extension-value {
  color: #222;
  font-family: monospace;
}

.extension-value-item {
  margin-bottom: 2px;
}

.extension-plain-value {
  padding-left: 48px; /* 或你希望的缩进值，如 20px、24px */
  white-space: pre-wrap;
}

</style>
