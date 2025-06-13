<template>
  <div :style="{ paddingLeft: depth * 20 + 'px' }">
    <div v-for="(value, key) in data" :key="key">
      <strong>{{ key }}:</strong>

      <!-- ✅ 如果是对象：递归展开 -->
      <template v-if="isObject(value)">
        <RecursiveDict :data="value" :depth="depth + 1" />
      </template>

      <!-- ✅ 如果是 list of dicts：逐项递归展开 -->
      <template v-else-if="isListOfObjects(value)">
        <div v-for="(item, index) in value" :key="index">
          <div :style="{ paddingLeft: (depth + 1) * 20 + 'px' }">
            <strong>[{{ index }}]</strong>
            <RecursiveDict :data="item" :depth="depth + 2" />
          </div>
        </div>
      </template>

      <!-- ✅ 如果是普通数组 -->
      <template v-else-if="isArray(value)">
        <code>{{ value.join(', ') }}</code>
      </template>

      <!-- ✅ 普通值 -->
      <template v-else>
        <code>{{ value }}</code>
      </template>
    </div>
  </div>
</template>

<script>
import DictTag from '@/components/DictTag';  // 路径根据你实际文件结构调整

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
    checkKeyInDict(key) {
      return [false, null];
    }
  },
};
</script>

<style>
.indent {
  margin-top: 4px;
}
.dict-item {
  margin-bottom: 4px;
}
</style>
