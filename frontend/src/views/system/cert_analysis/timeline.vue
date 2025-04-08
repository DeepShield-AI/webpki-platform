<template>
    <div id="timeline"></div>
  </template>
  
  <script>
  import { Timeline } from 'vis-timeline/standalone';
  
  export default {
    mounted() {
      // 定义证书数据
      const items = new vis.DataSet([
        {
          id: 1,
          content: '<a href="/certificate/1" target="_blank">Cert 1<br>Issued by CA1</a>',
          start: '2024-01-01',
          end: '2024-03-01',
        },
        {
          id: 2,
          content: '<a href="/certificate/2" target="_blank">Cert 2<br>Issued by CA2</a>',
          start: '2024-02-15',
          end: '2024-05-01',
        },
        {
          id: 3,
          content: '<a href="/certificate/3" target="_blank">Cert 3<br>Issued by CA3</a>',
          start: '2024-04-01',
          end: '2024-06-01',
        },
      ]);
  
      // 配置时间轴选项
      const options = {
        editable: false, // 禁止直接编辑
        stack: true, // 允许条目堆叠显示
        tooltip: { followMouse: true },
        zoomable: true,
      };
  
      // 初始化时间轴
      const container = document.getElementById('timeline');
      new Timeline(container, items, options);
    },
  };
  </script>
  
  <style>
  #timeline {
    width: 100%;
    height: 400px;
    border: 1px solid #ccc;
  }
  </style>
  