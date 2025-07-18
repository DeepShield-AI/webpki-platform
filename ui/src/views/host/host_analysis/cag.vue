<template>
  <div class="cert-graph-container">

    <div v-loading="loading" style="width: 100%; height: auto;">
      <svg ref="graphSvg" width="100%" :height="height"></svg>
    </div>

    <el-row>
      <el-col :span="24">
        <el-tabs v-model="activeTab">
          <el-tab-pane label="Certificates" name="certificates">
            <el-table :data="certList" style="width: 100%">
              <el-table-column
                label="#"
                type="index"
                width="50"
              />

              <el-table-column prop="sha256" label="Hash">
                <template #default="{ row }">
                  <router-link
                    :to="`/system/cert_view/${row.sha256}`"
                    style="color: #409EFF;"
                  >
                    {{ row.sha256 }}
                  </router-link>
                </template>
              </el-table-column>

            </el-table>
          </el-tab-pane>
        </el-tabs>
      </el-col>
    </el-row>

  </div>
</template>

<script>
import * as d3 from "d3";

export default {
  name: "Cag",
  props: {
    graphData: {
      type: Object,
      required: true,
    },
    width: {
      type: Number,
      default: 500,
    },
    height: {
      type: Number,
      default: 500,
    },
  },
  data() {
    return {
      loading : false,
      svgRoot: null,
      simulation: null,
      color: d3.scaleOrdinal(d3.schemeCategory10),
      
      selectedNode: null,
      infoBoxConfig: null,

      activeTab: 'certificates',
      certList: [],
      items: [],
    };
  },

  // this.$nextTick(...) 的作用是：等 DOM 渲染完成后再执行函数，确保 this.$el 存在。
  watch: {
    graphData: {
      handler(newData) {
        console.log('New Graph:', newData);
        if (newData) {
          this.$nextTick(() => {
            console.log('Before resetGraph and createGraph');
            this.resetGraph();
            console.log('After resetGraph');
            this.createGraph(null, newData);
            console.log('After createGraph');
          });
        }
      },
      immediate: true,
    },
  },

  // starts here
  mounted() {
    this.initGraph();  // 放图初始化逻辑
  },
  methods: {
    initGraph() {
      this.svgRoot = d3.select(this.$refs.graphSvg); // 根 SVG
      this.svgRoot
        .append("defs")
        .append("marker")
        .attr("id", "arrow")
        .attr("viewBox", "0 -5 10 10")
        .attr("refX", 20)
        .attr("refY", 0)
        .attr("markerWidth", 8)
        .attr("markerHeight", 8)
        .attr("orient", "auto")
        .append("svg:path")
        .attr("d", "M0,-5L10,0L0,5");

      this.svgRoot.append("defs").append("filter")
        .attr("id", "info-shadow")
        .append("feDropShadow")
        .attr("dx", 2)
        .attr("dy", 2)
        .attr("stdDeviation", 2)
        .attr("flood-color", "#000")
        .attr("flood-opacity", 0.2);

      // 图层：缩放区域
      this.graphLayer = this.svgRoot
        .call(d3.zoom().on("zoom", this.zoomed))
        .append("g")
        .attr("class", "zoom-layer");

      // 图层：图例区域，不缩放
      this.legendLayer = this.svgRoot
        .append("g")
        .attr("class", "legend-layer");

      console.log('width:', this.width, 'height:', this.height);
      this.simulation = d3.forceSimulation()
        .force(
          "link",
          d3.forceLink()
            .id(d => d.id)
            // .distance(d => (d.source.root || d.target.root) ? 100 : 50)
        )
        .force("charge", d3.forceManyBody().strength(-200))
        .force("collide", d3.forceCollide().radius(15))
        .force("center", d3.forceCenter(this.width / 2, this.height / 2).strength(0.5))
    },

    resetGraph() {
      d3.select(this.$refs.graphSvg).select("g").selectAll("*").remove();
      this.createTables([]);
    },

    // this 
    createGraph(error, graph) {
      if (error) throw error;
      if (!graph || typeof graph !== 'object' || !Array.isArray(graph.nodes) || !Array.isArray(graph.links)) {
        console.warn('Invalid graph data:', graph);
        return;
      }

      const link = this.graphLayer
        .append("g")
        .attr("class", "links")
        .selectAll("line")
        .data(graph.links)
        .enter()
        .append("line")
        .attr("stroke", (d) => this.color(d.type))
        .attr("marker-end", "url(#arrow)");

      const text = this.graphLayer
        .append("g")
        .attr("class", "labels")
        .selectAll("g")
        .data(graph.nodes)
        .enter()
        .append("g");

      text
        .append("text")
        .attr("x", 14)
        .attr("y", ".31em")
        .style("font-family", "sans-serif")
        .style("font-size", "0.7em")
        .text(function (d) {
          return d.name;
        });

      const node = this.graphLayer
        .append("g")
        .attr("class", "nodes")
        .selectAll("circle")
        .data(graph.nodes)
        .enter()
        .append("circle")
        .attr("r", d => {
          if (d.root) return 15;
          if (d.type === 'cert') return 12;
          if (d.type === 'domain') return 12;
          return 8;
        })
        .attr("fill", (d) => {
          if (d.root == "true") return this.color(d.root);
          return this.color(d.type);
        })
        .attr("class", d => d.root ? "main-node root-outline" : "main-node")
        .call(
          d3
            .drag()
            .on("start", this.dragstarted)
            .on("drag", this.dragged)
            .on("end", this.dragended)
        );

      node.on("click", (event, d) => {
        this.showInfoBox(d);
      });

      this.svgRoot.on("click", (event) => {
        if (event.target.tagName !== 'circle') {
          this.svgRoot.selectAll(".info-box").remove();
          this.selectedNode = null;
          this.infoBoxConfig = null;
        }
      });

      node.append("title").text(function (d) {
        return d.name;
      });

      this.simulation.nodes(graph.nodes).on("tick", this.ticked);

      this.simulation.force("link").links(graph.links);

      this.createTables(Array.isArray(graph.nodes) ? graph.nodes : []);

      // ----- 图例绘制（固定不随缩放） -----
      this.legendLayer.selectAll("*").remove(); // 清除旧图例

      const nodeTypes = [...new Set(graph.nodes.map(n => n.type))];

      const legend = this.legendLayer
        .append("g")
        .attr("class", "legend")
        .attr("transform", `translate(20, 20)`);

      nodeTypes.forEach((type, i) => {
        const legendRow = legend.append("g")
          .attr("transform", `translate(0, ${i * 20})`);

        legendRow.append("circle")
          .attr("r", 6)
          .attr("fill", this.color(type));

        legendRow.append("text")
          .attr("x", 12)
          .attr("y", 4)
          .text(type)
          .style("font-size", "12px")
          .style("font-family", "sans-serif");

        // legend.insert("rect", ":first-child")
        //   .attr("x", -10)
        //   .attr("y", -10)
        //   .attr("width", 120)
        //   .attr("height", nodeTypes.length * 20 + 10)
        //   .attr("fill", "#fff")
        //   .attr("stroke", "#ccc")
        //   .attr("rx", 6)
        //   .attr("ry", 6);
      });
    },

    // these are d3 events
    ticked() {
      const link = d3.selectAll(".links line");
      const node = d3.selectAll(".nodes circle");
      const text = d3.selectAll(".labels g");

      link
        .attr("x1", d => d.source.x)
        .attr("y1", d => d.source.y)
        .attr("x2", d => d.target.x)
        .attr("y2", d => d.target.y);

      node
        .attr("cx", d => d.x)
        .attr("cy", d => d.y);

      text.attr("transform", d => `translate(${d.x},${d.y})`);

      // ✅ 移动 info-box
      if (this.selectedNode) {
        const { x, y } = this.selectedNode;
        const boxX = x + 15;
        const boxY = y - 10;
        const { fontSize, padding, lines, boxWidth } = this.infoBoxConfig || {};
        const boxHeight = lines.length * (fontSize + 4) + padding * 2;

        const infoBox = this.svgRoot.select(".info-box");

        infoBox.select("rect.info-rect")
          .attr("x", boxX)
          .attr("y", boxY)
          .attr("width", boxWidth)
          .attr("height", boxHeight);

        infoBox.selectAll("text.info-line")
          .attr("x", boxX + padding)
          .attr("y", (d, i) => boxY + padding + (i + 1) * (fontSize + 2));
      }
    },

    dragstarted(event, d) {
      if (!event.active) this.simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    },

    dragged(event, d) {
      d.fx = event.x;
      d.fy = event.y;
    },

    dragended(event, d) {
      if (!event.active) this.simulation.alphaTarget(0);
      d.fx = null;
      d.fy = null;
    },

    zoomed(event) {
      this.graphLayer.attr(
        "transform",
        `translate(${event.transform.x},${event.transform.y}) scale(${event.transform.k})`
      );
    },

    showInfoBox(d) {
      this.svgRoot.selectAll(".info-box").remove();

      this.selectedNode = d; // ✅ 保存选中的节点引用

      const fontSize = 12;
      const padding = 6;
      const lines = [
        `Type: ${d.type}`,
        `Name: ${d.name}`,
        `Root: ${d.root}`,
      ];

      this.infoBoxConfig = { lines, fontSize, padding, boxWidth: 180 };

      const infoGroup = this.svgRoot.append("g").attr("class", "info-box");

      // 你可以不加 position，现在 tick 中再处理位置
      lines.forEach((line, i) => {
        infoGroup.append("text")
          .attr("class", "info-line")
          .attr("font-size", fontSize)
          .attr("fill", "#333")
          .text(line);
      });

      infoGroup.append("rect")
        .attr("class", "info-rect")
        .attr("rx", 6)
        .attr("ry", 6)
        .attr("fill", "#fdfdfd")
        .attr("stroke", "#888")
        .attr("stroke-width", 1.5)
        .lower(); // 把 rect 放到最底层
    },

    createTables(nodes) {
      console.log(nodes);
      this.certList = [];
      let certCount = 0;

      for (const node of nodes) {
        if (node && node.type === "cert") {
          certCount++;
          this.certList.push({
            index: certCount,
            sha256: node.id.slice(5),
          });
        }
      }

      console.log(this.certList);
    },
  },
};
</script>

<style scoped>
.cert-graph-container {
  width: 100%;
}

.links line {
  stroke-opacity: 0.6;
  stroke-width: 1px;
  fill: none;
}

.nodes circle {
  stroke: #333;
  stroke-width: 1.5px;
}

.root-outline {
  stroke: #f39c12;
  stroke-width: 3px;
  fill: white;
}

.upload-drop-zone {
  height: 200px;
  border-width: 2px;
  margin-bottom: 20px;
  color: #ccc;
  border-style: dashed;
  border-color: #ccc;
  line-height: 200px;
  text-align: center;
}

.upload-drop-zone.drop {
  color: #222;
  border-color: #222;
}
</style>