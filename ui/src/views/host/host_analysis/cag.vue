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
    height: {
      type: Number,
      default: 500,
    },
  },
  data() {
    return {
      loading : false,
      svg: null,
      simulation: null,
      color: d3.scaleOrdinal(d3.schemeCategory10),

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
    console.log(d3.version);
    this.initGraph();
  },
  methods: {
    initGraph() {
      this.svg = d3.select(this.$refs.graphSvg);
      const width = this.$el.clientWidth;

      this.svg = this.svg
        .call(d3.zoom().on("zoom", this.zoomed))
        .append("g");

      this.svg
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

      this.simulation = d3
        .forceSimulation()
        .force(
          "link",
          d3.forceLink().id(function (d) {
            return d.id;
          })
        )
        .force("charge", d3.forceManyBody().strength(-100))
        .force("center", d3.forceCenter(width / 2, this.height / 2));
    },

    resetGraph() {
      d3.select(this.$refs.graphSvg).select("g").selectAll("*").remove();
      this.createTables([]);

      // reset info
      const el = document.getElementById("node-info");
      if (el) {
        el.innerText = "Click on a node in the graph to view details.";
      }

      // redo layout
      const width = this.$el.clientWidth;
      this.simulation = d3
        .forceSimulation()
        .force(
          "link",
          d3.forceLink().id(function (d) {
            return d.id;
          })
        )
        .force("charge", d3.forceManyBody().strength(-100))
        .force("center", d3.forceCenter(width / 2, this.height / 2));
    },

    // this 
    createGraph(error, graph) {
      if (error) throw error;

      const link = this.svg
        .append("g")
        .attr("class", "links")
        .selectAll("line")
        .data(graph.links)
        .enter()
        .append("line")
        .attr("stroke", (d) => this.color(d.type))
        .attr("marker-end", "url(#arrow)");

      const text = this.svg
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

      const node = this.svg
        .append("g")
        .attr("class", "nodes")
        .selectAll("circle")
        .data(graph.nodes)
        .enter()
        .append("circle")
        .attr("r", 10)
        .attr("fill", (d) => {
          if (d.root == "true") return this.color(d.root);
          return this.color(d.type);
        })
        .call(
          d3
            .drag()
            .on("start", this.dragstarted)
            .on("drag", this.dragged)
            .on("end", this.dragended)
        );

      node.on("click", (d) => {
        // this.updateInfoBox(d);
      });

      node.append("title").text(function (d) {
        return d.name;
      });

      this.simulation.nodes(graph.nodes).on("tick", this.ticked);

      this.simulation.force("link").links(graph.links);

      this.createTables(graph.nodes);
    },

    // these are d3 events
    ticked() {
      const link = d3.selectAll(".links line");
      const node = d3.selectAll(".nodes circle");
      const text = d3.selectAll(".labels g");

      link
        .attr("x1", function (d) {
          return d.source.x;
        })
        .attr("y1", function (d) {
          return d.source.y;
        })
        .attr("x2", function (d) {
          return d.target.x;
        })
        .attr("y2", function (d) {
          return d.target.y;
        });

      node
        .attr("cx", function (d) {
          return d.x;
        })
        .attr("cy", function (d) {
          return d.y;
        });

      text.attr("transform", function (d) {
        return "translate(" + d.x + "," + d.y + ")";
      });
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
      d3.select(this.$refs.graphSvg)
        .select("g")
        .attr(
          "transform",
          `translate(${event.transform.x},${event.transform.y}) scale(${event.transform.k})`
        );
    },

    // updateInfoBox(d) {
    //   if (d) {
    //     const el = document.getElementById("node-info");
    //     let s = "Type: " + d.type + "</br>";
    //     if (d.type == "domain") {
    //       s = s + "Domain: " + this.linkifyDomain(d) + "</br>";
    //       s = s + "Status: " + d.status + "</br>";
    //     } else if ((d.type = "certificate")) {
    //       s = s + "Hash: " + this.linkifyCert(d) + "</br>";
    //     }
    //     el.innerHTML = s;
    //   }
    // },

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