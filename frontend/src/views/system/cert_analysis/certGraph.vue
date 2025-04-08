<template>
  <div class="container">
    <nav class="navbar navbar-inverse">
      <div class="container-fluid">
        <div class="navbar-header">
          <button type="button" class="navbar-toggle collapsed" @click="toggleNav" aria-expanded="false">
            <span class="sr-only">Toggle navigation</span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
          </button>
          <a class="navbar-brand" href="#">CertGraph</a>
        </div>
        <div v-if="navOpen" class="navbar-collapse collapse">
          <ul class="nav navbar-nav navbar-right">
            <li class="dropdown">
              <a href="#" class="dropdown-toggle" data-toggle="dropdown" role="button">
                Data <span class="caret"></span>
              </a>
              <ul class="dropdown-menu">
                <li><a href="#" @click.prevent="openModal('url')">URL</a></li>
                <li><a href="#" @click.prevent="openModal('paste')">Paste</a></li>
                <li><a href="#" @click.prevent="openModal('file')">File Upload</a></li>
              </ul>
            </li>
          </ul>
        </div>
      </div>
    </nav>

    <div class="panel panel-info">
      <div class="panel-heading">
        <h3 class="panel-title pull-left">Graph</h3>
        <div class="pull-right">
          <button class="btn btn-primary btn-xs" @click="downloadSVG">Download SVG</button>
        </div>
        <div class="clearfix"></div>
      </div>
      <svg id="graph" width="100%" height="500"></svg>
    </div>

    <div class="panel panel-info">
      <div class="panel-heading">Info</div>
      <div class="panel-body" id="node-info">{{ nodeInfo }}</div>
    </div>

    <ul class="nav nav-tabs">
      <li class="active">
        <a href="#domains" data-toggle="tab">Domains</a>
      </li>
      <li>
        <a href="#certificates" data-toggle="tab">Certificates</a>
      </li>
    </ul>
    <div id="myTabContent" class="tab-content panel-body">
      <div class="tab-pane fade active in" id="domains">
        <table class="table table-striped table-hover">
          <thead>
            <tr>
              <th>#</th>
              <th>Domain</th>
              <th>Status</th>
              <th>Lookup</th>
            </tr>
          </thead>
          <tbody id="domain-list"></tbody>
        </table>
      </div>
      <div class="tab-pane fade" id="certificates">
        <table class="table table-striped table-hover">
          <thead>
            <tr>
              <th>#</th>
              <th>Hash</th>
              <th>Lookup</th>
            </tr>
          </thead>
          <tbody id="cert-list"></tbody>
        </table>
      </div>
    </div>

    <footer>
      <hr />
      <div class="row">
        <div class="col-xs-10">
          <a href="https://github.com/lanrat/certgraph">CertGraph</a>
        </div>
      </div>
    </footer>

    <!-- URL, Paste, File Upload Modals -->
    <div class="modal fade" v-if="showModal" @click.self="showModal = false">
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <button type="button" class="close" @click="showModal = false">&times;</button>
            <h4 class="modal-title">{{ modalTitle }}</h4>
          </div>
          <div class="modal-body">
            <div v-if="modalType === 'url'">
              <input type="text" v-model="inputURL" placeholder="https://domain.com/data.json" class="form-control" />
            </div>
            <div v-else-if="modalType === 'paste'">
              <textarea v-model="inputPaste" rows="10" class="form-control"></textarea>
            </div>
            <div v-else-if="modalType === 'file'">
              <input type="file" @change="loadFile" class="form-control file" />
              <div class="upload-drop-zone" @drop.prevent="dropFile" @dragover.prevent>
                Drag and drop a JSON file here
              </div>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-primary" @click="loadData">Load</button>
            <button type="button" class="btn btn-default" @click="showModal = false">Close</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import * as d3 from 'd3';
import { saveAs } from 'file-saver';

export default {
  name: 'CertGraph',
  data() {
    return {
      navOpen: false,
      showModal: false,
      modalType: '',
      inputURL: '',
      inputPaste: '',
      nodeInfo: 'Click on a node in the graph to view details.',
    };
  },
  mounted() {
    this.initGraph();
  },
  methods: {
    toggleNav() {
      this.navOpen = !this.navOpen;
    },
    openModal(type) {
      this.showModal = true;
      this.modalType = type;
    },
    initGraph() {
      const svg = d3.select('#graph');
      const color = d3.scaleOrdinal(d3.schemeCategory10);

      svg.call(d3.zoom().on('zoom', (event) => {
        svg.attr('transform', event.transform);
      }));

      this.createGraph();
    },
    createGraph() {
      // Implement the graph creation logic with D3 here
    },
    downloadSVG() {
      const svgContent = document.getElementById('graph').outerHTML;
      const blob = new Blob([svgContent], { type: 'image/svg+xml' });
      saveAs(blob, 'certificate_graph.svg');
    },
    loadData() {
      // Logic for loading data based on modal type (URL, Paste, or File)
      this.showModal = false;
    },
    loadFile(event) {
      const file = event.target.files[0];
      // Handle file loading here
    },
    dropFile(event) {
      const file = event.dataTransfer.files[0];
      // Handle file drop loading here
    },
  },
};
</script>

<style scoped>
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
