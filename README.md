# Web-PKI Measurement Platform



## 1. Introduction



本测量平台作为 411 项目课题 6 的工程之一，对 Web PKI 和 SSL/TLS 证书相关内容进行态势感知



本平台具有以下功能：

1. 支持使用多种测量工具（如 Zmap、Zgrab）和自定义方式对网站 TLS 信息进行爬取
2. 支持爬取 CT 证书透明度的日志信息
3. 提供 MySQL 和文件两种方式对收集到的数据进行存储
4. 支持对目标的 TLS 数据和证书内容进行细致分析
5. 具有任务管理 Manager，允许用户同时提交多个测量或者分析任务
6. 提供脚本，对分析的结果进行可视化图表生成
7. 提供额外的工具对重点领域网站（政府、高校、企业）的域名进行爬取
8. 具有前端页面，允许用户提交测量任务，对证书进行搜索，展示 Web PKI 测量分析结果



每个部分的详情还请阅读对应路径中的 README，以及查看代码的注释



## 2. Workspace Structure

```
pki-internet-platform
|
| --- app - main backend code storage directory
|
| --- data - @deprecated, used to store temp data
|
| --- myenv - Python virtual environment
|
| --- script - scripts for analysis raw data or structured results （初步结果）
|				as well as submitting scan tasks;
|  				set up MySQL databases;
|				available for generating figures;
|
| --- test - scripts for testing source code, including unit tests and functional tests,
|				however, the tests are needed to be fixed
|
| --- tool - current for other useful tools such as web crawler or git manager
|				In the future, differnet entry points are available here
|
| --- ui - frontend source code directory
|
| --- start.py  - backend entry point
```



## 3. Installation & Usage



The platform currently only support build from source.

In the future,  we might provide docker image or other stuffs.



(1) Dependable thrid-party softwares to be installed first

```
Python3 - version used is python3.10
Zmap - make sure to remember the binary path, modify the path at app/config/scan_config.py
Zgrab2 - make sure to remember the binary path, modify the path at app/config/scan_config.py
MySQL - set up according to the doc
```

(2) Get the repo

```
git clone https://git.tsinghua.edu.cn/zhangty23/pki-internet-platform.git
```

(3) Set up environment

```
Backend:
    cd pki-internet-platform
    python3 -m venv myenv
    source myenv/bin/activate
    pip install -r requirments.txt

Fronend:
	cd ui/
	npm install
	
MYSQL set up
	In MySQL command line, use
	source $platform_dir/script/db_action/db.sql
```

(4) Run the platform for development

```
Uwsgi for Backend and Frontend
	uwsgi --ini uwsgi.ini

Backend:
	py .\start.py
	
Frontend:
	cd ui/
	npm run dev
```

The frontend are on 127.0.0.1:5001



(5) Run at production mode

On Linux Server, the development mode may not avaliable as one can not see the content on 127.0.0.1

```
Uwsgi for Backend and Frontend
	uwsgi --ini uwsgi.ini
	
Backend:
	py .\start.py
	
Frontend:
	cd ui/
	npm run build
	cp dist/ /var/www/pki-internet-platform/dist
```



Currently, the fronent webpage uses Nginx, the site config file are available at

```
/etc/nginx/sites-available/pki
```

Visit the webpage at:

```
118.229.43.254:8080
Note that on the server, the actual open port for HTTP is 4080(maybe?), the operator used port map for 4080 - 8080
```

注意，这是清华的服务器，需要在清华内网中才能访问





## 4. Design Overview



这里简单讲解一下整个平台的设计理念：



0. 本项目的基本盘来自于一个开源的前后端框架——authbase

   可以在 https://gitee.com/zhujf21st/authbase/tree/master 查看该项目的细节

1. Backend task manager

   目前采用的是一个简单的自己编写的管理器，具体内容在 app/manager 里面

   每提交一个 task，后端就会分配一个线程去执行该 task

   后端通过分析用户提交的 task 类型，将 task register 到不同的子 manager 当中，如：

   1. app/scanner/scan_manger.py 管理扫描任务
   2. app/analyzer/analysis_manager.py 管理后端分析的任务

   

   TODO：

   后期会有考虑改成经典的 redis + celery 去管理任务提交和下发

   或者采用 python 中的 asyncio 架构

2. Scanner

   提供三种扫描的方式：

   1. IPv4 活跃地址扫描
   2. 提供域名列表对网站进行扫描
   3. 对特定的 CT 日志的特定范围进行扫描

   扫描的配置可以在 app/config/scan_config 中进行查看

   

3. Data Storage

   目前平台支持两种方式的储存

   1. MySQL

      ```
      在 authbase db 中
      具体的每一个 Table 设计可以看
      /script/db_action/db.sql
      以及
      app/models
      ```

   2. File Based: on /data directory

      ```
      ip2location/ - basic country level and ASN level IP location map
      platform_log/ - the log 
      ```

      

4. Backend Analyzer

   目前支持以下的分析大类：

   （1）证书内容分析，提供规则检查

   （2）证书链验证，但是逻辑较为简单，没有按照 RFC 的标准

   （3）扫描结果的统计分析，比如证书的 issuer 统计，使用的加密方式统计等

   （4）CA 签发的证书的 Template 构建，但是后面没有在更新

   （5）Web 网站证书部署的问题（过期、被撤销、Subject mismatch 等）

   TODO：增加对 TLS 漏洞的检查

   ```
   具体的代码可以见：
   	app/analyzer
   	script/*
   ```

   TODO:

   ​	目前的分析代码非常的乱，需要花一段时间重新梳理

   ​	本质乱的原因就是没有什么新鲜东西（创新点），所以一直没有

5. Frontend

   目前，前端还是使用的原本 authbase 的架构，没有进行大更改

​		