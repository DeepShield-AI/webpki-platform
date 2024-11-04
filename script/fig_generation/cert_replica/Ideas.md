
# 在贡献 Contribution 里面可以写的点：

## 总体
### 有什么东西是之前没有注意到发现的？

1. Overview-50M 证书数据中：
    (1) Total amount of sites: 99329
    (1) Total amount of certs in top-1m: 346235
    (2) Total amount of sites with certificate replicas: 32837
    证书的有效期开始范围在 2023 年 11 月 ☞ 2024 年 2 月

2. Certificate Replicas 和 网站的 site rank 没有太大的关系
（这个确实没有想到，只有个别的网站在短时间内拥有大量的证书副本）

3. 大部分的网站的证书副本较少，都在 10 个以下，但是有部分的网站证书副本非常多，都具有以下特点：
    *.mongodb.net
    *.usatoday.com
    *.gannettdigital.com
    *.gannett-cdn.com



## 时间变化维度（可以粗略认为是证书的重新签发/更换）
### 什么东西应该随着时间变化而变化，却没有变化，或者变化的趋势不对？
### 反之亦然

#### 对于具有不同的 not before 的证书而言：
    (1) 首先应该是要具有不同的 Public Key
    (2) 有相同 SAN 的证书重新签发/更换的时间间隔应该相近（不同间隔相差不大）
    (3) 相同 SAN 的证书不应该出现 Gap
    (4) 证书签发的频率应该不需要很高，尤其是相同 SAN 的证书
    (5) 证书的 SAN list 变化应该不大

##### 但是我们发现：

1. 公钥应该每次都替换，但是发现 key reuse，有的网站在相同/不同日期的证书的 pubkey 相同
2. 人工签发的间隔差异很大，呈现不规律的现象
3. 部分网站存在 Gap 现象
4. 重新签发新的证书频率比想象中的要快很多，尤其是对于 SAN 相同的而言，和 PAM 2021 的出入较大，甚至在同一天就有非常多的证书出现
5. Domain add and remove 有部分网站在 2024 年之后立刻加大了证书当中的 SAN list 长度

#### 对于具有相同（同一天）not before 的证书而言：
    (1) 理论上应该只需要从单一 CA 签发即可
    (2) 理论上有了 EV/OV 就不需要 DV
    (3) 理论上不应该有 short-lived 和 long-lived certificates

##### 但是我们发现：

1. 部分网站同一天存在许多的 CA 签发的证书
2. 部分网站存在一天有 EV/OV 和 DV 的现象
3. 部分网站同一天存在 长证书 和 短证书



## 空间变化维度（可以粗略认为是不同站点的证书）
### 什么东西应该随着空间变化而变化，却没有变化，或者变化的趋势不对？
### 反之亦然

#### 对于具有 不同 的 SAN 的证书而言：
    (1) 首先应该是要具有不同的 Public Key
    (2) 其次是不同地区的证书的 SAN 不应该有大范围的域名交叉，尤其是根域名
    这些的目的都是要为了防止单点的 Failure 而影响大局

##### 但是我们发现：

1. 不同的 SAN 证书使用相同的密钥，这种行为严重影响了站点证书的安全
2. 不同站点的证书 SAN 就只有一个关于地区的域名不同，其他的域名，包括根域名在内，都是含有的，就很奇怪，没有意义，就是 intersection 没有变化
建议：在不同地区使用的证书，如果没有特殊原因，就不要进行通配符证书的申请或者是绑定的域名有大量交叉，这样很危险，如果有一个证书泄露，那么影响的是全部

##### 我们还可以统计：

1. 不同 SAN 证书的 CA 依赖情况
2. 不同 SAN 证书的 Zlint 情况

#### 对于具有 相同 的 SAN 的证书而言：
    (1) 证书签发/更换的行为尽量一致，尤其是证书类型，在同一时间段内有了 EV 就不要在申请 DV 证书，否则申请的意义是什么
    (2) 同上，如果站点的行为是要用 short-lived certificates，就不要同时在同一时间段内同时申请长时间证书和短时间证书
    注：可以先把不同时间段的做一下，然后递进关系做相同时间段的
    注：两个都相同的情况写一次就行

##### 但是我们发现：

1. 同一个域名的证书同一天出现了 长证书 和 短证书，甚至是具有相同的 SAN 的证书在相同的时间段下，有长证书，也有短证书
2. 同一个域名的证书同一天出现了 DV/OV 和 EV 的证书，甚至是具有相同的 SAN 的证书在同一天签发了 EV 和 DV 的证书
建议：不应该出现，因为 DV 和 EV/OV 验证方式不同，使用 DV 的会更加危险，EV/OV 的额外验证就是失效了

##### 我们还可以统计：

1. 相同 SAN 证书的 CA 依赖情况
2. 相同 SAN 证书的 Zlint 情况


### MISC

1. 有一个问题：就是很多证书很可能大量重复计算
    所以：应该如何去重呢？
    或者说，应该讲什么作为 一个 Group 呢？
    或者说，我们可以将完全相同的 Group 进行合并。

1. 模式挖掘（Pattern Mining）
模式挖掘旨在从数据集中识别出有意义的模式或模板。对于域名数据，模式挖掘可以帮助识别出常见的域名结构和模式。

算法: 常见的模式挖掘算法包括Apriori和FP-Growth，通常用于挖掘频繁项集。在域名模式挖掘中，类似的概念可以用来识别重复出现的域名部分或结构。
2. 序列模式挖掘（Sequence Pattern Mining）
序列模式挖掘专注于从序列数据中识别出经常出现的模式。在域名数据中，域名的结构可以视为一种序列，通过序列模式挖掘算法来识别通用模板。

算法: SPADE（Sequential Pattern Discovery using Equivalence classes）和PrefixSpan（Prefix-Projected Sequential Pattern Mining）是常用的序列模式挖掘算法。

bx6s4.mongodb.net
            [
                "*.2puio.mesh.mongodb.net",
                "*.2puio.mongodb.net",
                "*.f83888234a7f98eebb6dd16c.2puio.mongodb.net",
                "*.mongodb.net"
            ],
    "0.gcr.io": [
        [
            "*.gcr.io",
            "gcr.io"
        ],            
    "00xzu8-226-ppp.oss-accelerate.aliyuncs.com": [
        [
            "*.aliyuncs.com",
            "*.cn-hongkong.mgw.aliyuncs.com",
            "*.cn-hongkong.oss-console.aliyuncs.com",
            "*.cn-hongkong.oss.aliyuncs.com",
            "*.img-cn-hongkong-internal.aliyuncs.com",
            "*.img-cn-hongkong.aliyuncs.com",
            "*.oss-accelerate-overseas.aliyuncs.com",
            "*.oss-accelerate.aliyuncs.com",
            "*.oss-accesspoint.aliyuncs.com",
            "*.oss-cn-hongkong-cross.aliyuncs.com",
            "*.oss-cn-hongkong-internal.aliyuncs.com",
            "*.oss-cn-hongkong-internal.oss-accesspoint.aliyuncs.com",
            "*.oss-cn-hongkong-internal.oss-object-process.aliyuncs.com",
            "*.oss-cn-hongkong.aliyuncs.com",
            "*.oss-cn-hongkong.oss-accesspoint.aliyuncs.com",
            "*.oss-cn-hongkong.oss-object-process.aliyuncs.com",
            "*.oss-enet.aliyuncs.com",
            "*.oss-internal.aliyuncs.com",
            "*.oss.aliyuncs.com",
            "*.oss.cn-hongkong.privatelink.aliyuncs.com",
            "*.s3.oss-cn-hongkong-internal.aliyuncs.com",
            "*.s3.oss-cn-hongkong.aliyuncs.com",
            "*.vpc100-oss-cn-hongkong.aliyuncs.com",
            "oss-cn-hongkong.aliyuncs.com"
        ],
"memonotepad.com"
        [
            "*.memonotepad.com",
            "memonotepad.com"
        ],
        [
            "memonotepad.com"
        ]
        先暂时按照几级域名 match 来分析好了。。。
