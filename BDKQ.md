# 北京大学口腔医院（小程序版）接入说明

这个目录里的 `bdkq_*.py` 是把「北京大学口腔医院医疗服务助手」小程序的挂号接口
接进本项目的一组模块。它跟中日友好那套 config 驱动的源不是一条路：这个医院
所有请求都要现算签名、请求体国密加密、响应体国密解密，所以单独成模块，
但通知通道沿用 `hospital_watch.py` 里已经做好的那几个。

## 状态

| 部分 | 状态 |
| --- | --- |
| 加密/签名（`bdkq_crypto.py`） | 已实现，SM3/SM4 国标向量与 gmssl 交叉验证通过 |
| 接口客户端（`bdkq_client.py`） | 已实现，25 条离线测试通过 |
| HAR / cURL 导入（`bdkq_har.py`） | 已实现，能从抓包生成配置 |
| 字段探测（`bdkq_probe.py`） | 已实现，**需要真实 token 才能校准字段名** |
| 只读监控（`bdkq_watch.py`） | 已实现，不下单 |
| 下单 | **没写**，参数名没校准，不猜 |

## 一个绕不过去的问题

`app.bdkq.mingxuan.store` 的 A 记录是 `127.0.0.1`（DNSPod，TTL 600），
用 Cloudflare DoH、223.5.5.5、8.8.8.8、以及直接问权威 NS `ns3.dnsv2.com`
（六条 ECS 线路）全都是 `127.0.0.1`，没有分线路解析。

手机上微信里能正常打开，说明微信侧不走公共 DNS。所以：
- 在普通网络里跑这些脚本，连不上这个域名，会得到 connection refused
- 就算拿到 HAR 里的 token，也要先解决「从哪台机器能连上」

可能的走法（都还没验证）：让用户在能连的机器/网络里跑、抓 HAR 里的真实
出口 IP 再 `--resolve`、或者在手机端配合代理转发。**这条不通，后面全都跑不起来。**

## 用法

### 1. 拿登录态

小程序需要 `access_token`，它只能靠微信运行时 `wx.login` 换。两条路：

- 跑 `bdkq_har.py`，把浏览器/代理导出的 HAR 或 DevTools「Copy as cURL」喂进来：

  ```bash
  python3 bdkq_har.py capture.har -o config.bdkq.local.json
  python3 bdkq_har.py curl.txt --show          # 只看抠到什么，不落盘
  ```

  它会取最后一个非空的 `access_token`、`x-version`、referer、UA，
  拼出 `base_url`（去掉 `/{tenant}@{version}` 尾巴）和见过的接口路径清单。
  生成的配置权限 0600。

- 或者在模拟器里跑小程序，登录后调 `client.login_with_code(code)`。
  `code` 只能用一次，只能在微信运行时里取，见下面的「逆向记录」。

### 2. 校准字段名

```bash
python3 bdkq_probe.py -c config.bdkq.local.json --area 0
```

按 `dateList → getYyDeptList → getYyDoctorList → getYyScheduleList →
queryYyOtherAreaNumber` 顺序打，每步记下入参、业务状态码、截断后的原始
`data` 和拍平的字段表（`schema`），写进 `probe-result.json`。
它还会把「哪个字段是科室码」「哪个是医生码」「排班接口到底要哪些参数」
这些校准结果记在 `calibrated` 里——这些名字是我从混淆代码里推的，必须对一次。

### 3. 只读监控

```bash
python3 bdkq_watch.py -c config.bdkq.local.json --once
python3 bdkq_watch.py -c config.bdkq.local.json --duration 300 --interval 5
```

盯 `getYyDeptList` 返回里科室节点的剩余号源字段，从少变多就推通知。
剩余字段名也是启发式匹配（`remain/left/surplus/yuyue/available/...`），
第一次没识别出来会打印该节点真实字段名，用它改 `REMAIN_HINTS`。

注意 `bdkq_watch.py` **不会下单**。下单要等 probe 校准出 `yyOrder` /
`todayOrder` 的字段名，而且要跟主项目一样有人工确认词才允许提交——
这块故意留空，不拿猜的字段往医院系统写。

## 文件

| 文件 | 作用 |
| --- | --- |
| `bdkq_crypto.py` | SM3、SM4-ECB/PKCS7、签名、请求体加密、响应解密，纯标准库 |
| `bdkq_client.py` | `BdkqClient`：URL 拼接、签名、加密、解密、重登录、常用挂号方法 |
| `bdkq_har.py` | HAR / cURL / 日志文本 → 配置 |
| `bdkq_probe.py` | 只读探测 + 字段校准 |
| `bdkq_watch.py` | 只读号源监控 + 通知 |
| `bdkq_endpoints.json` | 从包体里提取的 132 个接口，按名字索引 |
| `config.bdkq.example.json` | 配置样板 |
| `tests/test_bdkq_crypto.py` | 25 条离线测试 |

## 逆向记录（校准参数时对照用）

- 小程序：APPID `wxf47aa38d871be854`，版本 331，uni-app（Vue3）编译，
  厂商「明轩」`mingxuan.store` 低代码平台
- 租户 `xcx-bjdxkqyy-wx`，`org_code 12100000400777097N`
- URL 规则：`{base}/{tenant}@{version}{path}`；path 含 `/online` 或 `/common`
  不加版本号；`/login/wechat` 固定 `default`，登录响应头 `x-version` 覆盖后续版本
- 请求头：`access_token`、`request_time`（毫秒）、`request_otp`（UUIDv4）、
  `signature`、`rid`、`content-type: application/json`
- 签名：query 按 key 升序拼 `k=v&...`（空值/`null`/`{}`/`[]`/超 2048 字符跳过）
  加 `&requesttime=&requestotp=&secret=`，再
  `sm3("[" + sm3(time##secret) + "#" + sm3(base64(串)) + "#" + sm3(otp##secret) + "]")`
- 请求体：key = `signature[24:40]` 的 ASCII，SM4-ECB + PKCS7，输出 hex，包成 `{"data": hex}`
- 响应：`sm3(signature + ":" + secret)[24:40]` 相邻两字符互换当 key，SM4 解密
- 业务码：`0` 成功、`1000` token 失效（自动重登录一次）、`1001` 停诊/维护
- `rid = md5(token)[8:24] + "#" + md5(随机)[8:24]`
- 院区 `areaCode`：0 魏公村总院区、1 第一门诊部、2 第二、3 第三、4 第四、
  5 第五、6 国合门诊部、7 天竺、9 朝阳门、10 石景山、11 回龙观

## 安全

- 所有探测都是只读 GET/POST 查询，不产生挂号记录
- `config.bdkq.local.json` 里有 token，写完自动 0600，别提交进仓库
  （如果 `.gitignore` 没盖住就自己加一行）
- 日志里不打印完整 token
