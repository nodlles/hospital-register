# 北京大学口腔医院（小程序版）接入说明

这个目录里的 `bdkq_*.py` 是把「北京大学口腔医院医疗服务助手」小程序的挂号接口
接进本项目的一组模块。它跟中日友好那套 config 驱动的源不是一条路：这个医院
所有请求都要现算签名、请求体国密加密、响应体国密解密，所以单独成模块，
但通知通道沿用 `hospital_watch.py` 里已经做好的那几个。

## 状态

| 部分 | 状态 |
| --- | --- |
| 加密/签名（`bdkq_crypto.py`） | 已实现，SM3/SM4 国标向量与 gmssl 交叉验证通过，**已用真服务器验证** |
| 接口客户端（`bdkq_client.py`） | 已实现，**已打通真服务器**（缺 token 时正确回 401） |
| HAR / cURL 导入（`bdkq_har.py`） | 已实现，能从抓包生成配置 |
| 字段探测（`bdkq_probe.py`） | 已实现，**差一个 access_token 才能校准字段名** |
| 只读监控（`bdkq_watch.py`） | 已实现，不下单 |
| 下单 | **没写**，参数名没校准，不猜 |

## 域名解析：公共 DNS 是假的，HTTPDNS 才是真的

`app.bdkq.mingxuan.store` 的公共 A 记录是 `127.0.0.1`（DNSPod，TTL 600）。
用 Cloudflare DoH、223.5.5.5、8.8.8.8、114、119.29.29.29、doh.pub，以及直接
问权威 NS `ns3.dnsv2.com`（六条 ECS 线路）全都是 `127.0.0.1`，没有分线路。

**但腾讯 HTTPDNS 能查到真实回源 IP**：

```bash
curl "http://119.29.29.29/d?dn=app.bdkq.mingxuan.store"
# 101.201.62.105;8.147.234.254;39.105.140.139;39.107.211.246
```

四个 IP 都验证过：TCP 443 通、TLS 证书校验通过（`ssl_verify=0`）、nginx 回 200。
微信自己走的就是这套 HTTPDNS，所以手机上能正常用。

所以不需要改系统 hosts，配置里写 `resolve` 就行（客户端连 IP、SNI 和 Host 头
仍然用域名，证书校验照做）：

```json
"resolve": { "app.bdkq.mingxuan.store": "8.147.234.254" }
```

IP 变了就重跑一次上面那条 curl 换掉它。模拟器里想设 hosts 需要 root，`adb root`
在 production 版镜像上不行；改用「把模拟器的 http_proxy 指到一台只做转发的隧道
代理」更省事（代理只把 CONNECT 的目标域名换成真实 IP，不做 MITM）。

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

- **或者什么都不用抓**（推荐）：让微信运行时里开着北大口腔小程序，然后

  ```bash
  python3 bdkq_token.py -c config.bdkq.local.json --force
  python3 bdkq_watch.py -c config.bdkq.local.json --duration 300
  ```

  `bdkq_token.py` 会走 `wxdevtools` 通道在逻辑层调 `wx.login()` 拿 code，
  再 `POST /login/wechat` 换成 token，token 连同 `api_version` 一起缓存到
  `config.bdkq.local.json.token`（0600）。token 是 JWT，有效期两小时，
  快到期会自动再换一次，所以 `bdkq_watch.py` 可以一直挂着跑。
  配置里的 `access_token` 可以直接留空。

  注意 `wx.login()` 的 code 是按小程序发的，所以换 token 前会核对运行时里
  第一个打开的小程序 appId 是不是 `wxf47aa38d871be854`，不对会直接报错，
  提示你重启运行时先开北大口腔——这个运行时的调试通道只挂第一个小程序。

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

盯 `getYyDeptList` 返回里科室节点的 `remainNum`（已用真实响应校准过，
52 个科室每个都带这个字段），从少变多就推通知。
其余几个候选字段名（`left/surplus/yuyue/available/...`）只是防御性的兜底，
万一接口换了还能认出关键词来。

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
| `bdkq_watch.py` | 只读号源监控 + 通知（token 自动续期） |
| `bdkq_token.py` | `wx.login` → token 自动换取与续期，带本地缓存 |
| `wxdevtools.py` | 免抓包通道：DevTools 协议读小程序登录态 / `wx.login` |
| `bdkq_endpoints.json` | 从包体里提取的 132 个接口，按名字索引 |
| `config.bdkq.example.json` | 配置样板 |
| `tests/test_bdkq_crypto.py` | 25 条离线测试 |
| `tests/test_bdkq_token.py` | token 解析、续期判定、缓存 18 条 |
| `tests/test_wxdevtools.py` | 采集结果转配置的纯函数 28 条 |

## 与真服务器校准出来的两处修正（2026-11-18）

逆向时看漏了两个细节，都是拿真服务器对着打才发现的：

1. **响应解密的 key 要把材料先反转**。原文是
   `sm3((o = signature + ":" + secret, P(o) ? o : o.split("").reverse().join("")))`，
   而 `P()` 是「空值判断」不是「可打印判断」，所以 `o` 永远非空、永远走反转分支。
   漏了反转的话，解出来是乱码。
2. **`cipher` 响应头是「要不要解密」的开关，不是「已解密」的标记**。原文
   `if ("false" != (header.cipher || false).toString())` 才去解 `data`。
   没有 `cipher` 头的响应（比如 `{"status":1000,"message":"访问受限"}`）是明文，
   直接当结果用。

另外确认：缺 token 时网关回 `{"code":"401","msg":"token is not black"}`，
客户端把 `status 1000` 和 `code "401"` 统一归一成「登录态失效」。
登录响应头里的 `x-version` 不是 `331` 而是 `3fdf7484` 这样的版本标识，
后续请求必须用它——用 `default` 会被回 `1000 访问受限`。

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
