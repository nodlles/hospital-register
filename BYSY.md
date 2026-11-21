# 北京大学第三医院（北医三院）接入说明

`bysy_client.py` 是把「北京大学第三医院」微信小程序的接口接进本项目的一组代码。
跟中日友好那套 config 驱动的源不是一条路：这个医院所有业务请求都走 `patwx.puh3.net.cn`，
带 token 时请求体要 SM4 加密、响应体是 AES 密文，所以单独成模块。

AppID：`wx3302a1b5a5f91dc4`，小程序版本 `2.2.2`。

## 状态

| 部分 | 状态 |
| --- | --- |
| 接口客户端（`bysy_client.py`） | 已实现，免登录 9 条 + 要 token 的主链路都已用真服务器跑通 |
| 接口清单（`bysy_endpoints.json`） | 已生成，206 条路径，138 个有函数名的带 token 接口 |
| 免登录数据（院区/科室/医生） | **可用** |
| 加解密（请求 SM4 / 响应 AES） | **已破解并按源码实现**，见「加解密」 |
| 号源 / 排班 | **可用**：一次请求拿全院 8 天号源矩阵（`schedules()` / `slot_rows()`） |
| 下单 / 支付 | **没写**：`createAppointment` 参数没对齐，`create_appointment()` 主动拒绝 |
| 登录 | 已解决：token 直接从 WeAppDev 运行时 storage 里取（见「登录」） |

## 怎么拿到这些事实的：不抓包，直接取小程序源码

WeAppDev（`github.ryf5584.weappdev`）的运行时调试网关开在模拟器里
`http://127.0.0.1:9400/mcp`（streamable HTTP，**1.1.0 Beta 起 64 个工具**），
`adb forward tcp:9400 tcp:9400` 后直接调用。取源码这条路是：

```
wad_open_app      {"appid":"wx3302a1b5a5f91dc4"}
wad_list_scripts                        # 69 个 script，拿到 scriptId
wad_save_script_source {"scriptId":148} # 返回 downloadUrl
curl 'http://127.0.0.1:9400/v1/files/download?scope=scripts&path=148' -o as.js
```

| scriptId | 文件 | 字节 |
| --- | --- | --- |
| 148 | `https://usr/app-service.js` | 1963462（12738 行） |
| 150 | `https://usr/subpackage-call/app-service.js` | 845506 |
| 146 | `https://usr/__plugin__/wx1fe8d9a3cb067a75/appservice.js` | — |
| 134 / 110 / 144 | `lib/WASubContext.js` / `WAServiceMainContext.js` / `WmpfInject` | — |

早期版本（1.0.1）的 `Debugger.getScriptSource`、codecache 反编译、HeapProfiler 捞堆
全都不必要了：`wad_save_script_source` 一句就能把真源码落盘。

## 请求协议

统一包装在 `lib/utils/request/request.js`，`app.config.js` 给出
`ENV:"production"`、`BASEURL:"https://patwx.puh3.net.cn"`、`version:"2.2.2"`。

```
POST {BASEURL}/{path}
Content-Type: application/json
platform:  wechat
version:   2.2.2
system:    <getSystemInfoCache().system>   # 实际值是 17
timestamp: Date.now()
token:     <storage token>          # 仅登录后
userId:    <loginUserInfo.userId>   # 仅登录后
```

### 两条分界线

1. **免登录白名单只有 9 条**（源码里那个 `d=[...]` 数组，顺序照抄）：
   `doctor/departmentList`、`doctor/departmentItem`、`department/getDepartments`、
   `doctor/department/getDoctors`、`doctor/new/getDoctors`、`wx/evaluate/getEvaluates`、
   `consultation/patient/doctorHasDiagnoses`、`appointment/getHospitalAreas`、
   `patient/free/department/list`。
2. **其余全部要 token**。无 token 打过去一律
   `{"code":"201","msg":"请升级到最新版本，或重新登录！","data":{}}`。
   这个 201 是「未登录／版本不对」的通用码，**不代表参数错**。
   另外 `code:"201"` + 「请求频繁，请稍后重试」是限流，不是登录失效 —— 别混淆。

## 加解密（已破解，全部来自源码，逐条实测）

两块都在 `lib/utils/` 里，算法 5 行就读完了；难的是"密钥是什么"，答案是
**token 与 userId 各管一个方向**。

### 请求体：SM4-ECB + PKCS7，密钥 = md5_upper(token)

```js
// lib/utils/sm4-crypto.js
SM4Encrypted(e, r) = gm.SM4.encrypt(e || "{}", md5_upper(r),
                      {inputEncoding:"utf8", outputEncoding:"base64"})
// lib/utils/*.js
encryptMD5(e) = CryptoJS.MD5(e).toString().toUpperCase()
// 调用点 lib/utils/request/request.js
g && (o = {encrypted: SM4Encrypted(JSON.stringify(o), g)})   // g = storage 里的 token
```

* 密钥不是 token 本身，也不是 token 的前 16 字节，而是
  **`md5(token)` 的 32 个十六进制字符（大写）再按 hex 解析成 16 字节**。
* 模式 ECB、填充 PKCS7、密文 base64。
* 线上：`{"encrypted":"ER+iJpe1qIDOhB3nAFxuZw=="}`（空 body 的 `{}` 加密后 16 字节）。

```python
sm4_key(token) -> bytes.fromhex(hashlib.md5(token.encode()).hexdigest().upper())
wrap_body(body) -> {"encrypted": base64(SM4-ECB-PKCS7(json, sm4_key(token)))}
```

### 响应体：AES-CBC + PKCS7，密钥 = userId，iv = token 末 16 字符

```js
// lib/utils/*.js
exports.decryptAes = function (e, r, n) {
  var u = CryptoJS.enc.Utf8.parse(r),                                    // key = userId
      a = CryptoJS.enc.Utf8.parse(n.substring(n.length-16, n.length)),   // iv  = token 末 16
      d = CryptoJS.enc.Hex.parse(e),          // 响应是十六进制
      p = CryptoJS.enc.Base64.stringify(d),   // 转 base64 再喂 CryptoJS
      f = CryptoJS.AES.decrypt(p, u, {iv:a, mode:CBC, padding:Pkcs7});
  return f.toString(CryptoJS.enc.Utf8);
};
// 调用点
b.data = JSON.parse(decryptAes(b.data, f.userId, g));   // f = loginUserInfo, g = token
```

* `userId` 是 24 字符 → **AES-192**；它变了 iv 也跟着换。
* 响应原文是一串大写十六进制，**不是 JSON**；`decode('utf-8')` 直接 `json.loads` 必然炸。
* 所有密文首块相同（`9C68E27FC021A2B27ADEBD50B455AF49` → `{"code":"200",`），
  因为 CBC 的 iv 是固定截 token 尾 16 位。

```python
decrypt_response(text, user_id, token):
    key = user_id.encode()            # 24 B
    iv  = token[-16:].encode()
    return json.loads(decrypt_hex_cbc(text, key, iv))
```

纯标准库实现放在 `bysy_aes.py`（128/192/256 + CBC + PKCS7，`python3 bysy_aes.py`
跑 FIPS-197 三条向量），项目不引 pycryptodome。

### 已否决的弯路（别再花时间）

| 思路 | 为什么不行 |
| --- | --- |
| 拿 token 的 utf8 前 16 字节当 SM4 密钥 | 字节数就不对，且源码明写 md5 |
| 离线字典爆破 71471 个候选密钥 | SM4/AES 各解一遍，0 命中；密钥不是猜出来的 |
| 只用无 token 的公开接口猜字段 | 号源字段名必须看真返回 |
| HeapProfiler 抓堆 / patch 内置对象 | 源码一出就都多余了 |

## 登录：token 从运行时直接拿

登录接口本身要微信手机号凭证：

* `POST api/v2/wx/patient/login {code, phoneCode}` 或 `{code, encryptedData, iv}`；
* 只给 `code` 服务端明确回「缺少手机号凭证(phoneCode 或 encryptedData/iv)」，且 code 单次有效。

但**不需要走这条路**：WeAppDev 里小程序已经登录着，登录态就在 storage 里，
直接用 MCP 取（storage key 都以 `ndyfy-master-` 开头）：

```
ndyfy-master-token            JWT，156 字符
ndyfy-master-loginUserInfo    {token, userId, usersig, identifier, phone, openid, easeAcounts}
ndyfy-master-loginKey         BEIYISAN
ndyfy-master-system           {version:"2.2.2", platform:"wechat", system:"17", ...}
```

`userId` 和 `token` 一个都不能少：少了 userId 解不了响应，少了 token 算不出 SM4 密钥。
`bysy_client.from_config()` 认 `{"token": {"token": ..., "userId": ...}}` 这种写法。

## 实测返回（2026-11-21，真服务器，带 token）

| 接口 | 结果 |
| --- | --- |
| `api/v1/system/getSystemTime` `{}` | 200，`{"systemTime":"2026-11-21"}`，426ms |
| `api/v1/appointment/getDepartments` `{"isShow":true,"isAffiliated":true}` | 200，**664 个科室**（带 hospitalName / isAppointment / deptSn），14s |
| `api/v2/appointment/getDepartmentDoctors` 见下 | 200，「获取医生列表成功V2」，**57 位医生** |
| `api/v2/appointment/area/getVisitSchedules` `{"departmentId":<任意>` | 200，**276 个科室 × 8 天**号源矩阵 |

`getDepartmentDoctors` 的请求体（源码调用点原样，已实测字段全对）：

```json
{"departmentAppointmentId":"<科室 _id>","showInternet":false,"getSchedule":true,
 "isToday":false,"departmentType":"gh","userId":"<userId>","mTicket":"","mRandstr":""}
```

`departmentAppointmentId` 就是科室列表里的 `_id`（不是 `deptSn`、不是 `id`）。
只有 `isAppointment:true` 的科室有号，非可挂号科室回空列表。

### 号源矩阵（`getVisitSchedules`）的坑

* **`departmentId` / `startDate` / `endDate` 服务端一概不理**：传什么都是同一份
  「276 科室 × 8 天」全量矩阵；**空 body 反而回 `[]`**。所以 `schedules()` 固定带一个
  `departmentId`（可空串），筛选全部自己做。
* 一次请求就有全院号源，**监控只需要打这一个接口**。
* 每条排班的关键字段：

| 字段 | 含义 |
| --- | --- |
| `leftNum` / `totalNum` / `useNum` | 剩余号 / 总号 / 已用；`leftNum:0` = 没号 |
| `visitDate` / `am_pm` | `2026-11-21` / `AM`\|`PM` |
| `doctorName` / `doctorSn` / `doctor_code` | 医生 |
| `deptName` / `deptSn` / `departmentHasDoctorId` | 科室 |
| `gh_fee` / `registerFee` / `totalFee` | 挂号费 |
| `sop_name` / `clinicName` / `exam_code` | 号别（普通/专家/特需 + 价格档） |
| `recordSn` | 排班标识，下单要回传 |
| `open_flag` / `isStopVisit` / `status` | 开放状态 / 停诊 / 状态 |
| `nightFlag` | 晚间门诊 |
| `_id` | 排班 id |

号源窗口实测 8 天（`2026-11-21` ~ `2026-11-28`），第 8 天 15:00 放号、当日号按上午 10:00 /
下午 15:00 / 晚间 18:00 截止，与 README 里的挂号规则一致。

## 还没校准的（不猜，不写「大概对」的实现）

* `api/v2/appointment/getVisitSchedulesTimes`（分时段号源）——分时段科室下单要 `timeIntervalCode`；
* `api/v2/appointment/createAppointment`（下单）+ `api/v1/payment/createPayment`（支付）；
* `getDoctors`（v1，department 那个）：白名单里留着，当前版本没有调用方，估计是废弃 handler。

下单还有个业务前提：**这个账号还没有就诊人**，点「在线挂号」会弹
「暂无就诊人，请先添加就诊人」，所以写接口在那之前没法端到端验证。

## 命令

```bash
python3 bysy_client.py areas        # 七个院区号源数（免登录）
python3 bysy_client.py depts        # 科室树（免登录）
python3 bysy_client.py hot          # 热门医生（免登录）
python3 bysy_client.py probe        # 逐个打 9 个白名单接口
python3 bysy_client.py check-auth   # 有 token 时验是否还有效
python3 bysy_client.py slots 心血管  # 要 token：全院八天有号时段，可带科室关键词
```

```python
from bysy_client import BysyClient

c = BysyClient.from_config({"token": {"token": tok, "userId": uid}})
for row in c.slot_rows(only_available=True):
    print(row["visitDate"], row["amPm"], row["deptName"], row["doctorName"], row["leftNum"])
```
