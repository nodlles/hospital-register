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
| 148 | `https://usr/app-service.js` | 1963462（12738 行）|
| 150 | `https://usr/subpackage-call/app-service.js` | 845506 |
| 224 | `https://usr/modules/appointment/app-service.js` | 231195（2655 行）|
| 146 | `https://usr/__plugin__/wx1fe8d9a3cb067a75/appservice.js` | — |
| 134 / 110 / 144 | `lib/WASubContext.js` / `WAServiceMainContext.js` / `WmpfInject` | — |

早期版本（1.0.1）的 `Debugger.getScriptSource`、codecache 反编译、HeapProfiler 捞堆
全都不必要了：`wad_save_script_source` 一句就能把真源码落盘。

**分包是按需加载的**：主包只有 148，`subpackage-call` 和 `modules/appointment` 得等对应
页面打开才出现。要抓预约相关的代码，先用 logic 层 `wx.navigateTo` 进一次预约页：

```
wad_evaluate_script {"layer":"logic",
  "expression":"new Promise(r=>wx.navigateTo({url:'/modules/appointment/doctor_intro/index',
                 success:()=>r('ok'),fail:e=>r('fail')}))"}
wad_list_scripts     # 这时才多出 224 = https://usr/modules/appointment/app-service.js
```

页面清单可以从运行时配置里读：
`__wxConfig.pages`（主包页面）和 `__wxConfig.subPackages`（分包 root，
`modules/appointment/`、`modules/patient/`、`modules/cloud_room/` 等 20 个）。

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
| `api/v2/appointment/area/getVisitSchedules` `{"departmentId":<真实科室 _id>}` | 200，**100s / 10.9 MB / 276 个科室 / 4242 条排班** |
| `api/v2/appointment/getVisitSchedulesTimes` 整条排班 + `userId` | 200，**条数 = 排班 `leftNum`**，每条带 `15:30~15:40` 之类时段，0.2s |
| `/api/v2/person/patient/patientManager` `{"userId":...}` | 200「请求成功」，**`[]`：这个账号没有就诊人** |

`getDepartmentDoctors` 的请求体（源码调用点原样，已实测字段全对）：

```json
{"departmentAppointmentId":"<科室 _id>","showInternet":false,"getSchedule":true,
 "isToday":false,"departmentType":"gh","userId":"<userId>","mTicket":"","mRandstr":""}
```

`departmentAppointmentId` 就是科室列表里的 `_id`（不是 `deptSn`、不是 `id`）。
只有 `isAppointment:true` 的科室有号，非可挂号科室回空列表。

### 号源矩阵（`getVisitSchedules`）的坑

* **必须是真实科室 `_id`**：传真实 id 才是那份「276 科室 × 8 天」全量矩阵；换任意
  一个真实 id 结果都一样（服务端只拿它认路，不拿它筛，`startDate`/`endDate` 同样不理）。
* **假 id / 空串会让服务端一直算不回来**：`{"departmentId":"x"}` 实测 600s 都没响应
  （连响应头都不到），空 body 则直接回 `[]`。所以 `schedules()` 留空时先打
  `getDepartments` 自动挑一个 `isAppointment:true` 的 `_id` 当锚点并缓存
  （`_schedule_anchor()`），别自己传空值。
* **一次 10.9 MB、约 100s**：默认超时给到 300s（`SCHEDULES_TIMEOUT`），别用普通接口的
  15s；解析后筛选（`slot_rows()`）全部在客户端做。
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

### 分时段（`getVisitSchedulesTimes`）

源码 `modules/appointment`（单独的端文件 `https://usr/modules/appointment/app-service.js`，
要先进预约页才会加载）里的 `queryScheduleTimes(schedule)`：

```js
m = Object.assign({}, schedule, {userId: f()})   // 整条排班原样展开，只补 userId
d.default.queryScheduleTimes(m)
```

所以请求体就是**号源矩阵里那一整条排班**（81 个字段全带上，别裁），把锚点 `_id`
抠掉也照样返回，但别省——源码不省。

响应 `data` 是数组（源码 `getScheduleTimes` 兼容对象/数组），**一条就是一个可约的号**：

| 字段 | 含义 |
| --- | --- |
| `beginTime` / `endTime` | 就诊时段，如 `15:30`~`15:40`（实测每条都有值） |
| `sortSn` / `yyhSn` | 号序 / 预约号，下单要回传 |
| `schduleTimeSn` | `"175224186|4465615"`（源码就是这个拼写），时段标识 |
| `timeText` | 实测都是 `"无"`，其他值表示特殊提示 |
| `_id` / `id` | **与排班 `_id` 相同**，源码当 `visitScheduleTimeId` 回传 |

**坑**：返回条数 = 排班 `leftNum`（余 24 号就回 24 条），而每条里的 `leftNum`/`totalNum`
恒为 `0`——它是「这一条本身就是一个能约的号」，不是剩余数，别拿它筛。挑时段按
`beginTime` 升序即可（`interval_rows()` 已经排好）。

### 就诊人

`POST /api/v2/person/patient/patientManager {"userId": ..., "showLoading": true}`
（源码 `getPatientList`，注意路径带前导 `/`）→ 就诊人数组，每人的 `patientCards[0].id`
就是下单要的 `patientCardId`。

实测这个账号回 `[]`：**没有就诊人时点「在线挂号」直接弹「暂无就诊人，请先添加就诊人」**。

### 下单（`createAppointment`）

源码 `modules/appointment/order_confirm` 的 `createAppointment`：

```js
g = Object.assign({}, timeInfo || {}, schedule)
y = Object.assign({
      scheduleId: schedule._id || schedule.id,
      visitScheduleTimeId: timeInfo ? timeInfo._id || timeInfo.id : null,
      patientCardId: patient.patientCards[0].id,
      appointmentType: selfPay ? "zf" : "yb",
      beginTime: timeInfo ? timeInfo.beginTime : "",
      endTime:   timeInfo ? timeInfo.endTime   : "",
      sortSn:    timeInfo ? timeInfo.sortSn    : "",
      yyhSn:     timeInfo ? timeInfo.yyhSn     : "",
      mTicket, mRandstr, userId, clientType: "wechat",
    }, g)
```

**注意 `g` 在最后合并**，排班行和时段里的同名字段会覆盖上面那些默认值，所以实现里
先摆默认值再 `payload.update({**timeInfo, **schedule})`（`build_appointment_payload()`
就是干这个的，37 个默认字段 + 排班 80 多个字段，实测拼出来 81 个键）。

成功回 `data._id`（appointmentId）、`appointmentFee`、`createdAt`；自费接着 `createPayment`，
医保走 `checkAppointmentPayment`。

**为什么默认 `dry_run=True`**：下单前小程序一定会弹腾讯验证码组件，`mTicket`/`mRandstr`
只能在小程序里拿到；再加上这个账号没有就诊人，写接口目前没法端到端验证。

### 支付（`createPayment`）

源码 `modules/appointment/payInfo`：

```js
{appointmentId, payWay: "MINIPROGRAM", openId}   // openId 从 storage 的 "openId" 取
```

返回 `data.orderInfo` 是**一段 JSON 字符串**，内容就是 `wx.requestPayment`
的参数（`timeStamp` / `nonceStr` / `package` / `signType` / `paySign`）。

**这是纯 HTTP 的终点**：`wx.requestPayment` 只能在微信小程序里调起，服务端调不动。
所以自动化的极限是「下单成功 + 拿到支付参数」，最后一下必须在小程序里点
（或者用 WeAppDev 驱动小程序 UI 去点 `payInfo` 页）。

## 还没校准的

* `getDoctors`（v1，department 那个）：白名单里留着，当前版本没有调用方，估计是废弃 handler。
* 医保链路：`checkAppointmentPayment` / `afterQueryHisOrderStatus` / `yb/*`，全部依赖于
  「先有一个成功的下单」，同样卡在就诊人。

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
