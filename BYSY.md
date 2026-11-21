# 北京大学第三医院（北医三院）接入说明

`bysy_client.py` 是把「北京大学第三医院」微信小程序的接口接进本项目的一组代码。
跟中日友好那套 config 驱动的源不是一条路：这个医院所有业务请求都走 `patwx.puh3.net.cn`，
带 token 时请求体还要用国密 SM4 加密，所以单独成模块。

AppID：`wx3302a1b5a5f91dc4`，小程序版本 `2.2.2`。

## 状态

| 部分 | 状态 |
| --- | --- |
| 接口客户端（`bysy_client.py`） | 已实现，**免登录的 8 个接口已用真服务器逐个验证通过** |
| 接口清单（`bysy_endpoints.json`） | 已生成，206 条路径，138 个有函数名的带 token 接口 |
| 免登录数据（院区/科室/医生） | **可用**，见下面「实测返回」 |
| 号源 / 排班 | 路径已知，**要 token**，参数未校准，`schedules()` 明确拒绝执行 |
| 下单 / 支付 | **没写**，参数名没和真实返回对齐，不猜 |
| 登录 | **卡在手机号凭证**，见「登录」一节 |
| 带 token 的请求体加密（SM4） | 机制已实现，**密钥推导方式未校准**（没有带 token 的样本） |

## 怎么拿到这些事实的：不抓包，直接取小程序源码

WeAppDev（`github.ryf5584.weappdev`）提供的运行时调试网关开在模拟器里
`http://127.0.0.1:9400`，逻辑层是 V8 isolate，:`9400/devtools/appservice` 就是一个
标准 CDP endpoint。用 `wxdevtools.py` 里已有的 `Cdp` 类直连，`Debugger.enable` 后
`Debugger.getScriptSource` 把三个包整套源码 dump 出来：

| 文件 | scriptId | 字节 |
| --- | --- | --- |
| `https://usr/app-service.js` | 149 | 1941211 |
| `https://usr/subpackage-call/app-service.js` | 151 | 835198 |
| `https://usr/__plugin__/wx1fe8d9a3cb067a75/appservice.js` | 147 | 77429 |

两个关键坑，记下来省下一次折腾：

* `Runtime.evaluate` **必须带 `contextId`**，否则报 `Cannot find default execution context`。
  共两个上下文：`contextId=1`（MainContext）里**没有 `wx`**，`contextId=2`
  （`WxaSub-...`，`isDefault:true`）里才有。所有取 storage、调 `wx.login` 都用 2。
* 异步结果用 `globalThis.__c` 轮询：`wx.login({success:x=>globalThis.__c='OK:'+x.code})`。

## 请求协议

统一包装在 `lib/utils/request`，`app.config.js` 给出 `ENV:"production"`、
`BASEURL:"https://patwx.puh3.net.cn"`、`version:"2.2.2"`。

```
POST {BASEURL}/{path}
Content-Type: application/json
platform: wechat
version:  2.2.2
system:   <wx.getSystemInfoSync().system>
timestamp: Date.now()
token:    <storage token>        # 仅登录后
userId:   <loginUserInfo.userId> # 仅登录后
```

### 两条分界线

1. **免登录白名单只有 9 条**（源码里那个 `d=[...]` 数组，顺序照抄）：
   `doctor/departmentList`、`doctor/departmentItem`、`department/getDepartments`、
   `doctor/department/getDoctors`、`doctor/new/getDoctors`、`wx/evaluate/getEvaluates`、
   `consultation/patient/doctorHasDiagnoses`、`appointment/getHospitalAreas`、
   `patient/free/department/list`。
2. **其余全部要 token**。无 token 打过去一律
   `{"code":"201","msg":"请升级到最新版本，或重新登录！","data":{}}`。
   这个 201 是「未登录／版本不对」的通用码，**不代表参数错**，别拿它当调试信号。

### 带 token 时的请求体加密

第二个包装函数里写死了 `useSM4:!0`，于是
`o={encrypted:SM4Encrypted(JSON.stringify(o), token)}` —— **密钥就是 token 本身**。
真正加密前要先知道 token 怎么变成 16 字节密钥（原始 utf8 截断？hex 解码？），
这一点没有带 token 的真实样本，`bysy_client.sm4_key()` 会在长度不对时直接抛
`BysyNotCalibrated`，不会静默算出垃圾密文。

## 实测返回（2026-11-21，直连真服务器，全程无 token）

| 接口 | 结果 |
| --- | --- |
| `appointment/getHospitalAreas` `{"flag":2}` | 200，7 个院区 + 号源数 |
| `department/getDepartments` `{"isShow":true,"isAffiliated":true}` | 200，69669 B 科室树 |
| `doctor/new/getDoctors` `{"hot":true}` | 200，38009 B，10 位热门医生 |
| `doctor/departmentList` `{}` | 200，223 B，4 个按院区分组（key 是正则） |
| `doctor/departmentItem` `{}` | 200，6382 B，返回「全部」占位 + 科室列表 |
| `wx/evaluate/getEvaluates` | 200，「获取评论」 |
| `patient/free/department/list` `{"flag":2}` | 200，`data:[]` |
| `consultation/patient/doctorHasDiagnoses` | 201「缺少或非法的医生ID」（白名单内但缺参） |
| `doctor/department/getDoctors` | **15s 超时**：白名单里留着，当前版本没有调用方，估计是废弃 handler |
| `appointment/getDepartments` | 201（要登录） |
| `v2/appointment/getDepartmentDoctors` | 201（要登录） |
| `v2/appointment/area/getVisitSchedules` | 201（要登录） |
| `system/getSystemTime` / `auth` | 201（要登录） |
| `login/getLoginId` `{}` | 200，`{"name":"BEIYISAN","push":"..."}` |
| `v2/wx/patient/login` `{"code":...}` | 200，`code:"201"` + **`缺少手机号凭证(phoneCode 或 encryptedData/iv)`**；重发同 code → `code been used` |

院区号源数（可以用来验证数据新鲜度）：

```
北京大学第三医院(本部)  333   北京市海淀区花园北路49号
生殖医学中心             16   北京市海淀区
第二门诊部(育新花园)     36   北京市海淀区育新花园小区23号楼
中央党校院区(肖家河)     29   北京市海淀区大有庄100号
首都机场院区(岗山路)     66   北京市朝阳区岗山路9号
北方院区(紫竹院)         70   北京市海淀区车道沟10号
海淀北部院区(西北旺)    114   北京市海淀区六里屯南路6号院1号楼
```

## 登录：唯一卡点，需要真人手机号

小程序首页 → 院区 → 「手机号快捷登录」→ 必须勾《服务协议》《隐私政策》→
「同意并登录」→ 弹**「请使用微信扫码完成下一步」**二维码，Toast 明说
**「您的微信没有绑定手机号」**。

服务端只认两种凭据：

* `phoneCode`：`wx.getPhoneNumber` 按钮给的手机号凭证；
* `encryptedData` + `iv`：手机号解密所需的那对。

`wx.login` 的 `code` 单独给不行（服务端明确回「缺少手机号凭证」），而且 **code 单次有效**。
换个说法：**北医三院要求微信账号绑定过手机号**，这一步绕不过去，必须真人参与。

模拟器里的微信是 clone 运行时（WeAppDev），没有真实登录态，所以：
`wx.getStorageSync('token')` 空、storage 里没有 `loginUserInfo`、扫码走不通。
APK 里确实带微信的手机号插件（`PhoneNumberAddUI`、`cgi-bin/.../customphone/sendverifycode|checkverifycode`），
但要真微信登录态才能收验证码。

目前手上没有 token，所以号源/排班/下单都还没法校准字段名。

## 还没校准的（不猜，不写「大概对」的实现）

* `v2/appointment/area/getVisitSchedules`（排班）请求体字段名；
* `v2/appointment/getVisitSchedulesTimes`（时段号源）；
* `v2/appointment/createAppointment`（下单）+ `v1/payment/createPayment`（支付）；
* 带 token 时请求体 SM4 的密钥推导与响应体是否也加密；
* `getDoctors`（v1，department 那个）的参数与可用性。

拿到一个 token 之后校准顺序：先 `getHospitalAreas` 验有效期 →
`getDepartmentDoctors`（带 `getSchedule:true`）看号源字段 → 再 `getVisitSchedules` → 最后才碰写接口。

## 命令

```bash
python3 bysy_client.py areas       # 七个院区号源数
python3 bysy_client.py depts       # 科室树
python3 bysy_client.py hot         # 热门医生
python3 bysy_client.py probe       # 逐个打 9 个白名单接口
python3 bysy_client.py check-auth  # 有 token 时验是否还有效
```
