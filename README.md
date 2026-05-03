# 中日友好医院号源监控服务

这个工具用于本地半自动监控微信小程序号源。它不会无人值守提交预约：发现号源后会在页面列出候选号源，只有输入配置里的确认词才会发送最终预约请求；成功后停在待支付订单，不做支付。

## Web 服务

启动：

```bash
docker compose up --build
```

打开：

```text
http://localhost:8000
```

页面支持：

- 首次启动授权向导，支持 HAR 上传和 cURL 粘贴导入
- 选择院区和门诊科室
- 选择挂号日期、上午/下午、医生策略
- 设置开始时间、监控时长、轮询间隔
- 开启/停止监控任务
- 命中号源后手动输入确认词提交预约
- 命中号源和提交成功时发送 Webhook 通知

## 使用步骤

1. 启动服务：

```bash
python3 app_server.py
```

如果本地配置不存在，服务会自动从 `config.example.json` 生成一份：

- 直接运行：`config.local.json`
- Docker Compose：`.hospital-register/config.local.json`

本地配置会包含登录态，已经在 `.gitignore` 中排除，不要提交。

2. 打开页面并完成“授权与配置”。

页面会提示先用微信打开医院小程序完成登录和就诊人选择，再从调试代理导出请求。

推荐方式是上传 Reqable、Charles 或 Proxyman 导出的 HAR 文件；备用方式是粘贴一条 `https://appaceso.zryhyy.com.cn` 的业务请求 cURL。导入后服务会自动提取：

- `base_url`
- 登录态相关 headers
- 最终提交接口路径
- 请求体里的 `patientCode`，如果粘贴的是提交预约请求

向导会显示这些检查项：

- 登录态是否已导入
- 登录态验证是否通过
- 就诊人编码是否已识别
- 提交接口是否已识别
- 本地配置是否已保存

当前项目不能只靠网页登录页“扫码后自动回填”登录态，因为医院小程序没有公开的二维码登录回调协议。页面里的扫码步骤用于让用户在微信端完成授权，配置回填通过 HAR 或 cURL 导入完成。

如果本机 Python 报证书校验失败，优先安装/使用 `certifi`。也可以在 `tls.ca_bundle` 指定 CA 文件路径；不建议把 `tls.insecure_skip_verify` 改成 `true`，除非只是本地临时排查。

3. 如需提交预约，导入提交接口：

`endpoints.submit` 需要从 Reqable 的最终提交预约请求复制路径。本次抓到的提交链路是先调用
`/api/mobile/source/locking/pre/check`，再调用 `/api/mobile/source/locking` 生成待支付订单。
请求体形态已由脚本生成：

```json
{
  "patientCode": "...",
  "sourceCode": "...",
  "deptCode": "Z279",
  "doctorCode": "...",
  "treatmentDate": "...",
  "treatmentPeriodType": "AM",
  "sendMsg": false
}
```

如果皮肤科号源支持分时段，脚本会追加 `timeIntervalCode`；这时还需要填写 `endpoints.time_intervals`。

4. 命令行运行：

```bash
python3 app_server.py
```

只监控不提交：

```bash
python3 hospital_watch.py --config config.local.json --no-submit
```

只检查一次：

```bash
python3 hospital_watch.py --config config.local.json --once --no-submit
```

忽略 `start_at` 立即检查一次，适合测试配置：

```bash
python3 hospital_watch.py --config config.local.json --now --once --no-submit
```

只检查配置是否还存在占位项：

```bash
python3 hospital_watch.py --config config.local.json --check-config
```

## 默认目标

- 医院：中日友好医院本部
- 科室：痤疮专病门诊(皮肤)
- `districtCode`: `001`
- `deptCode`: `Z279`
- 默认优先：专家门诊号源排在普通号源前面
- 医生策略：`不限医生` 不过滤，`专家优先` 排序靠前，`必须专家` 过滤非专家号源

关键监控接口：

```text
GET /api/mobile/source/dept/calendar?deptCode=Z279
GET /api/mobile/source/dept/detail?deptCode=Z279&visitDate=...
```

发现以下状态才认为可预约：

```json
{
  "sourceStatus": "HAVE_INVENTORY",
  "count": ">0"
}
```

## 安全边界

- 脚本不会保存或打印完整身份证、手机号。
- `config.local.json` / `.hospital-register/config.local.json` 会包含登录态，不要提交。
- Webhook URL 也只保存在本地配置；页面只显示是否已配置，不回显完整 URL。
- 最终预约必须终端手动确认。
- 付款不在脚本内处理。

## 消息通知

页面的“消息通知”区域支持这些渠道：

- Bark：填写 Bark App 里的 Device Key；默认服务器是 `https://api.day.app`，自建 Bark Server 可改。
- Server 酱：填写 SendKey。
- Telegram：填写 Bot Token 和 Chat ID，Bot Token 可从 BotFather 获取。
- 自定义 Webhook：填写 URL，默认 POST JSON，也可选 GET。

启用后会在两个时机发送通知：

- 发现可预约号源：提醒尽快打开监控页面确认提交。
- 预约提交成功：提醒尽快到微信小程序内完成支付。

自定义 Webhook 的默认 POST JSON 形态：

```json
{
  "title": "中日友好医院发现可预约号源",
  "message": "2026-05-04 上午 | 医生 | 专家门诊 | 余号 1",
  "event": "hit",
  "time": "2026-05-03T17:20:00"
}
```

如果选择 GET，请求会把这些字段放到 query string。通知发送失败不会中断监控任务。
