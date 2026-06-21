# Claude 防封号(anti-ban)使用指南

本文档说明本 fork 在网关层新增的 **Claude 账号防封** 能力:如何配置、每个参数的含义、如何对接你的住宅 IP 部署方案,以及如何通过管理 API 观察出口状态。

> 本功能是把《Claude 防封部署指南》里**网关能落地的原则**搬进代码。请求层的 Claude Code 客户端指纹伪装(Beta 头、计费头、User-Agent、会话 ID)由 Claude executor 始终自动施加,**不在本配置范围内、也无需手动开启**。

---

## 一、它解决什么问题

Anthropic 的风控会盯以下信号(对应部署指南里的红线):

| 风控信号 | 本功能如何应对 |
|---|---|
| 同一终端跑多个并发请求,像脚本滥用 | 按账号限制同时在飞的请求数(默认 1) |
| 一个 IP 挂多个 Claude 号 = 账号共享 | 检测多个账号共用同一出口 IP 并告警 |
| 出口是机房/托管 IP(非住宅) | 经代理探测出口 IP 信誉,机房 IP 告警 / 可强制下线 |
| 账号在多个 IP 间跳变 / 频繁换 IP | 监控每账号出口 IP 变化并告警 |
| 出口不在预期国家(异地登录) | 校验出口国家,非预期国家告警 |
| 账号裸奔在服务器真实 IP 上 | 强制每个 Claude 账号必须绑定专属代理 |

> **网关管不到的部分**:WebRTC 关闭、Clash 常开 / Rule 模式、比特浏览器指纹隔离——这些属于浏览器 / 操作系统部署层,仍需按部署指南在主机上配置。本功能不替代它们。

---

## 二、整体配置

全部配置在 `config.yaml` 的 `anti-ban` 块下。**完全可选**:`enabled: false`(默认)时一切行为与上游一致。支持热重载,改完保存即生效,无需重启。

```yaml
anti-ban:
  enabled: true                    # 总开关。false 时下面全部忽略

  # —— 并发与节奏 ——
  max-concurrent-per-auth: 1       # 每个账号同时在飞的请求数上限。1=一次一个(推荐);0=不限
  concurrency-wait-timeout-ms: 0   # 账号满载时,请求等待空位的最长毫秒数。0=一直等到空出或客户端断开
  jitter-min-ms: 0                 # 派发前随机延迟下限(毫秒)
  jitter-max-ms: 0                 # 派发前随机延迟上限。两者都为 0 = 不抖动
  min-request-interval-ms: 0       # 同一账号两次派发的最小间隔(毫秒)。0=不限

  # —— 账号↔代理强绑定 ——
  require-proxy: false             # true 时,没有自己 proxy-url 的 Claude 账号会被踢出轮询

  # —— 出口 IP 自检 ——
  ip-check:
    enabled: false                 # 出口 IP 自检总开关
    interval-minutes: 0            # 定时复查间隔(分钟)。0=仅启动时查一次
    timeout-seconds: 10            # 单次 IP 查询超时(秒)。0=默认 10s
    strict-datacenter: false       # true 时,机房/托管出口 IP 的账号被踢出轮询;false 仅告警
    warn-shared-egress: true       # true 时,多个账号共用同一出口 IP 时告警
    warn-ip-change: true           # true 时,账号出口 IP/国家变化时告警(需 interval-minutes > 0)
    expected-country: ""           # 期望出口国家 ISO 码(如 "US")。非该国告警;空=不校验
```

---

## 三、参数详解

### 并发限制 `max-concurrent-per-auth`
每个账号(凭证)在任一时刻最多允许多少个请求同时打到上游。
- **`1`(推荐)**:模拟"一个终端一次一个请求",彻底避免脚本式突发。
- **`0`**:不限制(回到上游默认行为)。
- 超出上限的请求会**排队等待**,而不是立即失败(等待时长见下一项)。

### 并发等待超时 `concurrency-wait-timeout-ms`
账号满载时,新请求等待空位的上限。
- **`0`(推荐)**:一直等,直到有空位或客户端自己断开。
- **`> 0`**:等待超过该毫秒数后,**自动切换到下一个可用账号**(故障转移),而不是直接报错。注意:此等待发生在与上游建立连接**之前**,不违反"连接建立后不设超时"的约束。

### 请求抖动 `jitter-min-ms` / `jitter-max-ms`
在每次派发前注入 `[min, max]` 之间的随机延迟,弱化机器般的规律时序。
- 两者都为 `0` = 关闭。
- 会增加延迟,**建议小值**(如 50–300ms)或保持关闭。

### 最小请求间隔 `min-request-interval-ms`
同一账号两次派发之间至少间隔多少毫秒。
- 与抖动**叠加**,取两者较大值。
- **重要语义**:严格的间隔保证仅在 `max-concurrent-per-auth: 1`(请求串行化)时成立;并发 > 1 时为避免延迟无限堆积,间隔会被放宽(突发下延迟有上界,最多约一个间隔)。

### 账号↔代理强绑定 `require-proxy`
- **`true`**:任何**没有配置自己 `proxy-url`** 的 Claude 账号,会被排除出选择,绝不走服务器裸 IP。
- 仅作用于 Claude,其他 provider 不受影响。
- 配合下面的"如何给账号配代理"使用。

### 出口 IP 自检 `ip-check`
经每个账号的代理,向 `ipapi.is` / `ip-api.com` / `ipinfo.io` **三库交叉验证**出口 IP,任一库判定机房/托管即视为风险。
- **`enabled`**:自检总开关。
- **`interval-minutes`**:`0` 只在启动时查一次;`> 0` 按分钟定时复查(IP 变化监控需要它 > 0 才能多次采样)。
- **`strict-datacenter`**:`true` 时把机房出口的账号**踢出轮询**(直到下次确认干净才恢复);`false` 仅写告警日志。
- **`warn-shared-egress`**:多个账号解析到同一出口 IP 时告警(对应"一个 IP 多个号")。
- **`warn-ip-change`**:账号出口 IP 或国家在两次检查间变化时告警。
- **`expected-country`**:填 `"US"` 之类,出口不在该国就告警;留空关闭。

> **有效出口的判定**:自检探测的出口 = 账号自己的 `proxy-url`,若没有则回退到全局 `proxy-url`——与真实请求走的路径完全一致。两者都没有时,会告警"将走服务器裸 IP"。

---

## 四、如何给每个账号配专属代理

防封的核心是**每个账号一个干净的住宅出口 IP**。代理按以下优先级解析:

1. 账号自己的 `proxy-url`(每个 OAuth 凭证文件里的字段)
2. 全局 `proxy-url`(`config.yaml` 顶层)

**强烈建议每个 Claude 账号配各自不同的 `proxy-url`**,指向各自的住宅 IP。共用一个全局代理 = 所有账号同一出口 = 触发"一个 IP 多个号"。

### 在 OAuth 凭证文件里设置
每个 Claude 账号的 token 文件(`auths/` 目录下的 JSON)可加 `proxy_url` 字段:

```json
{
  "type": "claude",
  "access_token": "...",
  "refresh_token": "...",
  "proxy_url": "socks5://user:pass@proxy-a.example.com:7085"
}
```

支持 `socks5://` / `http://` / `https://`;也支持 `direct` / `none` 显式绕过全局代理。

> 配合 `require-proxy: true`,任何漏配 `proxy_url` 的账号会被自动踢出轮询,避免裸奔。

---

## 五、观察出口状态(管理 API)

新增只读端点,查看每个 Claude 账号的当前出口情况:

```
GET /v0/management/anti-ban/egress-status
```

需带管理鉴权(与其他 `/v0/management/*` 端点一致)。返回示例:

```json
{
  "egress-status": [
    {
      "auth_id": "a1b2c3...",
      "label": "claude-LA",
      "ip": "128.241.24.166",
      "country": "US",
      "isp": "NTT America, Inc.",
      "is_datacenter": false,
      "blocked": false,
      "source": "ipapi.is+ip-api.com",
      "checked_at": "2026-06-21T11:30:00Z",
      "error": ""
    }
  ]
}
```

字段含义:

| 字段 | 含义 |
|---|---|
| `ip` / `country` / `isp` | 该账号当前出口 IP、国家、ISP |
| `is_datacenter` | 是否被判定为机房/托管 IP |
| `blocked` | 是否当前被踢出轮询(strict 模式下机房 IP) |
| `source` | 命中的信誉库(`+` 连接表示多库都返回) |
| `checked_at` | 本次检查时间 |
| `error` | 本次查询失败时的错误信息 |

- `ip-check.enabled: false` 或自检尚未跑过时,返回空列表 `[]`。
- 此端点纯只读,不改变任何路由行为。

---

## 六、推荐配置(对照部署指南)

适配"静态住宅 IP + 每账号独立代理"方案的最贴合配置:

```yaml
anti-ban:
  enabled: true
  max-concurrent-per-auth: 1      # 一次一个,杜绝脚本式突发
  require-proxy: true             # 漏配代理的账号直接下线,杜绝裸奔
  ip-check:
    enabled: true
    interval-minutes: 30          # 每 30 分钟复查,才能监控 IP 漂移
    strict-datacenter: true       # 机房 IP 账号自动下线
    warn-shared-egress: true      # 多号共用出口告警
    warn-ip-change: true          # 出口 IP/国家漂移告警
    expected-country: "US"        # 出口必须美国
```

然后给每个账号的凭证文件配各自的 `proxy_url`(见第四节)。

> 提醒:每个账号定时复查会通过其代理发起对外查询(`ipapi.is` 等)。`interval-minutes` 不宜过小(建议 ≥ 15),避免频繁外部请求。

---

## 七、注意事项

- **本功能不替代主机层部署**:Clash 链式代理过墙、比特浏览器指纹、WebRTC 关闭仍需按部署指南在主机配置。网关只负责出站到上游那一段的账号卫生。
- **全部可选、可热重载**:`enabled: false` 完全回到上游行为;改配置保存即生效。
- **关闭即释放**:关掉 `anti-ban` 或 `strict-datacenter` 后,之前被踢出轮询的账号会立即恢复(不需要重启)。
- **IP 自检超时是诊断探针**:`timeout-seconds` 仅作用于自检的对外查询,不承载任何 provider 流量。
