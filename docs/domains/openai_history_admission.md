# OpenAI OAuth 历史准入

本文定义 TokenRouter 的外部对话历史限制、长期归属和账号调度边界。功能沿用 sub-custom 的严格准入语义，但不移植其跨组 OAuth 共享权限、Prompt Audit 引擎或审核回执。TokenRouter 原有的内容审核、分组权限、账务和协议转换继续独立生效。

章节导航：[配置](#history_policy)、[分类](#history_classification)、[存储](#durable_ownership)、[预占与确认](#reservation_confirmation)、[调度](#history_routing)、[错误与升级](#history_errors)、[分组隔离](#group_isolation)。

<a id="history_policy"></a>
## 配置与作用范围

账号字段 `extra.openai_oauth_reject_external_history` 仅作用于 OpenAI OAuth，缺省为 `false`，只有显式 JSON 布尔值 `true` 才启用；字符串、数字或 null 在管理写入时拒绝，旧异常数据在读取时告警并按关闭处理。新建账号和未配置字段的存量账号不会自动启用，已有显式 `true` 则保留。API-key、setup-token 和其它平台不启用该限制。

后台创建和编辑 OAuth 凭据母账号可设置该开关；批量编辑必须勾选修改此项，且目标必须全部是 OpenAI OAuth 凭据母账号。影子账号使用母账号当前策略和凭据身份，不能通过自身 extra 放宽。调度 metadata 显式保存有效布尔值；旧 metadata 缺失字段时回源重建，避免丢失数据库中的明确配置。

关闭限制只允许该账号接收原本没有归属的历史，不关闭长期归属记录、内容审核或分组权限。数据库不可用时，OAuth 请求仍不能把未记录的响应 ID 暴露给客户端。

<a id="history_classification"></a>
## 首轮与历史

历史分类使用 `internal/auditcontent` 的协议解析结果，作用于经过鉴权、基本 JSON 校验和现有内容审核后的输入副本。分类不修改向上游发送的正文，也不以“不是当前轮审核文本”推断它必然是历史。

- 多条首轮 user 消息、system/developer 指令、工具声明以及 Codex `additional_tools` 声明均可属于新会话。
- assistant 消息、工具调用和工具返回、opaque/压缩上下文、`previous_response_id`，以及含未能完整理解内容的请求，按历史请求处理。
- `additional_tools` 同级存在 assistant、真实工具结果或不完整内容时不能豁免；工具声明仍交由原有审核逻辑处理，本功能不重写 TokenRouter 的审核提取规则。
- 同一用户和分组已有已确认的有效 session 归属时，即使当前只发一条 user 消息，也按已归属历史判断；预占记录只用于路由，不会让首轮失败后的普通新请求变成历史。

覆盖 HTTP Responses（含 compact）、Chat Completions、Messages，Responses WebSocket 首轮与每轮，以及两个只读计数入口。内容审核阻断应发生在历史归属查询、账号选择和上游写入前；计数不能新建会话或响应归属。

<a id="durable_ownership"></a>
## 长期归属

迁移 `266_openai_conversation_bindings.sql` 创建 PostgreSQL 表，按用户、分组、绑定类型和标识 SHA-256 唯一定位 session/response。只保存路由账号、凭据母账号、OAuth account/user 身份、API Key ID 和 CAS revision，不保存正文、访问令牌或原始会话/响应标识，不设置 TTL。

归属必须与当前凭据母账号匹配。普通 access token 刷新不使其失效；更换 OAuth 身份、改变母账号关系或删除用户/账号会失效。软删除触发器和物理删除外键负责清理。相同用户的不同 API Key 可共享该用户在同组内的归属；不同用户或不同组不得共享。

迁移 `267_openai_conversation_confirmation.sql` 增加 `confirmed`，缺省为 false，旧记录不凭空回填确认。session 使用 revision 比较交换防止不同账号争抢；同一身份的重复预占保持 revision 和已有确认状态，切换账号或凭据身份时 revision 增加并重新进入未确认状态。response 标识不能改绑到不同凭据身份。Redis 只承担原有短期粘性，不能补造 PostgreSQL 可信归属。服务重启或 Redis 丢失后仍可验证长期归属，但这不保证上游自身的 response 上下文永不过期。

<a id="reservation_confirmation"></a>
## 预占与确认

选择账号时保存未确认的 session 预占，`response.created` 等早期事件返回的响应 ID 同样只保存为未确认。它们不构成严格账号接收历史或 `previous_response_id` 的授权依据。

有效响应定义为带 `resp_` ID、没有非空 error 的成功完成 Response：非流式对象须有 `status=completed`；流式 `response.completed` 或 `response.done` 事件须有 response 对象，且状态为 completed，或完全省略 status、由完成事件明确表达成功。显式空值/null 状态、失败、取消、incomplete、超时、HTTP 200 但只有 created、仅有部分输出或 `[DONE]` 均不确认。

成功完成时先确认 response 归属，再按预占的账号、凭据身份和 revision 确认 session，最后才向客户端输出完成响应。延迟响应不能确认已切换到另一身份的预占；确认失败不发送完成事件。同一身份后续重试不会清除已经建立的成功证据。首轮失败的预占不授权历史，但普通无历史的新请求仍可重试；只读计数不预占也不确认。

这验证的是成功对话归属，不是逐条历史正文的来源证明；不引入完整正文存储或历史摘要链。

<a id="history_routing"></a>
## 调度与响应

基础和高级调度器均在候选过滤时检查策略。某个严格账号拒绝后继续尝试其它合格候选，不触发账号冷却或消耗上游失败切换额度。已有归属的历史不能因首次候选不可用、粘性逃逸或 WS 当前轮重试而被另一个严格凭据账号接走；明确关闭限制的账号仍按原有调度条件参与。

已取得或等待取得并发槽后，转发前重新读取配置并复查归属；WebSocket 每轮重建准入状态，以当前轮而非首轮状态执行重试。选定路由先保存 session，response ID 在 HTTP JSON/SSE、兼容格式转换及 WS 输出前保存，保存失败终止输出，不能将未持久化的 ID 发给客户端。

历史准入不新增协议兼容性：例如 HTTP OAuth 对 `previous_response_id` 的既有支持限制不因此被取消；允许历史也不能绕过模型、分组、transport 和账号健康条件。

<a id="history_errors"></a>
## 错误与升级

| 场景 | HTTP 状态 | 错误码 |
| --- | --- | --- |
| 严格候选无法接收历史 | 400 | `external_history_not_allowed` |
| 归属查询或持久化不可用 | 503 | `conversation_ownership_unavailable` |
| 并发归属冲突 | 409 | `conversation_routing_conflict` |
| WS 后续轮次需要重新建立会话 | WS error 事件 | `conversation_reconnect_required` |

SSE/WS 已开始时不能修改线上的 HTTP 200/101，改为发送带错误码的终止事件。Ops 按本地 gateway/routing 拒绝记录，不伪装成上游故障，也不携带前次重试的账号或上游错误详情。

升级后未配置字段的旧账号默认关闭限制。管理员明确开启后，没有已确认长期归属的历史可能被拒绝；不会从 Redis、日志或正文自动补录，应开启新会话或明确允许指定账号接收外部历史。先备份数据库，再由应用迁移器执行新增迁移；避免旧版应用继续接收内容却不写确认状态的混合版本窗口。应用回退不会删除新表，但旧应用也不会执行新的确认限制。

<a id="group_isolation"></a>
## 与分组会话隔离的关系

两者是独立、叠加的准入条件，不会相互覆盖：

| 配置 | 判断依据 | 存储与范围 |
| --- | --- | --- |
| 分组“开启会话隔离” | 显式会话的首次 owner 是否属于其它分组；仅目标分组开启时拒绝跨入 | Redis，用户/source/session 命名空间，有 TTL |
| 账号“拒绝外部历史请求” | 历史是否有当前用户、当前分组、当前凭据身份的已确认归属 | PostgreSQL，无 TTL，仅 OpenAI OAuth |

分组隔离未开启时也会记录显式 session 的首次归属；它不等待上游成功，这一既有行为不因账号确认机制改变。它不识别所有无显式 session 的历史导入，也不限制同组内切换凭据账号。账号限制则不能代替跨组隔离：两个不同分组即使共用同一个 OAuth 凭据，仍各自需要历史确认；关闭分组隔离不意味着允许历史跨组迁移。

HTTP/WS 中，分组隔离检查先于账号预占；WS 后续轮次同样如此。分组拒绝不会因此建立账号确认归属，账号默认关闭也不会放行分组隔离拒绝。两项都开启时，先遇到的拒绝返回给客户端。

实现入口为 `openai_history_admission.go`（service/handler）、`account_conversation_binding_repo.go` 和账号管理弹窗；回归覆盖协议分类、混合候选、跨重启归属、HTTP/WS 输出顺序及真实 PostgreSQL 身份校验/CAS/清理。

相关文档：[调度与缓存](../architecture/account_scheduling_and_cache.md)、[网关生命周期](../architecture/gateway_request_lifecycle.md)、[内容审核](content_moderation.md)、[部署与迁移](../operations/deployment_and_migrations.md)。
