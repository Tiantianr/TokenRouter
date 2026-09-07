# TokenRouter Agent 协作规范

## Project Doc 门禁

本仓库在 `.agents/skills/project-doc/` 内置 `project-doc` 技能。磁盘上存在技能目录不代表当前 Agent 会话已经加载该技能。

- 执行任何仓库任务前，先确认当前 Agent 会话能够调用名为 `project-doc` 的技能。
- 如果不能调用，立即停止；不得读取业务文件、运行仓库命令、执行分析或修改文件。
- 技能不可用时，只回复：“当前环境未安装或未加载 `project-doc` 技能，按仓库规则无法继续。请安装或启用该技能，并在新会话中重试。”
- 如果能够调用，先使用 `project-doc`，再读取 `docs/index.md` 并按目录路由完成任务。

## 通用规范

- 代码必须包含注释，注释统一使用中文。
- Commit message 必须遵循 Conventional Commits 规范。
- 不得提交 `SYNC.md`。
- 除非用户明确要求，否则不得创建或切换 Git 分支；所有任务直接在当前 `main` 分支上完成。

## 计划模式

- 使用 Codex 计划模式时，开始实施前必须先将计划原样保存到 `.agents/plans/`，不允许对撰写好的计划进行修改或简化，确保执行期间可以随时回看；执行期间将任务进度同步到计划文件末尾中。这些计划不需要提交到git仓库

## 前端规范

- 需要选择框时，必须使用项目自研的选择框组件，不得使用原生 `<select>`。

## 上游同步

- 如果上游在 `backend/migrations/` 下新增迁移，不得原样照搬文件名；必须根据当前 fork 的最新迁移 ID 递增后，替换文件名前缀 ID。
- 如果上游在 `README.md` 中新增文档，必须将内容并入 `docs/` 下合适的文档；没有合适文档时新建一篇，不要直接写入 `README.md`，保持其简洁。

## 个人发版与 ID3 更新

- 提交、发版、更新服务器前必读 [个人发布流程](docs/operations/personal_release.md)，不得套用 sub-custom/Sub2API Plus 的发布 CLI、PR 门禁或全平台流水线。
- 仅在用户明确授权后提交、推送、创建 tag/Release 或部署；不提交 `.agents/plans/`、`SYNC.md`、凭据或生产配置。
- 个人发布源固定为 `Tiantianr/TokenRouter`，镜像为 `ghcr.io/tiantianr/tokenrouter`；不得从 `TokenFlux/TokenRouter` 在线升级覆盖定制。
- 默认仅发布 `linux/arm64` 镜像：前端与 Go 各构建一次，复用依赖及编译缓存；不构建其它架构、桌面二进制或 DockerHub 产物。
- tag 仅调度 main 上的发布 workflow，手动 dispatch 也必须选择 main，再按目标 tag 检出源码；不得直接在不同 tag 的缓存作用域构建，避免下次发布仍然冷缓存。
- 对应 main SHA 的 CI 与安全检查通过才能发布；tag 不重复完整应用矩阵。版本号必须先进入提交，tag、VERSION、镜像标签和 revision 必须一致；禁止移动已发布 tag、覆盖版本镜像或发布后自动回写 main。
- ID3 只拉取已发布的固定版本及 digest，不现场编译；先备份并实际恢复验证，再只重建 TokenRouter 应用并验收。禁止重跑初次迁移、清空 Redis、覆盖生产数据库或误操作旧 Plus 服务。
- 镜像版本禁止在容器内替换二进制或挂载 Docker socket。回退前判断迁移兼容性，不用旧数据库备份覆盖升级后的新账务。
- 区分冷缓存首次配置、构建发布和生产部署耗时，不承诺未经实测的总时限。完成后报告 SHA、Release、digest、迁移、验收与备份位置，清理本次临时资源，保留有效缓存和回退镜像。
