# 个人仓库发布与 ID3 更新

本文拥有 `Tiantianr/TokenRouter` 的个人发行、镜像升级和生产验收流程，不适用于原 `sub-custom` 仓库，也不包含首次跨工程数据迁移。入口规则保存在根 `AGENTS.md`，流水线以 `.github/workflows/release.yml` 为准。

## 授权与版本

提交、推送、tag/Release/镜像发布、生产部署均须用户明确授权。直接使用用户指定的当前 main，不自行创建分支，不提交本地计划、`SYNC.md` 或秘密。不要调用 Plus 的 `push-cli`、`release-cli` 或旧迁移工具。

版本使用递增的三段数字 `X.Y.Z`，与上游版本序列分开管理。先把版本写入 `backend/cmd/server/VERSION` 并提交，再创建指向该确切 SHA 的 annotated tag `vX.Y.Z`。tag body 必须包含中文变更说明、上游基线、兼容性、迁移、已知问题和回退约束。禁止移动已发布 tag 或复用版本。镜像 tag 不带 v，不发布可漂移的 latest 作为生产更新依据。

<a id="release_pipeline"></a>
## ARM64 流水线

1. 推送 main，CI 和 Security Scan 验证该确切 SHA。发布脚本和升级来源变更运行针对性检查；已经完成的功能验证不因创建 tag 在本地完整重跑。
2. `v*` tag 或现有 tag 的 workflow dispatch 触发 Personal ARM64 Release。只允许个人仓库执行，验证 VERSION/tag/SHA 和 main 祖先关系，不自动修改源码或回写版本。
3. 使用原生 ARM64 runner。Node 22、pnpm 9.15.9 容器构建一次前端，Go 1.27.0 容器只构建一次嵌入前端的 Linux ARM64 程序；具体工具链以 workflow 和 `backend/go.mod` 为准。
4. 缓存包含 pnpm store、Go modules、Go build 和运行时镜像层。依赖缓存键包含工具链、manifest/lock 哈希；同依赖代内源码变化复用编译缓存，不跨依赖代恢复。冷缓存首次发布会明显慢于后续发布。
5. `Dockerfile.goreleaser` 仅包装预编译程序和运行时资源，不再次编译，不执行 GoReleaser 的跨平台矩阵。运行容器验证程序、ARM64 架构、PostgreSQL dump/psql 工具。
6. 构建和 main 验证并行，发布前必须确认同 SHA 的 CI 与 Security Scan 成功。失败不发布，不通过跳过检查或现场编译绕过；tag 不重复触发这两个完整工作流。
7. 只发布 `ghcr.io/tiantianr/tokenrouter:X.Y.Z` 与 GitHub Release。Release 附带 `release-manifest.json`，绑定版本、完整 SHA、平台、构建类型和镜像 digest；镜像必须公开且可由生产主机拉取。没有二进制归档、校验和安装包、amd64/macOS/Windows 或 DockerHub 产物。

首次启用 Actions 后要核对仓库权限、ARM64 runner 可用性、GHCR 包可见性和实际下载。构建失败可在相同未发布 tag 上重跑；镜像已推送但 Release 尚未建立时只允许复用 revision 完全一致的镜像。已有 Release 时停止并人工核对，不覆盖产物。

## ID3 部署

当前业务使用 `/opt/tokenrouter/compose.yml` 的 TokenRouter 应用、独立 PostgreSQL 和 Redis；旧 Plus 服务不是更新目标。每次先核对实际容器、镜像、端口、持久挂载和依赖状态，不沿用历史容器 IP，不输出完整环境或凭据。通过已配置的 MaidKit ID3 连接执行维护，不把生产密钥写入仓库。

1. 读取 Release manifest，核对 tag SHA、OCI revision、ARM64、公开拉取和 digest；记录当前镜像、Compose、依赖容器 ID。
2. 在服务器专用备份目录创建完整 PostgreSQL dump，保存 Compose、私有环境和应用数据。核对 Redis 持久化，并保存业务需要的 RDB/AOF 或一致快照；外部对象存储另行盘点。备份权限限定运维用户，不能输出内容。
3. 将 PostgreSQL dump 恢复到隔离临时数据库，核对关键表数量、迁移和业务抽样，再删除恢复验证资源。备份文件存在不等于验证通过。
4. 拉取固定版本与 digest，更新应用镜像引用。只重建应用，不重建数据库/Redis，不重新初始化、重跑跨项目迁移或重置缓存。需要停机或不允许混跑的迁移按专题顺序排空旧实例。
5. 检查 health、域名、管理版本、迁移记录、实际镜像 SHA/digest、账号与用户数据。经授权执行一次小网关请求，核对成功响应、用量和计费，不发起真实支付或批量修改账号设置。
6. 健康或关键验收失败时先停止推进，按兼容性回退旧应用镜像；保留新 schema 和账务，不自动恢复旧数据库覆盖新写入。破坏性迁移必须使用其专门恢复流程。
7. 留存备份、manifest、发布与部署状态、旧回退镜像；清理本次构建/恢复验证容器、临时资源和过时代缓存，不清理无关项目。记录哪些步骤已完成以便超时后先查状态再恢复，不盲目重复部署。

<a id="image_updates"></a>
## 后台更新边界

更新检查与历史 Release 来源固定为个人仓库，缓存包含仓库身份，旧上游缓存不能继续使用。个人镜像编译为 `BuildType=image`，后台提供个人 Release 与镜像信息；服务端拒绝原地更新、备份二进制回退和指定版本二进制回退，即使绕过前端直接调用 API 也不能改写镜像内程序。

日常在线升级由 1Panel/Compose 在宿主机拉取并重建应用完成。网页按钮不是 Docker 部署系统，不挂载宿主机 Docker socket，不用容器内二进制替换冒充持久镜像升级。单二进制安装器虽然指向个人源，但本发行不提供安装归档，不能宣称支持该安装路径。

## 耗时与验收记录

分别记录配置准备、验证等待、前端编译、Go 编译、镜像包装推送、备份恢复和应用切换耗时。加速来自限定目标、缓存和并行，不来自跳过安全检查、迁移验证或备份。没有实测前不承诺几分钟完成整个发行。

每次交付明确区分本地、已提交、已推送、已发布、ID3 已生效；报告完整 SHA、Release URL、版本/digest、迁移结果、业务验收和备份目录。发布变更说明放 GitHub Release，不向 README 追加每版日志。

相关文档：[开发流程](development_workflow.md)、[部署与迁移](deployment_and_migrations.md)、[历史准入](../domains/openai_history_admission.md)、[运维目录](index.md)。
