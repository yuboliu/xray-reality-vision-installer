# 使用 VLESS + REALITY + Vision 部署少量用户代理

当前维护的安装、安全边界、客户端设置和多用户操作说明统一放在 [README](../README.md)，避免两份部署步骤出现差异。

本项目采用直接 RAW/TCP + REALITY + `xtls-rprx-vision`；默认目标为 `www.tesla.com:443`，部署时验证基础 TLS 条件和 X25519 系列密钥组。`www.tesla.com` 已验证 TLS 1.3 + X25519MLKEM768、证书匹配、无跳转，完整 REALITY 链路可用。REALITY 会镜像目标的 TLS ServerHello，`skyapi.onedrive.live.com` 会返回 HelloRetryRequest 并协商 P-384，不能作为目标；Xray 26.10.31 还会对包含 `microsoft`/`apple` 等字样的目标发出 GFW 警告，因此 `www.microsoft.com` 只建议作为备选。`storage.googleapis.com` 和 `www.bing.com` 是已验证的替代目标。域名选择不会自动赋予目标站点的流量特征；其适用性仍受目标行为、网络拓扑和客户端实现影响。

原文中“自动旋转指纹”“完全融入背景”“绝对隐蔽”等说法没有足够依据，已移除。安装器负责正确、安全地部署协议，不承诺突破特定封锁策略。

使用前阅读 [官方 REALITY 实践示例](https://github.com/XTLS/REALITY/blob/main/README.en.md) 与 [当前配置文档](https://xtls.github.io/config/transports/reality.html)。脚本默认检查系统防火墙，未启用时先保留 SSH 管理端口并放行 Xray TCP 监听端口，再启用并复查状态；SSH 端口由 `--ssh-port` 指定，默认 `22`，不自动读取 `SSH_CONNECTION`。已运行时仅添加 Xray 端口规则，不清理已有规则。可用 `--skip-firewall` 跳过。云安全组、特殊防火墙 zone、IPv6 防护及实际 VPS 性能评测由部署者管理。
