# Xray Reality Vision Installer

面向个人或少量用户、systemd Linux VPS 的 Python 3 部署脚本。使用直接的 `VLESS + RAW/TCP + REALITY + xtls-rprx-vision`，无面板、无额外反向代理、无第三方 Python 依赖。

当前审核基线：**Xray-core v26.10.31**（2026-11-03 核对的官方稳定版）。该版默认关闭 MPTCP 以降低官方公告所述内核漏洞攻击面；仍须自行安装发行版内核安全更新，必要时重启。

## 安装

要求：root/sudo、Python 3.10+（OpenSSL 支持 TLS 1.3）、systemd、`runuser`、`sysctl`；官方安装器还需要系统包管理器及 curl/unzip。已安装的 Xray 必须使用官方 `/usr/local/bin/xray` 和单配置 `xray.service`。

先取得并检查本项目脚本，再执行；不推荐把远端可变分支直接通过管道交给 root。也不要直接执行本仓库中的历史计划文档。

```bash
python3 reality_installer.py --dry-run
sudo python3 reality_installer.py --server-ip YOUR_PUBLIC_IP --skip-upgrade
```

`YOUR_PUBLIC_IP` 换成 VPS 公网地址；NAT 主机尤其需要显式指定。自动检测仅来自本机 `hostname -I`，可能是私网地址，不使用第三方查 IP 服务。

默认 SNI 为 `www.tesla.com`，目标为 `www.tesla.com:443`。部署前会从 VPS 检查目标证书匹配 SNI、TLS 1.3、H2 以及根路径不返回 HTTP 跳转；安装核心后还会用 `xray tls ping` 复查目标协商的密钥组，只接受 `X25519` 或 `X25519MLKEM768`，任一失败即停止，不自动降级验证或更换目标。`www.tesla.com` 已验证 TLS 1.3 + X25519MLKEM768、证书匹配、无跳转，且完整 REALITY 链路可用。

REALITY 会镜像目标的 TLS ServerHello，因此目标必须协商 X25519 系列密钥组。`skyapi.onedrive.live.com` 会返回 HelloRetryRequest 并协商 P-384，REALITY 无法处理，会导致客户端拿到真实证书后超时；不要把它作为目标。Xray 26.10.31 还会对包含 `microsoft`、`apple`、`icloud` 或 `.cn`/`.ru`/`.ir` 的 serverName 发出 GFW 警告，因此 `www.microsoft.com` 和 `www.apple.com` 虽然兼容，但不是理想默认值；`storage.googleapis.com` 和 `www.bing.com` 是已验证的备选。目标选择不保证隐蔽性或带宽，也不让代理流量经过目标站点的下载服务。官方建议优先选择与 VPS 网络拓扑接近、最好同 ASN 的合适目标；部署检查只确认基础协议条件，不替代目标 ASN、客户端兼容性和实际网络环境验证。

自定义目标与监听端口：

```bash
sudo python3 reality_installer.py \
  --server-ip YOUR_PUBLIC_IP \
  --server-name www.tesla.com \
  --target www.tesla.com:443 \
  --port 8443 --skip-upgrade
```

监听端口与目标端口独立；不传 `--target` 时目标始终是 `server-name:443`。`--dest` 保留为 `--target` 的别名。

## 安装与配置的安全边界

- 固定官方 Xray-install 提交和 SHA256，校验通过后执行；上游安装器再校验核心归档的 SHA256。摘要校验不等于独立签名认证，仍依赖官方发布渠道及其供应链。
- 缺失或较旧的 Xray 会安装到固定审核版本；不自动追踪预发布版本。比审核版本更新的现有核心会被拒绝，避免静默降级或使用未审核版本。
- 默认路径 `/usr/local/etc/xray/config.json`。自定义路径暂不支持，避免校验的文件与服务实际加载的文件不同。
- 服务必须使用非 root 用户及非 root 组，且 ExecStart 与官方单配置服务一致；配置目录 `root:<服务组> 0750`，配置文件 `root:<服务组> 0640`，备份 `root:root 0600`。
- 先写受限临时文件，再以服务用户执行 `xray run -test`，通过后原子替换。启动失败恢复旧配置并尝试重启；首次部署失败移除新配置并停止服务。
- 回滚只覆盖配置，不回滚已经完成的核心升级、系统包升级、BBR、防火墙规则/启用状态或服务开机启用状态。磁盘故障、断电和旧配置与新核心不兼容仍可能需要人工恢复；备份路径会打印。
- 私钥不从命令行接收，避免进程参数和 shell 历史泄露；每次部署生成新密钥。`--verbose` 不打印密钥生成输出；`--print-config` 只打印脱敏配置。
- 最后输出的客户端参数仍含敏感凭据，请保存在密码管理器中，不上传日志或公开分享。REALITY 的 `Password/PublicKey` 也应保密。
- 代理出站默认拒绝常见私网、环回、链路本地和云元数据地址，包含 IPv6 地址段，不下载 GeoIP 数据库。该规则是应用层基本保护，不是完整的主机出站隔离；恶意 DNS 重绑定等威胁需要独立的网络层控制。
- 保留官方基础 REALITY/Vision 行为；不默认叠加 VLESS Encryption、ML-DSA、Mux、TFO、MPTCP、固定回落限速或任意大缓冲参数。启用可选功能需要核对两端支持和对应目标条件。

默认检查并按需启用系统防火墙。已运行时只添加 `--port` 指定的 TCP 监听端口（默认 `443/tcp`）；首次启用时，还会先添加 SSH 管理端口的 TCP 放行规则。不会放行 UDP、目标网站端口，也不会清理已有规则或修改默认策略。

首次启用前，SSH 端口由 `--ssh-port` 指定，默认 `22`；不自动读取 `SSH_CONNECTION`。如果 SSH 使用非 22 端口，必须显式传入实际端口，例如：

```bash
sudo python3 reality_installer.py --server-ip YOUR_PUBLIC_IP --ssh-port 2222 --skip-upgrade
```

这里指定的是 VPS 本机 SSH 监听端口；如果通过端口映射连接，不要填写映射前的外部端口。

- Debian/Ubuntu 使用 UFW：读取状态，添加端口规则；未启用时先添加 SSH 和 Xray 端口规则，再执行 `ufw --force enable`，随后复查 active 状态和每个端口的 ALLOW 规则，规则缺失会停止部署。UFW 的 enable 同时设置开机启用。
- RHEL 系使用 firewalld：运行中分别添加运行时和永久规则，不执行全局 reload；未运行时先用 `firewall-offline-cmd` 保存 SSH/Xray 规则并校验配置，再执行 `systemctl enable --now firewalld`，最后确认 running。
- firewalld 规则添加到默认 zone；若公网接口绑定其他 zone，或主机已有复杂拒绝规则、多个防火墙管理器，请自行管理并使用 `--skip-firewall`。端口放行不等于已验证远程 SSH 可重连，首次启用建议保留云控制台访问途径。
- 工具缺失、状态无法识别或规则/启动操作失败会停止部署，不自动安装防火墙。失败时已添加规则或已启用状态可能保留，不自动删除或停用，以免影响现有规则和服务。
- Arch 等未适配的防火墙由部署者管理，请使用 `--skip-firewall`。`--skip-ufw` 保留为兼容别名。

云安全组、IPv6 防护和公网可达性仍由部署者验证。`--dry-run` 只描述状态检查与条件启用步骤，不读取或启动真实防火墙。

## 部署检查

`check_deployment.py` 是只读检查脚本，不修改防火墙、sysctl 或服务状态：

```bash
sudo python3 check_deployment.py
sudo python3 check_deployment.py --offline          # 跳过 GitHub 和目标网络检查
sudo python3 check_deployment.py --port 8443 --ssh-port 2222
```

检查内容：

- 已安装 Xray 版本、GitHub 最新稳定版、安装器审核基线
- UFW 状态、默认入站策略、Xray/SSH TCP 规则、IPv6 规则
- `net.core.default_qdisc` 与 `net.ipv4.tcp_congestion_control` 的实际值和持久化配置
- `xray.service` 运行/开机启用状态、端口监听、以服务用户执行配置校验
- REALITY 目标的 TLS 1.3 与 X25519/X25519MLKEM768 密钥组

失败项返回非零退出码；脚本只报告问题和建议命令，不自动修复。

## 升级与重复部署

不要将重复运行部署脚本当作无损升级：覆盖配置将生成新密钥并替换客户端列表，旧客户端失效。发现已有非空配置时，脚本先显示不含凭据的摘要，询问是否覆盖，并建立权限受限的唯一备份；`--yes` 明确跳过这次询问。首次安装不需要确认。

已有少量用户时，优先保留正式配置，按照经过审核的官方升级流程更新核心。维护本项目版本基线时，应重新核对稳定版公告、安装器固定提交和摘要，并验证配置；不要仅修改版本字符串来追新。

系统升级默认按发行版执行，可能更新内核或影响其他服务；已有业务的主机可用 `--skip-upgrade`，自行安排安全更新。

## 客户端与少量用户

按脚本输出填写：VLESS、RAW/TCP、`xtls-rprx-vision`、REALITY、对应 SNI、UUID、`Password/PublicKey`、ShortId、`chrome` 指纹及 SpiderX。客户端地址必须是 VPS 公网地址，而不是目标网站地址。VLESS encryption 使用 `none`，传输安全仍然由 REALITY 提供；不要关闭 REALITY 验证。

SpiderX 输出一个随机路径，不是服务端路由；不同客户端可以各自设置不同路径。不同用户建议分别生成 UUID，以便撤销单个用户，不要共享一份订阅：

```bash
/usr/local/bin/xray uuid
```

用 `sudoedit /usr/local/etc/xray/config.json` 在 `settings.clients` 中增加一个条目，保留原有条目和共享的 REALITY 服务端密钥：

```json
{"id": "NEW_UUID", "flow": "xtls-rprx-vision"}
```

手动编辑前先保存权限受限的备份；校验通过后再重启。默认官方服务用户为 `xray`，若已有服务使用其他用户，请使用其实际用户名：

```bash
sudo -u xray /usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json
sudo systemctl restart xray
sudo systemctl is-active xray
```

修改前后的 UUID 都是敏感信息。删除对应条目即可撤销该用户的新连接；如果共享的 REALITY 私钥或 Password 已泄露，应轮换相关凭据并更新全部客户端。

客户端 DNS、分流、IPv6 和断线后是否直连由客户端管理，请自行验证。不建议将客户端本地 SOCKS/HTTP 代理暴露到局域网或公网。

## 参数与测试

- `--skip-upgrade`：不升级系统包。
- `--skip-firewall`：跳过系统防火墙状态检查、端口规则和启用操作。
- `--ssh-port`：首次启用防火墙前保留的 SSH TCP 端口，默认 `22`；非 22 端口必须显式指定。
- `--skip-bbr`：不修改 BBR。开启时验证实际拥塞算法为 BBR；不调整现有网卡队列或保证降低延时。
- `--skip-install-xray`：禁止安装或升级核心，现有版本必须符合审核基线。
- `--uuid`：指定合法 UUID；默认安全随机生成。
- `--short-id`：8–16 位、小写十六进制、偶数长度；默认随机 16 位。
- `--distro-id` / `--distro-like`：覆盖发行版识别。
- `--dry-run`：不下载、不连接目标、不写配置、不运行系统修改命令；仅模拟流程。
- `--verbose` / `--print-config`：执行详情 / 脱敏配置预览。

支持 Debian/Ubuntu、RHEL 系及 Arch 的系统升级和 BBR 命令。保持单进程和低日志量，适用于小型 VPS；线路、吞吐、延时和实际封锁环境的测试由部署者完成。

```bash
python3 -m unittest discover -s tests -v
python3 reality_installer.py --dry-run --print-config
```

官方参考：[稳定版公告](https://github.com/XTLS/Xray-core/releases/tag/v26.10.31)、[REALITY 配置](https://xtls.github.io/config/transports/reality.html)、[官方实践示例](https://github.com/XTLS/REALITY/blob/main/README.en.md)、[固定版本安装器](https://github.com/XTLS/Xray-install/blob/04e6f3bd9534811ed901a48c47b2c042dd64eb3a/install-release.sh)。
