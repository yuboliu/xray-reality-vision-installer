#!/usr/bin/env bash
# ============================================================
# 腾讯云（轻量应用服务器 / CVM）主机内监控与运维组件清理 —— 硬化版
#   参考基线：cloud.tencent.com/document/product/248/53584（官方卸载流程）
#   目标：把「主机内可采集面」清理到可验证的干净状态，而不是删完就走
#
# 用法：
#   bash tc-privacy-cleanup.sh --dry-run   # 只探测 + 输出报告，不动任何东西（先跑这个）
#   bash tc-privacy-cleanup.sh             # 标准清理
#   bash tc-privacy-cleanup.sh --hard      # 标准清理 + 关 cloud-init / 换公共 DNS+NTP / 换镜像源
#
# 前置条件（务必先满足）：
#   1. 已确认 SSH 公钥或密码登录可用（卸载 TAT 后控制台「一键登录/命令执行」会失效）
#   2. 控制台保留一个 VNC/串口 窗口作为后路
#   3. 有快照或已备份要保留的数据（本脚本不做业务数据备份）
# ============================================================

set -u
DRY=0
HARD=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    --hard)    HARD=1 ;;
  esac
done

LOG=/root/tc-cleanup-$(date +%Y%m%d-%H%M%S).log
exec > >(tee -a "$LOG") 2>&1

c_g(){ printf '\033[32m%s\033[0m\n' "$*"; }
c_y(){ printf '\033[33m%s\033[0m\n' "$*"; }
c_r(){ printf '\033[31m%s\033[0m\n' "$*"; }
step(){ echo; c_g "==== $* ===="; }

# 统一的执行出口：dry-run 时只打印
do_it(){
  if [ "$DRY" -eq 1 ]; then echo "  [dry] $*"; else eval "$*"; fi
}
# 非交互执行官方卸载脚本，最多等 20s，防止它卡在交互提示上
run_uninstaller(){
  local s="$1"
  [ -x "$s" ] || { c_y "  跳过（不存在）: $s"; return 0; }
  if [ "$DRY" -eq 1 ]; then echo "  [dry] yes | timeout 20 $s"; return 0; fi
  c_y "  执行: $s"
  yes 2>/dev/null | timeout 20 bash "$s" >/dev/null 2>&1
  echo "  exit=$?"
}

step "0. 环境检查"
[ "$(id -u)" -eq 0 ] || { c_r "必须以 root 运行（用 sudo bash $0）"; exit 1; }
echo "  主机: $(hostname)  机型: $(systemd-detect-virt 2>/dev/null)"
echo "  OS  : $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")"
echo "  日志: $LOG"
[ "$DRY" -eq 1 ] && c_y "  DRY-RUN 模式：只探测与打印，不修改任何文件"

step "1. 探测现有组件"
for p in /usr/local/qcloud /usr/local/sa /usr/local/agenttools /var/lib/qcloud /etc/qcloud; do
  [ -e "$p" ] && echo "  目录存在: $p"
done
echo "  --- 进程 ---"
ps -eo pid,comm,args --no-headers 2>/dev/null \
  | grep -Ei 'sgagent|barad|YDService|YDLive|YDEdr|secu-tcs|sap100|tat_agent|stargate|cosfs|agentPlugIn' \
  | grep -v grep || echo "  （无匹配进程）"
echo "  --- systemd 单元 ---"
for s in tat_agent tat_install barad_agent sgagent secu-tcs-agent stargate; do
  systemctl list-unit-files "${s}.service" 2>/dev/null | grep -q "^${s}" && echo "  单元: ${s}.service"
done
echo "  --- init.d 脚本 ---"
ls -1 /etc/init.d/ 2>/dev/null | grep -Ei 'barad|sgagent|secu|stargate|tat|qcloud' || echo "  （无）"
echo "  --- 自愈痕迹 ---"
ls -1 /etc/cron.d/ 2>/dev/null | grep -Ei 'sgagent|yunjing|barad|qcloud' || true
crontab -l 2>/dev/null | grep -Ei 'qcloud|stargate|yunjing|barad|tat' || echo "  （crontab 无 qcloud 项）"
grep -Ei 'qcloud|stargate|barad|yunjing|tat_agent' /etc/rc.local 2>/dev/null || true
[ -f /etc/ld.so.preload ] && { c_r "  !!! /etc/ld.so.preload 存在（全局 SO 注入）:"; cat /etc/ld.so.preload; }
ls -l /lib64/libsgmon.so* /lib64/libonion*.so* /usr/lib64/libsgmon.so* 2>/dev/null || true
echo "  --- 出向长连接 ---"
ss -tnp 2>/dev/null | grep ESTAB | grep -Ei 'qcloud|tencent|yd\.' || echo "  （无 qcloud/tencent 连接）"

if [ "$DRY" -eq 1 ]; then
  echo; c_y "探测完成。确认无误后去掉 --dry-run 重跑。"
  exit 0
fi

step "2. 备份将要被改动的配置"
BK=/root/tc-cleanup-backup-$(date +%Y%m%d-%H%M%S).tar.gz
tar czf "$BK" \
  /etc/systemd/system/tat_agent.service /etc/systemd/system/tat_install.service \
  /etc/ld.so.preload /etc/rc.local /etc/cron.d /var/spool/cron 2>/dev/null
c_g "  备份文件: $BK"

step "3. 调官方卸载脚本（sgagent / barad / YunJing）"
run_uninstaller /usr/local/qcloud/stargate/admin/uninstall.sh
run_uninstaller /usr/local/qcloud/monitor/barad/admin/uninstall.sh
run_uninstaller /usr/local/qcloud/YunJing/uninst.sh
# 部分镜像装机目录在 /var/lib
run_uninstaller /var/lib/qcloud/YunJing/uninst.sh

step "4. 清理 ld.so.preload 注入（多数一键脚本漏掉的一步）"
if [ -f /etc/ld.so.preload ]; then
  do_it "sed -i -E '/libsgmon|libonion/d' /etc/ld.so.preload"
  do_it "[ -s /etc/ld.so.preload ] || rm -f /etc/ld.so.preload"
  do_it "rm -f /lib64/libsgmon.so* /usr/lib64/libsgmon.so* /lib64/libonion*.so* /usr/lib64/libonion*.so* /lib/x86_64-linux-gnu/libsgmon.so* /lib/x86_64-linux-gnu/libonion*.so*"
  do_it "ldconfig"
else
  echo "  无需处理"
fi

step "5. 停服务 + 断自启（先停再删，避免开机 failed 与自愈拉起）"
for s in tat_agent tat_install stargate sgagent barad_agent secu-tcs-agent; do
  do_it "systemctl stop ${s}.service 2>/dev/null; systemctl disable ${s}.service 2>/dev/null"
done
for f in /etc/init.d/barad_agent /etc/init.d/sgagent /etc/init.d/secu-tcs-agent /etc/init.d/stargate /etc/init.d/tat_agent; do
  [ -e "$f" ] && do_it "chkconfig --del $(basename "$f") 2>/dev/null; update-rc.d -f $(basename "$f") remove 2>/dev/null; rm -f $f"
done
do_it "rm -f /etc/systemd/system/tat_agent.service /etc/systemd/system/tat_install.service"
do_it "rm -f /etc/systemd/system/multi-user.target.wants/tat_agent.service /etc/systemd/system/multi-user.target.wants/tat_install.service"
do_it "systemctl daemon-reload; systemctl reset-failed 2>/dev/null"

step "6. 清理定时任务与开机自启残留"
do_it "rm -f /etc/cron.d/sgagenttask /etc/cron.d/yunjing /etc/cron.d/barad*"
do_it "crontab -l 2>/dev/null | grep -v -E 'qcloud|stargate|yunjing|barad|YDCrontab|tat_agent' | crontab - 2>/dev/null || true"
do_it "sed -i -E '/qcloud|stargate|barad|yunjing|tat_agent/I d' /etc/rc.local 2>/dev/null || true"

step "7. 收尾杀进程（含脚本常漏的 YDService/YDLive/YDEdr）"
for p in sgagent sgagent64 barad_agent YDService YDLive YDEdr secu-tcs-agent sap100 agentPlugInD stargate; do
  do_it "pkill -9 -x $p 2>/dev/null || true"
done
do_it "ps -eo pid,args --no-headers | grep -E 'YunJing|/usr/local/qcloud' | grep -v grep | awk '{print \$1}' | xargs -r kill -9 2>/dev/null || true"

step "8. 删除目录、日志与 COS 挂载"
mount 2>/dev/null | grep -q cosfs && do_it "umount -l /lhcos-data 2>/dev/null || true"
do_it "rm -rf /usr/local/qcloud /usr/local/sa /usr/local/agenttools /var/lib/qcloud /etc/qcloud"
do_it "rm -rf /var/log/qcloud* /var/log/barad* /var/log/tat* /var/log/yunjing* 2>/dev/null || true"

if [ "$HARD" -eq 1 ]; then
  step "9. [--hard] 关闭 cloud-init（控制台重置密码/注入公钥通道）"
  do_it "touch /etc/cloud/cloud-init.disabled"
  for u in cloud-init cloud-init-local cloud-config cloud-final; do
    do_it "systemctl disable --now $u.service 2>/dev/null || true"
  done

  step "10. [--hard] DNS / NTP 去腾讯化"
  do_it "cp -a /etc/resolv.conf /etc/resolv.conf.tcbak 2>/dev/null || true"
  do_it "printf 'nameserver 223.5.5.5\nnameserver 119.29.29.29\noptions timeout:2 attempts:2\n' > /etc/resolv.conf"
  do_it "chattr +i /etc/resolv.conf 2>/dev/null || true"
  if [ -f /etc/chrony.conf ]; then
    do_it "sed -i -E 's/^(\s*server\s+.*tencent.*)/#\1/I' /etc/chrony.conf"
    do_it "grep -q 'ntp.aliyun.com' /etc/chrony.conf || echo 'server ntp.aliyun.com iburst' >> /etc/chrony.conf"
    do_it "systemctl restart chronyd 2>/dev/null || true"
  fi
  if [ -f /etc/ntp.conf ]; then
    do_it "sed -i -E '/tencent|tencentyun/I s/^/#/' /etc/ntp.conf"
    do_it "systemctl restart ntpd 2>/dev/null || true"
  fi
  step "11. [--hard] 换掉腾讯内网镜像源"
  c_y "  请手动确认并把 yum/apt 源改为公共源；脚本不自动改，避免签名不匹配导致装不上包"
  grep -rl 'tencentyun\|mirrors.cloud.tencent' /etc/yum.repos.d/ /etc/apt/ 2>/dev/null || echo "  未发现腾讯内网源"
fi

step "12. 结果校验"
echo "  --- 残留进程 ---"
ps -eo pid,args --no-headers | grep -Ei 'sgagent|barad|YDService|YDLive|YDEdr|secu-tcs|tat_agent|stargate|agentPlugIn' | grep -v grep || c_g "  干净：无残留进程"
echo "  --- 残留目录 ---"
ls -d /usr/local/qcloud /usr/local/sa /usr/local/agenttools 2>/dev/null || c_g "  干净：目录已删除"
echo "  --- ld.so.preload ---"
[ -f /etc/ld.so.preload ] && c_r "  仍存在，请人工检查" || c_g "  干净：无 preload 注入"
echo "  --- 出向连接 ---"
ss -tnp 2>/dev/null | grep ESTAB | grep -Ei 'tencent|qcloud' || c_g "  干净：无腾讯侧长连接"
echo "  --- 失效的 systemd 单元 ---"
systemctl --failed --no-legend | grep -Ei 'tat|barad|sgagent|stargate' || c_g "  干净：无失败单元"

step "完成"
c_y "  下一步：reboot 后重跑一次「阶段 1 探测」确认无复活。"
c_y "  注意：卸载后控制台「监控图表 / 主机安全 / 一键登录 OrcaTerm / 命令执行」将不可用，VNC 与 SSH 不受影响。"
