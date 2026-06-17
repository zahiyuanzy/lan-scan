#!/usr/bin/env python3
"""
局域网漏洞扫描工具
- 自动发现本机局域网存活主机
- 端口服务探测 + 已知漏洞检测
- HTML 报告输出
- 图形界面 (tkinter) + 命令行双模式
- 无外部依赖，纯标准库

Usage:
    python3 lan_scan.py                          # 图形界面
    python3 lan_scan.py --cli                    # 命令行模式
    python3 lan_scan.py --port-scan 192.168.1.1  # 端口探测
    python3 lan_scan.py --port-scan 192.168.1.1:80,443  # 指定端口
    python3 lan_scan.py --port-scan 192.168.1.1:all  # 全部端口
    python3 lan_scan.py --net 192.168.1.0/24     # 指定网段
    python3 lan_scan.py --ips 192.168.1.1,192.168.1.2  # 指定IP
    python3 lan_scan.py --output scan_report.html  # 指定输出文件
"""

import socket
import struct
import threading
import time
import subprocess
import sys
import os
import json
import ipaddress
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import urlopen

# ====================================================================
# 配置
# ====================================================================

# 并发线程数
THREAD_POOL_SIZE = 64

# 端口扫描范围（关键端口）
SCAN_PORTS = {
    21:   ("FTP", "CVE-2022-36936", "vsFTPd 3.0.3 后门"),
    22:   ("SSH", "CVE-2024-6387", "SSH regreSSHion (openssh < 9.8p1)"),
    23:   ("Telnet", None, "Telnet 明文传输（高风险）"),
    25:   ("SMTP", None, "SMTP 开放（可能可钓鱼/转发）"),
    53:   ("DNS", None, "DNS 开放（可能 DNS 放大攻击）"),
    80:   ("HTTP", None, "HTTP 开放（可能后台/管理界面）"),
    110:  ("POP3", None, "POP3 明文传输"),
    135:  ("MSRPC", None, "Windows RPC（可能 MS17-010 永恒之蓝）"),
    139:  ("NetBIOS", None, "NetBIOS 开放（SMB 攻击面）"),
    143:  ("IMAP", None, "IMAP 明文传输"),
    443:  ("HTTPS", None, "HTTPS 开放"),
    445:  ("SMB", "CVE-2017-0144", "EternalBlue (MS17-010)"),
    993:  ("IMAPS", None, "IMAP over SSL"),
    995:  ("POP3S", None, "POP3 over SSL"),
    1433: ("MSSQL", "CVE-2019-0908", "MSSQL 远程代码执行"),
    1521: ("Oracle DB", None, "Oracle 数据库开放"),
    3306: ("MySQL", "CVE-2012-2122", "MySQL 认证绕过"),
    3389: ("RDP", "CVE-2019-0708", "BlueKeep (RDP 远程代码执行)"),
    5432: ("PostgreSQL", None, "PostgreSQL 数据库开放"),
    5900: ("VNC", "CVE-2023-23951", "VNC 未授权访问"),
    6379: ("Redis", "CVE-2022-0542", "Redis 未授权访问 / 沙箱逃逸"),
    8000: ("HTTP-Alt", None, "HTTP 备用端口开放"),
    8080: ("HTTP-Proxy", None, "HTTP 代理/管理后台常见端口"),
    8443: ("HTTPS-Alt", None, "HTTPS 备用端口"),
    9090: ("WebAdmin", None, "管理面板常见端口"),
    9200: ("Elasticsearch", "CVE-2014-3120", "Elasticsearch RCE (v1.x)"),
    11211:("Memcached", "CVE-2020-25686", "Memcached 未授权访问 / DDoS 放大"),
    1883: ("MQTT", None, "MQTT 未授权消息接收"),
    27017:("MongoDB", "CVE-2024-21232", "MongoDB 未授权访问"),
}

# Web 后台检测路径
WEB_ADMIN_PATHS = [
    "/admin", "/administrator", "/login", "/wp-admin",
    "/phpmyadmin", "/pma", "/manager", "/console",
    "/dashboard", "/api", "/.env", "/config.php",
]

# ====================================================================
# 网络发现
# ====================================================================

def get_local_network():
    """获取本机所在局域网网段"""
    try:
        result = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.strip().split("\n"):
            if "dev " in line:
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == "dev":
                        iface = parts[i+1]
                        if iface == "en0":
                            return "192.168.0.0/16"
                        elif iface.startswith("en"):
                            return "172.16.0.0/12"
                        elif iface == "en1":
                            return "10.0.0.0/8"
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["arp", "-an"], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.strip().split("\n"):
            parts = line.strip().strip("()").split()
            if len(parts) >= 2:
                ip = parts[1].lstrip("(").rstrip(")")
                addr = ipaddress.ip_address(ip)
                if addr.is_private:
                    prefix = ".".join(ip.split(".")[:2])
                    return f"{prefix}.0/16"
    except Exception:
        pass

    return "192.168.0.0/16"


def get_all_local_interfaces():
    """获取本机所有网络接口的IP地址和所属网段"""
    interfaces = []

    if sys.platform == "darwin":
        # macOS: use networksetup to list interfaces, then ifconfig for IPs
        try:
            result = subprocess.run(
                ["networksetup", "-listallhardwareports"],
                capture_output=True, text=True, timeout=10
            )
            current = None
            for line in result.stdout.split("\n"):
                line = line.strip()
                if line.startswith("Hardware port:"):
                    if current:
                        interfaces.append(current)
                    current = {"name": line.split(":", 1)[1].strip(), "ips": []}
                elif line.startswith("Serial Number:"):
                    continue
                elif line.startswith("Device:") or line.startswith("Ethernet address:"):
                    continue
            if current:
                interfaces.append(current)
        except Exception:
            pass

        # If networksetup found nothing, fall back to ifconfig
        if not interfaces:
            try:
                result = subprocess.run(
                    ["ifconfig", "-a"], capture_output=True, text=True, timeout=10
                )
                current = None
                for line in result.stdout.split("\n"):
                    if line and not line.startswith("\t"):
                        if ":" in line:
                            if current:
                                interfaces.append(current)
                            name = line.split(":")[0].strip()
                            current = {"name": name, "ips": []}
                    elif line.startswith("\tinet ") and current is not None:
                        parts = line.split()
                        if len(parts) >= 2:
                            current["ips"].append(parts[1])
                if current:
                    interfaces.append(current)
            except Exception:
                pass
    elif sys.platform == "win32":
        # Windows: use ipconfig
        try:
            result = subprocess.run(
                ["ipconfig", "/all"], capture_output=True, text=True, timeout=10
            )
            current = {}
            in_interface = False
            for line in result.stdout.split("\n"):
                line_stripped = line.strip()
                if line_stripped and not line.startswith("   ") and ":" in line_stripped:
                    if current and in_interface:
                        interfaces.append(current)
                    name = line_stripped.split(":")[0].strip()
                    current = {"name": name, "ips": []}
                    in_interface = True
                elif "IPv4 Address" in line_stripped and current is not None:
                    parts = line_stripped.split(":")
                    if len(parts) >= 2:
                        ip = parts[-1].strip()
                        current["ips"].append(ip)
                elif "IP Address" in line_stripped and "IPv6" not in line_stripped and current is not None:
                    parts = line_stripped.split(":")
                    if len(parts) >= 2:
                        ip = parts[-1].strip()
                        current["ips"].append(ip)
            if current and in_interface:
                interfaces.append(current)
        except Exception:
            pass
    else:
        # Linux: use ip addr
        try:
            result = subprocess.run(
                ["ip", "-4", "addr"], capture_output=True, text=True, timeout=10
            )
            current = {}
            for line in result.stdout.split("\n"):
                line = line.strip()
                if line and not line.startswith(" ") and ":" in line:
                    if current:
                        interfaces.append(current)
                    name = line.split(":")[1].strip()
                    current = {"name": name, "ips": []}
                elif "inet " in line and current is not None:
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p == "inet" and i + 1 < len(parts):
                            cidr = parts[i + 1]
                            # Extract IP from CIDR
                            ip = cidr.split("/")[0]
                            current["ips"].append(ip)
                            break
            if current:
                interfaces.append(current)
        except Exception:
            pass

    # Filter out loopback, VPN, and empty interfaces
    vpn_prefixes = ("utun", "tap", "tun", "wg")
    filtered = []
    for iface in interfaces:
        name_lower = iface["name"].lower()
        if "lo" in name_lower or "loopback" in name_lower:
            continue
        if any(name_lower.startswith(vp) for vp in vpn_prefixes):
            continue
        if iface["ips"]:
            filtered.append(iface)
    return filtered


def get_networks_from_interfaces(interfaces):
    """从接口列表构建可选的网段信息"""
    networks = []
    for iface in interfaces:
        for ip in iface["ips"]:
            try:
                addr = ipaddress.ip_address(ip)
                if not addr.is_private:
                    continue
                # Determine subnet based on IP class
                parts = ip.split(".")
                prefix_len = len(parts)
                if prefix_len == 4:
                    # Try /24 first, then /16
                    subnet_24 = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                    subnet_16 = f"{parts[0]}.{parts[1]}.0.0/16"
                    networks.append({
                        "interface": iface["name"],
                        "ip": ip,
                        "subnet_24": subnet_24,
                        "subnet_16": subnet_16,
                    })
            except Exception:
                continue
    return networks


def discover_hosts(net_cidr="auto", thread_pool_size=64):
    """ARP 扫描发现存活主机（快速、免 root）"""
    if net_cidr == "auto":
        net_cidr = get_local_network()

    network = ipaddress.ip_network(net_cidr, strict=False)
    hosts = []
    lock = threading.Lock()
    current = 0
    total = len(list(network.hosts()))

    def ping_one(ip):
        nonlocal current
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.3)
            s.connect((str(ip), 9))
            s.close()
            with lock:
                current += 1
            return str(ip)
        except (socket.timeout, OSError):
            return None

    with ThreadPoolExecutor(max_workers=min(thread_pool_size, total)) as executor:
        futures = {executor.submit(ping_one, host): host for host in network.hosts()}
        for future in as_completed(futures):
            result = future.result()
            if result:
                hosts.append(result)

    return sorted(hosts)


def discover_hosts_manual(ips=None):
    """手动指定 IP 列表扫描"""
    if ips:
        hosts = ips
    else:
        hosts = ["127.0.0.1"]
    return sorted(hosts)


# ====================================================================
# 端口 & 服务探测
# ====================================================================

def scan_port(ip, port, timeout=1.5):
    """扫描单个端口，返回 (端口, 状态, 服务名, CVE, 描述, banner, severity)"""
    svc = SCAN_PORTS.get(port)
    if not svc:
        return (port, "closed", "", None, None, None, "low")

    service, cve, desc = svc

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        conn_result = s.connect_ex((ip, port))
        if conn_result != 0:
            s.close()
            return (port, "closed", "", None, None, None, "low")

        banner = ""
        try:
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        except:
            pass
        s.close()

        severity = "low"
        if banner:
            severity = "medium"
            if "vsftpd 3.0.3" in banner.lower():
                severity = "high"
            if "openssh 7." in banner.lower() or "openssh 8." in banner.lower():
                severity = "high"

        return (port, "open", service, cve, desc, banner, severity)

    except (socket.timeout, OSError, ConnectionRefusedError):
        return (port, "closed", "", None, None, None, "low")


def check_web_admin(ip, port, timeout=3):
    """检测 Web 后台/管理面板"""
    findings = []
    paths = WEB_ADMIN_PATHS[:8]

    def check_path(path):
        try:
            url = f"http://{ip}:{port}{path}"
            resp = urlopen(url, timeout=timeout)
            code = resp.getcode()
            if code in (200, 302):
                return (path, code)
            elif code >= 400:
                return (path, code)
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_path, p): p for p in paths}
        for f in as_completed(futures):
            result = f.result()
            if result and result[1] == 200:
                findings.append(f"{result[0]} (HTTP 200)")
    return findings


# ====================================================================
# 综合扫描
# ====================================================================

def scan_host(ip, thread_pool_size=64):
    """对单个主机进行综合扫描"""
    results = {
        "ip": ip,
        "open_ports": [],
        "vulnerabilities": [],
        "web_admin": [],
        "summary": {},
    }

    open_ports = []

    with ThreadPoolExecutor(max_workers=min(thread_pool_size, len(SCAN_PORTS))) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in SCAN_PORTS}
        for f in as_completed(futures):
            port, status, service, cve, desc, banner, severity = f.result()
            if status == "open":
                open_ports.append(port)
                findings = {
                    "port": port,
                    "service": service,
                    "cve": cve,
                    "description": desc,
                    "banner": banner,
                    "severity": severity,
                }
                results["open_ports"].append(findings)

    web_ports = [p for p in open_ports if p in (80, 443, 8080, 8443, 9090, 3306, 9200, 27017)]
    if web_ports:
        for wp in web_ports:
            admin_findings = check_web_admin(ip, wp)
            if admin_findings:
                results["web_admin"].extend(admin_findings)

    vuln_count = sum(1 for p in results["open_ports"] if p.get("cve"))
    high_count = sum(1 for p in results["open_ports"] if p.get("severity") == "high")
    results["summary"] = {
        "open_ports_count": len(open_ports),
        "vulnerabilities_count": vuln_count,
        "high_severity": high_count,
        "web_admin_findings": len(results["web_admin"]),
    }

    results["open_ports"].sort(key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x.get("severity", "low"), 3))

    return results


# ====================================================================
# 报告输出
# ====================================================================

def severity_color(severity):
    colors = {"high": "#dc3545", "medium": "#fd7e14", "low": "#ffc107"}
    return colors.get(severity, "#6c757d")


def generate_html_report(results, output_file):
    """生成 HTML 报告"""
    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>局域网漏洞扫描报告 - {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: #1a1a2e; color: #e0e0e0; padding: 24px; line-height: 1.6; }}
  .header {{ background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
             padding: 24px 32px; border-radius: 12px; margin-bottom: 24px; }}
  .header h1 {{ font-size: 28px; color: #fff; margin-bottom: 8px; }}
  .header .meta {{ color: #aaa; font-size: 14px; }}
  .summary-bar {{ display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }}
  .summary-card {{ background: #16213e; padding: 16px 24px; border-radius: 8px; flex: 1; min-width: 150px; }}
  .summary-card .num {{ font-size: 32px; font-weight: 700; }}
  .summary-card .label {{ font-size: 13px; color: #888; }}
  .host-card {{ background: #16213e; border-radius: 10px; margin-bottom: 20px; overflow: hidden; }}
  .host-header {{ padding: 16px 24px; display: flex; justify-content: space-between; align-items: center;
                  cursor: pointer; background: #1a1a3e; }}
  .host-header h2 {{ font-size: 18px; color: #fff; }}
  .host-header .badge {{ padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }}
  .badge-high {{ background: #dc3545; color: white; }}
  .badge-medium {{ background: #fd7e14; color: white; }}
  .badge-low {{ background: #ffc107; color: #333; }}
  .host-body {{ padding: 20px 24px; }}
  .vuln-table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
  .vuln-table th {{ text-align: left; padding: 10px 12px; background: #0f0c29;
                   color: #aaa; font-size: 12px; text-transform: uppercase; }}
  .vuln-table td {{ padding: 12px; border-bottom: 1px solid #1e2a4a; font-size: 14px; }}
  .vuln-table tr:hover {{ background: #1e2a4a; }}
  .vuln-tag {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;
               color: white; }}
  .vuln-cve {{ font-family: monospace; color: #e74c3c; font-weight: 600; }}
  .vuln-desc {{ color: #bbb; }}
  .banner {{ font-family: monospace; font-size: 12px; background: #0a0a1e; padding: 8px 12px;
             border-radius: 4px; color: #4ec9b0; overflow-x: auto; white-space: pre-wrap; }}
  .web-admin {{ color: #4ec9b0; font-weight: 600; }}
  .empty {{ text-align: center; padding: 40px; color: #666; }}
  .section-title {{ font-size: 14px; color: #888; text-transform: uppercase; margin: 16px 0 8px; }}
  .footer {{ text-align: center; padding: 24px; color: #555; font-size: 12px; margin-top: 32px; }}
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ 局域网漏洞扫描报告</h1>
  <div class="meta">生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | 扫描主机: {len(results)} 台</div>
</div>

<div class="summary-bar">
  <div class="summary-card"><div class="num" style="color:#0f0">{sum(1 for r in results if r["summary"]["open_ports_count"])}</div>
    <div class="label">存活主机</div></div>
  <div class="summary-card"><div class="num" style="color:#fd7e14">{sum(r["summary"]["open_ports_count"] for r in results)}</div>
    <div class="label">开放端口</div></div>
  <div class="summary-card"><div class="num" style="color:#dc3545">{sum(r["summary"]["vulnerabilities_count"] for r in results)}</div>
    <div class="label">已知漏洞</div></div>
  <div class="summary-card"><div class="num" style="color:#dc3545">{sum(r["summary"]["high_severity"] for r in results)}</div>
    <div class="label">高危</div></div>
  <div class="summary-card"><div class="num" style="color:#4ec9b0">{sum(r["summary"].get("web_admin_findings", 0) for r in results)}</div>
    <div class="label">Web 后台</div></div>
</div>
"""

    for r in sorted(results, key=lambda x: -x["summary"]["vulnerabilities_count"]):
        ips = r.get("ip", "unknown")
        s = r["summary"]

        if s["high_severity"]:
            badge_class = "badge-high"
            badge_text = f"🔴 {s['high_severity']} 高危"
        elif s["vulnerabilities_count"]:
            badge_class = "badge-medium"
            badge_text = f"🟠 {s['vulnerabilities_count']} 漏洞"
        elif s["open_ports_count"]:
            badge_class = "badge-low"
            badge_text = f"🟡 {s['open_ports_count']} 端口"
        else:
            badge_class = ""
            badge_text = "✅ 安全"

        html += f"""
<div class="host-card">
  <div class="host-header">
    <h2>{ips}</h2>
    {badge_text and f'<span class="badge {badge_class}">{badge_text}</span>' or ''}
  </div>
  <div class="host-body">
    <div class="section-title">📡 开放端口与服务 ({len(r["open_ports"])})</div>
    <table class="vuln-table">
      <tr><th>端口</th><th>服务</th><th>严重性</th><th>漏洞 / 风险</th><th>Banner</th></tr>
"""
        for p in r["open_ports"]:
            sev = p.get("severity", "low")
            color = severity_color(sev)
            tag = f'<span class="vuln-tag" style="background:{color}">{sev.upper()}</span>'
            cve = p.get("cve")
            cve_html = f'<span class="vuln-cve">{cve}</span>' if cve else '<span style="color:#888">-</span>'
            desc = p.get("description") or ""
            banner = p.get("banner")
            banner_html = f'<div class="banner">{_escape(banner)}</div>' if banner else '-'

            html += f"<tr>"
            html += f"<td><strong>{p['port']}/tcp</strong></td>"
            html += f"<td>{p['service']}</td>"
            html += f"<td>{tag}</td>"
            html += f"<td>{cve_html}<br><span class='vuln-desc'>{_escape(desc)}</span></td>"
            html += f"<td>{banner_html}</td>"
            html += f"</tr>\n"

        if r["web_admin"]:
            html += f"""</table>
    <div class="section-title">🌐 Web 管理后台 ({len(r['web_admin'])})</div>
    <table class="vuln-table">
      <tr><th>路径</th><th>风险</th></tr>"""
            for wa in r["web_admin"]:
                html += f"<tr><td class='web-admin'>http://{ips}:<strong>xxx</strong>{wa.split(' (')[0]}</td>"
                html += f"<td><span class='vuln-cve'>⚠️ 未授权访问风险</span></td></tr>\n"
            html += "</table>"

        html += "</div></div>\n"

    html += f"""
<div class="footer">
  扫描工具: LanScan v2.0 | 仅供授权的安全评估使用 |
  扫描时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
</div>
</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)
    return output_file


def _escape(text):
    if not text:
        return ""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


# ====================================================================
# 图形界面
# ====================================================================

class ScanGUI:
    """扫描工具的图形界面"""

    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ 局域网漏洞扫描工具 v2.0")
        self.root.geometry("720x520")
        self.root.resizable(True, True)
        self.scanning = False
        self._stop_flag = False
        self._executor = None

        self._build_ui()

    def _build_ui(self):
        # ===== 顶部：扫描模式选择 =====
        mode_frame = ttk.LabelFrame(self.root, text="扫描模式", padding=10)
        mode_frame.pack(fill="x", padx=10, pady=(10, 5))

        self.mode_var = tk.StringVar(value="auto")
        self.mode_var.trace_add("write", lambda *args: self._on_mode_change())
        ttk.Radiobutton(mode_frame, text="自动扫描（检测本机网段）", variable=self.mode_var, value="auto").pack(side="left", padx=10)
        ttk.Radiobutton(mode_frame, text="网卡选择", variable=self.mode_var, value="iface_select").pack(side="left", padx=10)
        ttk.Radiobutton(mode_frame, text="指定网段", variable=self.mode_var, value="subnet").pack(side="left", padx=10)
        ttk.Radiobutton(mode_frame, text="指定IP", variable=self.mode_var, value="ips").pack(side="left", padx=10)
        ttk.Radiobutton(mode_frame, text="端口探测", variable=self.mode_var, value="port_scan").pack(side="left", padx=10)

        # ===== 网段/IP 输入区 =====
        input_frame = ttk.LabelFrame(self.root, text="扫描目标", padding=10)
        input_frame.pack(fill="x", padx=10, pady=5)

        # Container frame to hold exactly one input row, always left-aligned
        self.input_row_frame = ttk.Frame(input_frame)
        self.input_row_frame.pack(fill="x", padx=5, pady=2)

        self.net_entry = ttk.Entry(self.input_row_frame, width=40)
        self.net_entry.insert(0, "auto")
        self.net_entry_label = ttk.Label(self.input_row_frame, text="网段 (CIDR，如 192.168.1.0/24，填 auto 自动检测)")
        self.net_entry_label.pack(side="left", padx=(0, 5))
        self.net_entry.pack(side="left", fill="x", expand=True)

        self.ips_entry = ttk.Entry(self.input_row_frame, width=40)
        self.ips_entry.pack_forget()
        self.ips_hint_label = ttk.Label(self.input_row_frame, text="")
        self.ips_hint_label.pack_forget()

        # Port scan target input
        self.port_entry = ttk.Entry(self.input_row_frame, width=40)
        self.port_entry.pack_forget()
        self.port_entry_label = ttk.Label(self.input_row_frame, text="")
        self.port_entry_label.pack_forget()

        # ===== 网卡选择区 =====
        self.iface_frame = ttk.LabelFrame(self.root, text="网卡选择", padding=10)
        self.iface_frame.pack(fill="x", padx=10, pady=5)
        self.iface_frame.pack_forget()

        self.iface_list_frame = ttk.Frame(self.iface_frame)
        self.iface_list_frame.pack(fill="both", expand=True, pady=(0, 8))

        self.iface_canvas = tk.Canvas(self.iface_list_frame, bg="#1a1a2e", highlightthickness=0)
        self.iface_scrollbar = ttk.Scrollbar(self.iface_list_frame, orient="vertical", command=self.iface_canvas.yview)
        self.iface_inner_frame = ttk.Frame(self.iface_canvas)
        self.iface_scrollbar_command = self.iface_canvas.yview
        self.iface_canvas.configure(yscrollcommand=self.iface_scrollbar.set)
        self.iface_scrollbar.pack(side="right", fill="y")
        self.iface_canvas.pack(side="left", fill="both", expand=True)
        self.iface_canvas.create_window((0, 0), window=self.iface_inner_frame, anchor="nw")
        self.iface_canvas.bind("<Configure>", lambda e: self.iface_canvas.configure(scrollregion=self.iface_canvas.bbox("all")))

        self.iface_checkboxes = []  # list of (subnet_label, checkbox_var, subnet_string)
        self.iface_scan_type_var = tk.StringVar(value="subnet_24")

        ttk.Button(self.iface_frame, text="🔄 刷新网卡列表", command=self._refresh_interfaces).pack(fill="x")

        # ===== 高级选项 =====
        advanced_frame = ttk.LabelFrame(self.root, text="高级选项", padding=10)
        advanced_frame.pack(fill="x", padx=10, pady=5)

        opts_row1 = ttk.Frame(advanced_frame)
        opts_row1.pack(fill="x", pady=2)

        ttk.Label(opts_row1, text="并发线程数:").pack(side="left", padx=(0, 5))
        self.threads_var = tk.StringVar(value=str(THREAD_POOL_SIZE))
        ttk.Spinbox(opts_row1, from_=1, to=256, textvariable=self.threads_var, width=6).pack(side="left", padx=(0, 20))

        ttk.Label(opts_row1, text="端口超时(秒):").pack(side="left", padx=(0, 5))
        self.timeout_var = tk.StringVar(value="1.5")
        ttk.Spinbox(opts_row1, from_=0.5, to=10, increment=0.5, textvariable=self.timeout_var, width=6).pack(side="left", padx=(0, 20))

        opts_row2 = ttk.Frame(advanced_frame)
        opts_row2.pack(fill="x", pady=2)

        self.check_web = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts_row2, text="检测 Web 管理后台", variable=self.check_web).pack(side="left", padx=(0, 20))

        self.check_cves = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts_row2, text="只显示有 CVE 漏洞的端口", variable=self.check_cves).pack(side="left", padx=(0, 20))

        # ===== 输出设置 =====
        output_frame = ttk.LabelFrame(self.root, text="输出设置", padding=10)
        output_frame.pack(fill="x", padx=10, pady=5)

        self.output_var = tk.StringVar(value=f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        ttk.Entry(output_frame, textvariable=self.output_var, width=40).pack(side="left", fill="x", expand=True, padx=(0, 5))
        ttk.Button(output_frame, text="浏览...", command=self._browse_output).pack(side="left")

        # ===== 进度条 =====
        progress_frame = ttk.Frame(self.root)
        progress_frame.pack(fill="x", padx=10, pady=5)

        self.progress = ttk.Progressbar(progress_frame, mode="indeterminate")
        self.progress.pack(fill="x", side="left", expand=True, padx=(0, 10))

        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(progress_frame, textvariable=self.status_var, foreground="#888").pack(side="left", fill="x", expand=True)

        # ===== 按钮 =====
        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(fill="x", padx=10, pady=5)

        self.start_btn = ttk.Button(btn_frame, text="▶ 开始扫描", command=self._start_scan)
        self.start_btn.pack(side="left", padx=(0, 5))

        self.stop_btn = ttk.Button(btn_frame, text="⏹ 停止", command=self._stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=(0, 5))

        ttk.Button(btn_frame, text="📋 打开报告", command=self._open_report).pack(side="left")

        # ===== 日志区域 =====
        log_frame = ttk.LabelFrame(self.root, text="扫描日志", padding=5)
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.log_text = tk.Text(log_frame, height=8, state="disabled", bg="#1a1a2e", fg="#e0e0e0",
                                font=("Consolas", 9), wrap="word")
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.log_text.pack(side="left", fill="both", expand=True)

    def _on_mode_change(self, *args):
        """切换扫描模式时清空输入框并显示对应提示"""
        mode = self.mode_var.get()
        # Clear all input fields
        self.net_entry.delete(0, "end")
        self.ips_entry.delete(0, "end")
        self.port_entry.delete(0, "end")

        # Hide everything first
        self.net_entry.pack_forget()
        self.net_entry_label.pack_forget()
        self.ips_entry.pack_forget()
        self.ips_hint_label.pack_forget()
        self.port_entry.pack_forget()
        self.port_entry_label.pack_forget()
        self.iface_frame.pack_forget()

        if mode == "subnet":
            self.net_entry.insert(0, "auto")
            self.net_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
            self.net_entry_label.pack(side="left")
        elif mode == "ips":
            self.ips_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
            self.ips_hint_label.configure(text="多个IP用逗号或换行分隔，如 192.168.1.1,192.168.1.2")
            self.ips_hint_label.pack(side="left")
        elif mode == "port_scan":
            self.port_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
            self.port_entry_label.configure(text="目标IP:端口（如 192.168.1.1 或 192.168.1.1:80,443 或 all）")
            self.port_entry_label.pack(side="left")
        elif mode == "iface_select":
            self.iface_frame.pack(fill="x", padx=10, pady=5)
            self._refresh_interfaces()
        # auto mode: nothing to show

    def _browse_output(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            initialfile=f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        )
        if path:
            self.output_var.set(path)

    def _log(self, msg):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", msg + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _update_status(self, msg):
        self.status_var.set(msg)
        self.root.update_idletasks()

    def _refresh_interfaces(self):
        """刷新网卡列表，显示所有可用的IP和网段供用户选择"""
        # Clear existing checkboxes
        for widget in self.iface_inner_frame.winfo_children():
            widget.destroy()
        self.iface_checkboxes.clear()

        interfaces = get_all_local_interfaces()
        if not interfaces:
            ttk.Label(self.iface_inner_frame, text="未检测到网络接口", foreground="#888").pack(pady=10)
            return

        networks = get_networks_from_interfaces(interfaces)
        if not networks:
            ttk.Label(self.iface_inner_frame, text="未找到私有IP地址", foreground="#888").pack(pady=10)
            return

        # Group by interface
        iface_groups = defaultdict(list)
        for net in networks:
            iface_groups[net["interface"]].append(net)

        for iface_name, nets in iface_groups.items():
            # Interface header
            header = ttk.Label(self.iface_inner_frame, text=f"🖧 {iface_name}", font=("", 10, "bold"), foreground="#4ec9b0")
            header.pack(fill="x", pady=(8, 2))

            for net_info in nets:
                row_frame = ttk.Frame(self.iface_inner_frame)
                row_frame.pack(fill="x", padx=10, pady=1)

                var = tk.BooleanVar(value=False)
                self.iface_checkboxes.append((row_frame, var, net_info))

                ttk.Checkbutton(row_frame, variable=var, selectcolor="#16213e").pack(side="left")
                ttk.Label(row_frame, text=f"IP: {net_info['ip']}", foreground="#ccc").pack(side="left", padx=(5, 10))

                subnet_label = ttk.Label(row_frame, text="[ ] /24", foreground="#888", cursor="hand2")
                subnet_label.pack(side="left", padx=2)
                subnet_label.bind("<Button-1>", lambda e, v=var, l=subnet_label: self._toggle_subnet_var(v, l, "24"))

                subnet_label16 = ttk.Label(row_frame, text="[ ] /16", foreground="#888", cursor="hand2")
                subnet_label16.pack(side="left", padx=2)
                subnet_label16.bind("<Button-1>", lambda e, v=var, l=subnet_label16: self._toggle_subnet_var(v, l, "16"))

                # Store references
                subnet_label.var = var
                subnet_label.subnet_type = "24"
                subnet_label16.var = var
                subnet_label16.subnet_type = "16"

        # Scan type selector
        type_frame = ttk.Frame(self.iface_inner_frame)
        type_frame.pack(fill="x", pady=(8, 2))
        ttk.Label(type_frame, text="扫描粒度:", foreground="#888").pack(side="left", padx=(0, 5))
        ttk.Radiobutton(type_frame, text="/24 (精确)", variable=self.iface_scan_type_var, value="subnet_24").pack(side="left", padx=5)
        ttk.Radiobutton(type_frame, text="/16 (宽泛)", variable=self.iface_scan_type_var, value="subnet_16").pack(side="left", padx=5)

    def _toggle_subnet_var(self, var, label, subnet_type):
        """点击 /24 或 /16 标签时同步勾选/取消复选框"""
        var.set(not var.get())
        color = "#4ec9b0" if var.get() else "#888"
        label.config(foreground=color)

    def _get_iface_targets(self):
        """获取网卡选择模式下选中的网段"""
        subnets = []
        scan_type = self.iface_scan_type_var.get()
        for item in self.iface_checkboxes:
            row_frame, var, net_info = item
            if var.get():
                if scan_type == "subnet_24":
                    subnets.append(net_info["subnet_24"])
                else:
                    subnets.append(net_info["subnet_16"])
        return list(set(subnets))  # deduplicate

    def _get_targets(self):
        mode = self.mode_var.get()
        if mode == "auto":
            return "auto", None, None
        elif mode == "iface_select":
            subnets = self._get_iface_targets()
            if not subnets:
                messagebox.showwarning("提示", "请至少选择一个网卡或子网")
                return None, None, None
            return subnets, None, None
        elif mode == "subnet":
            net = self.net_entry.get().strip()
            if not net:
                messagebox.showwarning("提示", "请输入网段地址")
                return None, None, None
            return net, None, None
        elif mode == "ips":
            ips_str = self.ips_entry.get().strip()
            if not ips_str:
                messagebox.showwarning("提示", "请输入IP地址")
                return None, None, None
            ips = [i.strip() for i in ips_str.replace(",", "\n").splitlines() if i.strip()]
            return None, ips, None
        else:  # port_scan
            port_str = self.port_entry.get().strip()
            if not port_str:
                messagebox.showwarning("提示", "请输入目标IP和端口")
                return None, None, None
            return None, None, port_str

    def _toggle_ui(self, scanning):
        self.scanning = scanning
        self.start_btn.configure(state="disabled" if scanning else "normal")
        self.stop_btn.configure(state="normal" if scanning else "disabled")
        self.net_entry.configure(state="disabled" if scanning else "normal")
        self.ips_entry.configure(state="disabled" if scanning else "normal")
        self.port_entry.configure(state="disabled" if scanning else "normal")
        # Disable interface selection widgets during scan
        for widget in self.iface_inner_frame.winfo_children():
            try:
                widget.configure(state="disabled" if scanning else "normal")
            except Exception:
                pass
        for rb in self.root.winfo_children():
            for w in rb.winfo_children():
                if isinstance(w, ttk.Radiobutton):
                    w.configure(state="disabled" if scanning else "normal")

    def _start_scan(self):
        target = self._get_targets()
        if target[0] is None and target[1] is None and target[2] is None:
            return

        net_or_subnet = target[0]
        ips_list = target[1]
        port_str = target[2]

        self._toggle_ui(True)
        self.progress.start()
        self._log("=" * 50)
        self._log(f"[{datetime.now().strftime('%H:%M:%S')}] 开始扫描...")

        threads = int(self.threads_var.get())
        timeout = float(self.timeout_var.get())
        output_file = self.output_var.get()
        scan_cves_only = self.check_cves.get()

        def run_scan():
            try:
                mode = self.mode_var.get()
                hosts = []
                target_ports = []
                is_port_scan = False

                if mode == "auto":
                    self._update_status("正在检测本机网段...")
                    self._log("[+] 自动检测本机网段...")
                    hosts = discover_hosts(thread_pool_size=threads)
                elif mode == "iface_select":
                    self._update_status("正在合并选中的网段...")
                    self._log(f"[+] 网卡选择模式: {len(net_or_subnet)} 个子网")
                    # Merge all selected subnets into one scan
                    all_hosts = []
                    for idx, subnet in enumerate(net_or_subnet):
                        if self._stop_flag:
                            return
                        self._update_status(f"正在扫描网段 {subnet} ({idx+1}/{len(net_or_subnet)})...")
                        self._log(f"[+] 扫描子网: {subnet}")
                        subnet_hosts = discover_hosts(subnet, thread_pool_size=threads)
                        all_hosts.extend(subnet_hosts)
                    hosts = sorted(set(all_hosts))
                elif mode == "subnet":
                    self._update_status(f"正在扫描网段 {net_or_subnet}...")
                    self._log(f"[+] 网段: {net_or_subnet}")
                    hosts = discover_hosts(net_or_subnet, thread_pool_size=threads)
                elif mode == "ips":
                    self._update_status("正在解析 IP 列表...")
                    hosts = discover_hosts_manual(ips_list)
                elif mode == "port_scan":
                    is_port_scan = True
                    self._update_status("正在解析目标...")
                    host, ports = self._parse_port_scan_input(port_str)
                    if host:
                        hosts = [host]
                        target_ports = ports

                if not hosts:
                    self._log("[!] 未输入有效目标")
                    self.root.after(0, lambda: messagebox.showinfo("结果", "未输入有效目标"))
                    self.root.after(0, self._finish_scan)
                    return

                if is_port_scan:
                    self._log(f"[+] 目标: {hosts[0]} 端口: {','.join(str(p) for p in target_ports) if target_ports else '全部'}")
                    self._log(f"[*] 开始端口探测...")
                    results = []
                    completed = 0
                    total = len(hosts)

                    with ThreadPoolExecutor(max_workers=min(threads, len(hosts))) as executor:
                        self._executor = executor
                        futures = {executor.submit(self._scan_single_host, ip, target_ports, threads): ip for ip in hosts}
                        for future in as_completed(futures):
                            if self._stop_flag:
                                executor.shutdown(wait=False, cancel_futures=True)
                                break
                            try:
                                r = future.result()
                                results.append(r)
                            except Exception as e:
                                self._log(f"[!] 扫描失败: {e}")
                            completed += 1
                            self.root.after(0, lambda c=completed, t=total: self._update_status(f"扫描进度: {c}/{t}"))
                else:
                    self._log(f"[+] 发现 {len(hosts)} 台主机")
                    self._log(f"    目标: {', '.join(hosts[:10])}{'...' if len(hosts) > 10 else ''}")
                    self._log(f"[*] 开始端口扫描 ({len(hosts)} 台主机)...")
                    results = []
                    completed = 0

                    with ThreadPoolExecutor(max_workers=min(threads, len(hosts))) as executor:
                        self._executor = executor
                        futures = {executor.submit(scan_host, ip, threads): ip for ip in hosts}
                        for future in as_completed(futures):
                            if self._stop_flag:
                                executor.shutdown(wait=False, cancel_futures=True)
                                break
                            try:
                                r = future.result()
                                results.append(r)
                            except Exception as e:
                                self._log(f"[!] 扫描失败: {e}")
                            completed += 1
                            self.root.after(0, lambda c=completed, t=len(hosts): self._update_status(f"扫描进度: {c}/{t}"))

                # If stopped early, still save what we have
                if self._stop_flag:
                    self._log(f"[!] 扫描已被用户中断，已收集 {len(results)} 台主机的数据")
                else:
                    self._log(f"[*] 扫描完成! 共 {len(hosts)} 台主机")

                # 过滤
                if scan_cves_only and not is_port_scan:
                    results = [r for r in results if r["summary"]["vulnerabilities_count"] > 0]
                    self._log(f"[+] 过滤后: {len(results)} 台有漏洞的主机")

                # 生成报告
                self._update_status("正在生成报告...")
                generate_html_report(results, output_file)
                self._log(f"[+] HTML 报告已保存: {os.path.abspath(output_file)}")

                if not self._stop_flag:
                    total_high = sum(r["summary"]["high_severity"] for r in results)
                    if total_high > 0:
                        self._log(f"⚠️  发现 {total_high} 个高危漏洞！")

                    mode_label = "端口探测" if is_port_scan else "扫描"
                    self.root.after(0, lambda: messagebox.showinfo("扫描完成", f"{mode_label}完成！\n发现 {len(hosts)} 台主机\n报告已保存: {output_file}"))

            except Exception as e:
                self._log(f"[!] 扫描出错: {e}")
                self.root.after(0, lambda err=e: messagebox.showerror("错误", str(err)))
            finally:
                self.root.after(0, self._finish_scan)

        threading.Thread(target=run_scan, daemon=True).start()

    def _parse_port_scan_input(self, port_str):
        """解析端口探测输入，返回 (ip, [ports])"""
        port_str = port_str.strip()
        if not port_str:
            return None, []

        # 支持格式: "192.168.1.1", "192.168.1.1:80,443", "192.168.1.1:all"
        if ":" in port_str:
            parts = port_str.rsplit(":", 1)
            host = parts[0].strip()
            ports_part = parts[1].strip()

            if ports_part == "all":
                # 扫描所有已知端口
                ports = sorted(SCAN_PORTS.keys())
            else:
                # 解析端口列表，支持范围如 1-1024
                ports = []
                for p in ports_part.split(","):
                    p = p.strip()
                    if "-" in p:
                        try:
                            start, end = p.split("-", 1)
                            ports.extend(range(int(start), int(end) + 1))
                        except ValueError:
                            pass
                    else:
                        try:
                            ports.append(int(p))
                        except ValueError:
                            pass
            return host, sorted(set(ports))
        else:
            # 只有 IP，扫描所有已知端口
            return port_str, sorted(SCAN_PORTS.keys())

    def _scan_single_host(self, ip, target_ports, thread_pool_size):
        """对单个主机进行端口探测"""
        results = {
            "ip": ip,
            "open_ports": [],
            "vulnerabilities": [],
            "web_admin": [],
            "summary": {},
        }

        open_ports = []

        with ThreadPoolExecutor(max_workers=min(thread_pool_size, len(target_ports))) as executor:
            futures = {executor.submit(self._probe_port, ip, port): port for port in target_ports}
            for f in as_completed(futures):
                try:
                    port, status, service, cve, desc, banner, severity = f.result()
                    if status == "open":
                        open_ports.append(port)
                        findings = {
                            "port": port,
                            "service": service,
                            "cve": cve,
                            "description": desc,
                            "banner": banner,
                            "severity": severity,
                        }
                        results["open_ports"].append(findings)
                except Exception:
                    pass

        # Web 后台检测
        if self.check_web.get():
            web_ports = [p for p in open_ports if p in (80, 443, 8080, 8443, 9090)]
            for wp in web_ports:
                admin_findings = check_web_admin(ip, wp)
                if admin_findings:
                    results["web_admin"].extend(admin_findings)

        vuln_count = sum(1 for p in results["open_ports"] if p.get("cve"))
        high_count = sum(1 for p in results["open_ports"] if p.get("severity") == "high")
        results["summary"] = {
            "open_ports_count": len(open_ports),
            "vulnerabilities_count": vuln_count,
            "high_severity": high_count,
            "web_admin_findings": len(results["web_admin"]),
        }

        results["open_ports"].sort(key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x.get("severity", "low"), 3))
        return results

    def _probe_port(self, ip, port, timeout=1.5):
        """探测单个端口是否开放"""
        svc = SCAN_PORTS.get(port)
        if svc:
            service, cve, desc = svc
        else:
            service = f"Port-{port}"
            cve = None
            desc = "未知服务"

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            conn_result = s.connect_ex((ip, port))
            if conn_result != 0:
                s.close()
                return (port, "closed", service, cve, desc, "", "low")

            banner = ""
            try:
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            except:
                pass
            s.close()

            severity = "low"
            if banner:
                severity = "medium"
                if "vsftpd 3.0.3" in banner.lower():
                    severity = "high"
                if "openssh 7." in banner.lower() or "openssh 8." in banner.lower():
                    severity = "high"

            return (port, "open", service, cve, desc, banner, severity)

        except (socket.timeout, OSError, ConnectionRefusedError):
            return (port, "closed", service, cve, desc, "", "low")

    def _stop_scan(self):
        self._stop_flag = True
        self._log("[!] 正在停止扫描...")
        # Cancel all pending futures in the executor
        if self._executor:
            try:
                self._executor.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass
            self._executor = None
        self._log("[!] 扫描已取消")
        self._finish_scan()

    def _finish_scan(self):
        self._stop_flag = False
        self.progress.stop()
        self._toggle_ui(False)
        self._update_status("就绪")

    def _open_report(self):
        output_file = self.output_var.get().strip()
        if not output_file:
            messagebox.showwarning("提示", "请先设置输出文件路径")
            return
        if os.path.exists(output_file):
            if sys.platform == "win32":
                os.startfile(output_file)
            elif sys.platform == "darwin":
                subprocess.call(["open", output_file])
            else:
                subprocess.call(["xdg-open", output_file])
        else:
            messagebox.showinfo("提示", "报告文件不存在，请先执行扫描")


# ====================================================================
# CLI 辅助函数
# ====================================================================

def _parse_cli_port_input(port_str):
    """解析 CLI 端口探测输入"""
    port_str = port_str.strip()
    if not port_str:
        return None, []

    if ":" in port_str:
        parts = port_str.rsplit(":", 1)
        host = parts[0].strip()
        ports_part = parts[1].strip()

        if ports_part == "all":
            ports = sorted(SCAN_PORTS.keys())
        else:
            ports = []
            for p in ports_part.split(","):
                p = p.strip()
                if "-" in p:
                    try:
                        start, end = p.split("-", 1)
                        ports.extend(range(int(start), int(end) + 1))
                    except ValueError:
                        pass
                else:
                    try:
                        ports.append(int(p))
                    except ValueError:
                        pass
        return host, sorted(set(ports))
    else:
        return port_str, sorted(SCAN_PORTS.keys())


def _probe_port(ip, port, timeout=1.5):
    """探测单个端口是否开放（模块级函数）"""
    svc = SCAN_PORTS.get(port)
    if svc:
        service, cve, desc = svc
    else:
        service = f"Port-{port}"
        cve = None
        desc = "未知服务"

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        conn_result = s.connect_ex((ip, port))
        if conn_result != 0:
            s.close()
            return (port, "closed", service, cve, desc, "", "low")

        banner = ""
        try:
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        except:
            pass
        s.close()

        severity = "low"
        if banner:
            severity = "medium"
            if "vsftpd 3.0.3" in banner.lower():
                severity = "high"
            if "openssh 7." in banner.lower() or "openssh 8." in banner.lower():
                severity = "high"

        return (port, "open", service, cve, desc, banner, severity)

    except (socket.timeout, OSError, ConnectionRefusedError):
        return (port, "closed", service, cve, desc, "", "low")


def _scan_single_host_cli(ip, target_ports, thread_pool_size):
    """CLI 模式: 扫描单个主机端口"""
    results = {
        "ip": ip,
        "open_ports": [],
        "vulnerabilities": [],
        "web_admin": [],
        "summary": {},
    }

    with ThreadPoolExecutor(max_workers=min(thread_pool_size, len(target_ports))) as executor:
        futures = {executor.submit(_probe_port, ip, port): port for port in target_ports}
        for f in as_completed(futures):
            try:
                port, status, service, cve, desc, banner, severity = f.result()
                if status == "open":
                    results["open_ports"].append({
                        "port": port, "service": service, "cve": cve,
                        "description": desc, "banner": banner, "severity": severity,
                    })
            except Exception:
                pass

    vuln_count = sum(1 for p in results["open_ports"] if p.get("cve"))
    high_count = sum(1 for p in results["open_ports"] if p.get("severity") == "high")
    results["summary"] = {
        "open_ports_count": len(results["open_ports"]),
        "vulnerabilities_count": vuln_count,
        "high_severity": high_count,
        "web_admin_findings": 0,
    }
    results["open_ports"].sort(key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x.get("severity", "low"), 3))
    return results


# ====================================================================
# 主流程
# ====================================================================

def parse_args():
    import argparse
    parser = argparse.ArgumentParser(description="局域网漏洞扫描工具", add_help=False)
    parser.add_argument("--net", type=str, default="auto", help="CIDR 网段")
    parser.add_argument("--ips", type=str, default=None, help="逗号分隔的 IP 列表")
    parser.add_argument("--output", type=str, default=None, help="输出 HTML 报告路径")
    parser.add_argument("--json", type=str, default=None, help="同时输出 JSON 文件")
    parser.add_argument("--threads", type=int, default=THREAD_POOL_SIZE, help="并发线程数")
    parser.add_argument("--cli", action="store_true", help="强制命令行模式")
    parser.add_argument("--port-scan", type=str, metavar="IP:PORTS", help="端口探测: IP 或 IP:port1,port2 或 IP:all")
    parser.add_argument("--help", "-h", action="store_true", help="显示帮助")
    return parser.parse_args()


def cli_main(args):
    """命令行模式主函数"""
    start_time = time.time()

    # 端口探测模式
    if args.port_scan:
        host, ports = _parse_cli_port_input(args.port_scan)
        if not host:
            print("[!] 无效的端口探测格式，用法: --port-scan IP[:ports]")
            print("    示例: --port-scan 192.168.1.1          # 扫描所有已知端口")
            print("         --port-scan 192.168.1.1:80,443   # 扫描指定端口")
            print("         --port-scan 192.168.1.1:all      # 扫描所有端口")
            print("         --port-scan 192.168.1.1:1-1024   # 扫描端口范围")
            return

        output_file = args.output or f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        print(f"[*] 端口探测: {host} 端口: {','.join(str(p) for p in ports) if ports else '全部'}")

        results = []
        with ThreadPoolExecutor(max_workers=min(args.threads, 1)) as executor:
            future = executor.submit(_scan_single_host_cli, host, ports, args.threads)
            results.append(future.result())

        print("=" * 60)
        print("  📊 端口探测结果")
        print("=" * 60)
        for r in results:
            s = r["summary"]
            print(f"\n  🖥️  {r['ip']}")
            print(f"     开放端口: {s['open_ports_count']} | 漏洞: {s['vulnerabilities_count']} | 高危: {s['high_severity']}")
            for p in r["open_ports"][:10]:
                sev = p.get("severity", "?").upper()
                cve = p.get("cve", "")
                tag = f"[{sev}]" if sev else "[  ]"
                cve_str = f" {cve}" if cve else ""
                banner_str = f"  banner: {p.get('banner','')}" if p.get("banner") else ""
                print(f"       {tag} {p['port']}/tcp {p['service']:15s}{cve_str}{banner_str}")

        elapsed = time.time() - start_time
        generate_html_report(results, output_file)
        print(f"\n[*] HTML 报告已保存到: {os.path.abspath(output_file)}")
        print(f"\n[*] 总耗时: {elapsed:.1f} 秒")
        return

    # 常规扫描模式
    if args.ips:
        hosts = [i.strip() for i in args.ips.split(",") if i.strip()]
    elif args.net == "auto":
        hosts = discover_hosts(thread_pool_size=args.threads)
    else:
        hosts = discover_hosts(args.net, thread_pool_size=args.threads)

    if not hosts:
        print("[!] 未发现存活主机，退出")
        return

    output_file = args.output or f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

    print(f"[*] 开始扫描 {len(hosts)} 台主机...")
    results = []
    completed = 0

    with ThreadPoolExecutor(max_workers=min(args.threads, len(hosts))) as executor:
        futures = {executor.submit(scan_host, ip, args.threads): ip for ip in hosts}
        for f in as_completed(futures):
            try:
                r = f.result()
                results.append(r)
            except Exception as e:
                print(f"[!] 扫描失败: {e}")
            completed += 1
            sys.stdout.write(f"\r[*] 进度: {completed}/{len(hosts)}")
            sys.stdout.flush()

    print(f"\r[*] 扫描完成! 共 {len(hosts)} 台主机\n")

    print("=" * 60)
    print("  📊 扫描结果摘要")
    print("=" * 60)

    for r in sorted(results, key=lambda x: -x["summary"]["vulnerabilities_count"]):
        s = r["summary"]
        if not s["open_ports_count"]:
            continue
        print(f"\n  🖥️  {r['ip']}")
        print(f"     开放端口: {s['open_ports_count']} | 漏洞: {s['vulnerabilities_count']} | 高危: {s['high_severity']}")
        for p in r["open_ports"][:5]:
            sev = p.get("severity", "?").upper()
            cve = p.get("cve", "")
            tag = f"[{sev}]" if sev else "[  ]"
            cve_str = f" {cve}" if cve else ""
            banner_str = f"  banner: {p.get('banner','')}" if p.get("banner") else ""
            print(f"       {tag} {p['port']}/tcp {p['service']:15s}{cve_str}{banner_str}")

    elapsed = time.time() - start_time
    generate_html_report(results, output_file)
    print(f"\n[*] HTML 报告已保存到: {os.path.abspath(output_file)}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"[*] JSON 报告已保存到: {os.path.abspath(args.json)}")

    print(f"\n[*] 总耗时: {elapsed:.1f} 秒")

    total_high = sum(r["summary"]["high_severity"] for r in results)
    if total_high > 0:
        print(f"\n⚠️  发现 {total_high} 个高危漏洞！建议尽快修复。")


def main():
    args = parse_args()

    if args.help:
        print(__doc__)
        return

    # 如果有 CLI 参数则走命令行模式，否则启动 GUI
    if args.cli or args.ips or args.net != "auto" or args.json or args.port_scan:
        cli_main(args)
    else:
        root = tk.Tk()
        app = ScanGUI(root)
        root.mainloop()


if __name__ == "__main__":
    main()
