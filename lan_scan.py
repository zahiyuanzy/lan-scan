#!/usr/bin/env python3
"""
局域网漏洞扫描工具
- 自动发现本机局域网存活主机
- 端口服务探测 + 已知漏洞检测
- HTML 报告输出
- 无外部依赖，纯标准库

Usage:
    python3 lan_scan.py               # 自动扫描本机所在网段
    python3 lan_scan.py --net 192.168.1.0/24  # 指定网段
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
        # macOS / Linux
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
                        if iface == "en0":  # WiFi
                            return "192.168.0.0/16"
                        elif iface.startswith("en"):
                            return "172.16.0.0/12"
                        elif iface == "en1":
                            return "10.0.0.0/8"
    except Exception:
        pass

    # 备选：通过 ARP 表
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

    return "192.168.0.0/16"  # 默认


def discover_hosts(net_cidr="auto"):
    """ARP 扫描发现存活主机（快速、免 root）"""
    if net_cidr == "auto":
        net_cidr = get_local_network()

    network = ipaddress.ip_network(net_cidr, strict=False)
    print(f"[+] 网段: {network}")
    print(f"[+] ARP 扫描中...")

    hosts = []
    lock = threading.Lock()
    current = 0
    total = len(list(network.hosts()))

    def ping_one(ip):
        nonlocal current
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.3)
            s.connect((str(ip), 9))  # Discard protocol
            s.close()
            with lock:
                current += 1
                if current % 50 == 0:
                    sys.stdout.write(f"\r[+] 扫描进度: {current}/{total}")
                    sys.stdout.flush()
            return str(ip)
        except (socket.timeout, OSError):
            return None

    with ThreadPoolExecutor(max_workers=min(THREAD_POOL_SIZE, total)) as executor:
        futures = {executor.submit(ping_one, host): host for host in network.hosts()}
        for future in as_completed(futures):
            result = future.result()
            if result:
                hosts.append(result)

    print(f"\r[+] 扫描完成! 发现 {len(hosts)} 台存活主机\n")
    return sorted(hosts)


def discover_hosts_manual(ips=None):
    """手动指定 IP 列表扫描"""
    if ips:
        hosts = ips
    else:
        hosts = ["127.0.0.1"]
    print(f"[+] 扫描 {len(hosts)} 个目标...")
    return sorted(hosts)


# ====================================================================
# 端口 & 服务探测
# ====================================================================

def banner_grab(ip, port, timeout=2):
    """抓取服务 banner"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        try:
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        except:
            banner = ""
        s.close()
        return banner[:256]
    except (socket.timeout, OSError, ConnectionRefusedError):
        return None


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
    paths = WEB_ADMIN_PATHS[:8]  # 限制扫描数量

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

def scan_host(ip):
    """对单个主机进行综合扫描"""
    print(f"[*] 扫描 {ip} ...")
    results = {
        "ip": ip,
        "open_ports": [],
        "vulnerabilities": [],
        "web_admin": [],
        "summary": {},
    }

    open_ports = []

    # 并发扫描端口
    with ThreadPoolExecutor(max_workers=min(THREAD_POOL_SIZE, len(SCAN_PORTS))) as executor:
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

    # 发现端口后，检查 Web 后台
    web_ports = [p for p in open_ports if p in (80, 443, 8080, 8443, 9090, 3306, 9200, 27017)]
    if web_ports:
        for wp in web_ports:
            admin_findings = check_web_admin(ip, wp)
            if admin_findings:
                results["web_admin"].extend(admin_findings)

    # 汇总漏洞
    vuln_count = sum(1 for p in results["open_ports"] if p.get("cve"))
    high_count = sum(1 for p in results["open_ports"] if p.get("severity") == "high")
    results["summary"] = {
        "open_ports_count": len(open_ports),
        "vulnerabilities_count": vuln_count,
        "high_severity": high_count,
        "web_admin_findings": len(results["web_admin"]),
    }

    # 按严重性排序
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
  <div class="summary-card"><div class="num" style="color:#4ec9b0">{sum(r["summary"]["web_admin_findings"] for r in results)}</div>
    <div class="label">Web 后台</div></div>
</div>
"""

    for r in sorted(results, key=lambda x: -x["summary"]["vulnerabilities_count"]):
        ips = r.get("ip", "unknown")
        s = r["summary"]

        # 严重性 badge
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
  扫描工具: LanScan v1.0 | 仅供授权的安全评估使用 |
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
# 主流程
# ====================================================================

def parse_args():
    import argparse
    parser = argparse.ArgumentParser(description="局域网漏洞扫描工具", add_help=False)
    parser.add_argument("--net", type=str, default="auto", help="CIDR 网段，如 192.168.1.0/24（默认自动检测）")
    parser.add_argument("--ips", type=str, default=None, help="逗号分隔的 IP 列表，如 192.168.1.1,192.168.1.2")
    parser.add_argument("--output", type=str, default="scan_report.html", help="输出 HTML 报告路径")
    parser.add_argument("--json", type=str, default=None, help="同时输出 JSON 文件")
    parser.add_argument("--threads", type=int, default=THREAD_POOL_SIZE, help="并发线程数")
    parser.add_argument("--help", "-h", action="store_true", help="显示帮助")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.help:
        print(__doc__)
        print("Examples:")
        print("  python3 lan_scan.py                        # 自动扫描")
        print("  python3 lan_scan.py --net 192.168.1.0/24   # 指定网段")
        print("  python3 lan_scan.py --ips 192.168.1.1      # 指定IP")
        print("  python3 lan_scan.py --output report.html   # 指定输出")
        return

    start_time = time.time()

    # 步骤 1: 发现存活主机
    if args.ips:
        ips = [i.strip() for i in args.ips.split(",") if i.strip()]
        hosts = ips
    elif args.net == "auto":
        hosts = discover_hosts()
    else:
        hosts = discover_hosts(args.net)

    if not hosts:
        print("[!] 未发现存活主机，退出")
        return

    # 步骤 2: 综合扫描
    print(f"[*] 开始扫描 {len(hosts)} 台主机...")
    results = []
    completed = 0

    with ThreadPoolExecutor(max_workers=min(THREAD_POOL_SIZE, len(hosts))) as executor:
        futures = {executor.submit(scan_host, ip): ip for ip in hosts}
        for f in as_completed(futures):
            try:
                r = f.result()
                results.append(r)
            except Exception as e:
                print(f"[!] 扫描失败: {f.result()}: {e}")
            completed += 1
            sys.stdout.write(f"\r[*] 进度: {completed}/{len(hosts)}")
            sys.stdout.flush()

    print(f"\r[*] 扫描完成! 共 {len(hosts)} 台主机\n")

    # 终端输出摘要
    print("=" * 60)
    print("  📊 扫描结果摘要")
    print("=" * 60)

    for r in sorted(results, key=lambda x: -x["summary"]["vulnerabilities_count"]):
        s = r["summary"]
        if not s["open_ports_count"]:
            continue
        print(f"\n  🖥️  {r['ip']}")
        print(f"     开放端口: {s['open_ports_count']} 个 | "
              f"漏洞: {s['vulnerabilities_count']} 个 | "
              f"高危: {s['high_severity']} 个 | "
              f"Web 后台: {s['web_admin_findings']} 个")
        for p in r["open_ports"][:5]:
            sev = p.get("severity", "?").upper()
            cve = p.get("cve", "")
            tag = f"[{sev}]" if sev else "[  ]"
            cve_str = f" {cve}" if cve else ""
            banner_str = f"  banner: {p.get('banner','')}" if p.get("banner") else ""
            print(f"       {tag} {p['port']}/tcp {p['service']:15s}{cve_str}{banner_str}")

    elapsed = time.time() - start_time

    # 生成报告
    output_file = generate_html_report(results, args.output)
    print(f"\n[*] HTML 报告已保存到: {os.path.abspath(output_file)}")

    # 可选 JSON 输出
    if args.json:
        # 移除不可序列化的数据
        serializable = results
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(serializable, f, ensure_ascii=False, indent=2)
        print(f"[*] JSON 报告已保存到: {os.path.abspath(args.json)}")

    print(f"\n[*] 总耗时: {elapsed:.1f} 秒")

    # 高危提示
    total_high = sum(r["summary"]["high_severity"] for r in results)
    if total_high > 0:
        print(f"\n⚠️  发现 {total_high} 个高危漏洞！建议尽快修复。")


if __name__ == "__main__":
    main()
