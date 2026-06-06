#!/usr/bin/env python3
"""
메모리 포렌식 자동 분석 도구 v2.0
- 윈도우/리눅스 자동 감지
- Volatility 3 자동 탐색
"""

# =====================================================================
# 의존성 자동 설치
# =====================================================================
import subprocess
import sys

def auto_install(package: str):
    """패키지가 없으면 자동 설치"""
    try:
        __import__(package)
    except ImportError:
        print(f"[*] {package} 설치 중...")
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", package, "-q"
        ])
        print(f"[+] {package} 설치 완료")

auto_install("volatility3")

# =====================================================================
# import
# =====================================================================
import os
import re
import json
import argparse
import shutil
import platform
from datetime import datetime
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

# =====================================================================
# 전역 변수
# =====================================================================
VOL_PATH = ""
MEM_PATH = ""

# =====================================================================
# Volatility 버전 감지
# =====================================================================

def detect_volatility_version():
    """설치된 Volatility 버전 자동 감지 (OS별 경로 탐색 포함)"""

    is_windows = platform.system() == "Windows"

    # === Volatility 3 후보 ===
    candidates_v3 = ["vol", "vol3", "volatility3", "volatility"]

    if is_windows:
        candidates_v3.extend([
            os.path.join(os.path.dirname(sys.executable), "Scripts", "vol.exe"),
            os.path.join(os.path.dirname(sys.executable), "Scripts", "vol3.exe"),
            os.path.join(os.path.dirname(sys.executable), "vol.exe"),
        ])
    else:
        candidates_v3.extend([
            "/usr/local/bin/vol",
            "/usr/local/bin/vol3",
            "/usr/bin/vol",
            "/usr/bin/vol3",
            os.path.join(os.path.expanduser("~"), ".local", "bin", "vol"),
            os.path.join(os.path.expanduser("~"), ".local", "bin", "vol3"),
            os.path.join(os.path.dirname(sys.executable), "vol"),
            os.path.join(os.path.dirname(sys.executable), "vol3"),
        ])

    # Volatility 3 탐색
    for cmd in candidates_v3:
        try:
            if shutil.which(cmd) or os.path.isfile(cmd):
                result = subprocess.run(
                    [cmd, "--help"],
                    capture_output=True, text=True, timeout=30
                )
                if "Volatility 3" in result.stdout or "volatility3" in result.stdout:
                    return "3", cmd
        except Exception:
            continue

    # python -m volatility3 시도
    try:
        result = subprocess.run(
            [sys.executable, "-m", "volatility3", "--help"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            return "3", f"{sys.executable} -m volatility3"
    except Exception:
        pass

    # Volatility 3 패키지 직접 확인
    try:
        import volatility3
        return "3", f"{sys.executable} -m volatility3"
    except ImportError:
        pass

    # Volatility 2 확인
    try:
        result = subprocess.run(
            ["vol.py", "--help"],
            capture_output=True, text=True, timeout=30
        )
        if "Volatility Foundation" in result.stdout:
            return "2", "vol.py"
    except Exception:
        pass

    return None, None

# =====================================================================
# Volatility 실행
# =====================================================================

def run_volatility(plugin, extra_args=None):
    """Volatility 플러그인 실행 및 결과 반환"""

    global VOL_PATH

    if VOL_PATH is None or VOL_PATH == "":
        print(f"  [✗] Volatility 경로가 설정되지 않았습니다.")
        return None

    cmd_parts = VOL_PATH.split()
    cmd = cmd_parts + ["-f", MEM_PATH]
    cmd.append(plugin)

    if extra_args:
        if isinstance(extra_args, list):
            cmd += extra_args
        else:
            cmd += extra_args.split()

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600
        )

        if result.returncode != 0 and result.stderr:
            error_lines = [l for l in result.stderr.split('\n')
                          if 'error' in l.lower() and 'warning' not in l.lower()]
            if error_lines:
                print(f"  [!] 경고: {error_lines[0][:100]}")

        return result.stdout

    except subprocess.TimeoutExpired:
        print(f"  [✗] {plugin} 실행 시간 초과 (10분)")
        return None
    except FileNotFoundError:
        print(f"  [✗] Volatility 실행 파일을 찾을 수 없습니다: {VOL_PATH}")
        return None
    except Exception as e:
        print(f"  [✗] {plugin} 실행 오류: {e}")
        return None


def parse_vol_output(output):
    """Volatility 출력을 헤더 기반으로 파싱하여 딕셔너리 리스트로 반환"""
    results = []
    lines = output.strip().split('\n')
    header_indices = []
    header_names = []

    for line in lines:
        if not line.strip():
            continue

        if all(c in '-\t ' for c in line):
            continue

        parts = line.split()
        if not header_names and parts:
            if any(keyword in parts for keyword in ["PID", "Offset", "PPID", "Name",
                    "ImageFileName", "Process", "Pid", "Owner", "Start"]):
                header_names = parts
                for name in header_names:
                    idx = line.index(name)
                    header_indices.append(idx)
                continue

        if not header_names:
            continue

        row = {}
        for i, name in enumerate(header_names):
            try:
                start = header_indices[i]
                end = header_indices[i + 1] if i + 1 < len(header_indices) else len(line)
                value = line[start:end].strip()
                row[name] = value
            except IndexError:
                row[name] = ""

        if any(row.values()):
            results.append(row)

    return results

# =====================================================================
# 결과 파싱 유틸
# =====================================================================

def row_path_name(full_path: str) -> str:
    """경로에서 파일명만 추출 (OS 무관)"""
    if not full_path:
        return ""
    return full_path.replace("\\", "/").split("/")[-1].strip()


# =====================================================================
# 데이터 클래스
# =====================================================================

@dataclass
class Finding:
    """분석 발견 사항"""
    category: str
    severity: str      # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    detail: str
    evidence: str = ""

@dataclass
class AnalysisReport:
    findings: list = field(default_factory=list)
    raw_outputs: dict = field(default_factory=dict)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime = None
    memory_image: str = ""
    output_dir: str = ""
    os_name: str = "Unknown_OS"

    def add(self, finding: Finding):
        self.findings.append(finding)

    def get_critical(self):
        return [f for f in self.findings if f.severity == "CRITICAL"]

    def get_high(self):
        return [f for f in self.findings if f.severity == "HIGH"]


# =====================================================================
# 탐지 함수들
# =====================================================================

def detect_hidden_processes(report):
    """은닉 프로세스 탐지 (pslist vs psscan 비교)"""
    pslist_output = report.raw_outputs.get("pslist", "")
    psscan_output = report.raw_outputs.get("psscan", "")

    if not pslist_output or not psscan_output:
        print("  [!] pslist 또는 psscan 결과가 없습니다.")
        return []

    def extract_pids(output):
        """출력에서 PID 집합 추출 (헤더 기반)"""
        pids = {}
        lines = output.strip().split('\n')
        pid_idx = None
        name_idx = None

        for line in lines:
            parts = line.split()
            if not parts:
                continue

            # 헤더 행 감지
            if "PID" in parts and pid_idx is None:
                pid_idx = parts.index("PID")
                if "ImageFileName" in parts:
                    name_idx = parts.index("ImageFileName")
                elif "Name" in parts:
                    name_idx = parts.index("Name")
                continue

            if pid_idx is None:
                continue

            try:
                pid = int(parts[pid_idx])
                name = parts[name_idx] if name_idx and name_idx < len(parts) else "Unknown"
                pids[pid] = name
            except (ValueError, IndexError):
                continue

        return pids

    pslist_pids = extract_pids(pslist_output)
    psscan_pids = extract_pids(psscan_output)

    hidden_pids = set(psscan_pids.keys()) - set(pslist_pids.keys())

    findings = []
    for pid in hidden_pids:
        name = psscan_pids.get(pid, "Unknown")
        findings.append(Finding(
            category="은닉 프로세스",
            severity="CRITICAL",
            title=f"은닉 프로세스 탐지: {name} (PID: {pid})",
            detail=f"psscan에만 존재하는 프로세스 발견",
            evidence=f"PID={pid}, 프로세스명={name}"
        ))

    return findings

def detect_code_injection(report):
    """코드 인젝션 탐지 (malfind 결과 분석)"""
    malfind_output = report.raw_outputs.get("malfind", "")
    if not malfind_output:
        print("  [!] malfind 결과가 없습니다.")
        return []

    WHITELIST = [
        "MsMpEng.exe", "dllhost.exe", "SearchApp.exe",
        "RuntimeBroker.", "Teams.exe", "smartscreen.ex",
        "LockApp.exe", "TextInputHost.exe", "ShellExperienceHost.exe",
        "msedgewebview2", "msedge.exe", "chrome.exe",
        "firefox.exe", "svchost.exe", "csrss.exe",
        "explorer.exe", "taskhostw.exe", "sihost.exe",
        "ctfmon.exe", "SecurityHealth", "OneDrive.exe",
        "StartMenuExper", "WindowsTermina", "powershell.exe",
        "conhost.exe", "dwm.exe", "fontdrvhost.ex",
        "lsass.exe", "services.exe", "wininit.exe",
        "winlogon.exe", "spoolsv.exe", "SearchIndexer.",
    ]

    shellcode_patterns = [
        (r'fc e8', '쉘코드 프롤로그 (FC E8)', 80),
        (r'e8 00 00 00 00', 'Call $+5 패턴', 70),
        (r'4d 5a', 'PE 헤더 (MZ)', 60),
        (r'ff d5', 'Call EBP 패턴', 50),
        (r'68 00 00 00 00', 'Push 0x0 패턴', 30),
    ]

    findings = []
    filtered_count = 0

    # malfind 출력은 특수 구조 (헤더 + hex 블록 반복)
    # 헤더 행에서 PID/프로세스명을 감지하고, 이후 hex 행을 수집
    lines = malfind_output.strip().split('\n')

    # 1단계: 헤더 컬럼 위치 감지
    header_found = False
    pid_col = None
    name_col = None
    addr_col = None
    header_keys = []

    for line in lines:
        parts = line.split()
        if not parts:
            continue
        # PID가 포함된 헤더 행 탐지
        if "PID" in parts and not header_found:
            header_keys = parts
            pid_col = parts.index("PID")
            for key in ["ImageFileName", "Name", "Process"]:
                if key in parts:
                    name_col = parts.index(key)
                    break
            for key in ["Start", "Address", "StartVPN"]:
                if key in parts:
                    addr_col = parts.index(key)
                    break
            header_found = True
            break

    # 헤더를 못 찾으면 인덱스 기반 폴백
    if not header_found:
        pid_col = 0
        name_col = 1
        addr_col = 2

    # 2단계: 항목별 파싱
    current_entry = None
    hex_lines = []

    for line in lines:
        parts = line.split()
        if not parts:
            continue

        # 구분선 스킵
        if all(c in '-\t ' for c in line):
            continue

        # 헤더 행 스킵
        if "PID" in parts and "ImageFileName" in line:
            continue

        # 새 항목 시작 감지 (PID가 숫자인 행)
        is_new_entry = False
        if len(parts) > max(pid_col, name_col or 0):
            try:
                int(parts[pid_col])
                is_new_entry = True
            except (ValueError, IndexError):
                pass

        if is_new_entry:
            # 이전 항목 처리
            if current_entry and hex_lines:
                finding = _analyze_malfind_entry(
                    current_entry, hex_lines, shellcode_patterns, WHITELIST
                )
                if finding == "FILTERED":
                    filtered_count += 1
                elif finding:
                    findings.append(finding)

            # 새 항목 시작
            try:
                pid = int(parts[pid_col])
                process = parts[name_col] if name_col is not None and name_col < len(parts) else "Unknown"
                address = parts[addr_col] if addr_col is not None and addr_col < len(parts) else "0x0"
            except (IndexError, ValueError):
                pid = 0
                process = "Unknown"
                address = "0x0"

            current_entry = {
                "pid": pid,
                "process": process,
                "address": address
            }
            hex_lines = []
        else:
            # hex 데이터 행 수집
            hex_lines.append(line)

    # 마지막 항목 처리
    if current_entry and hex_lines:
        finding = _analyze_malfind_entry(
            current_entry, hex_lines, shellcode_patterns, WHITELIST
        )
        if finding == "FILTERED":
            filtered_count += 1
        elif finding:
            findings.append(finding)

    if filtered_count > 0:
        print(f"  [i] 화이트리스트 필터링: {filtered_count}건 제외")

    print(f"  [✓] 코드 인젝션: {len(findings)}건")
    return findings


def _analyze_malfind_entry(entry, hex_lines, shellcode_patterns, whitelist):
    """malfind 단일 항목 분석 (내부 헬퍼)"""
    pid = entry["pid"]
    process = entry["process"]
    address = entry["address"]

    # 화이트리스트 체크
    proc_lower = process.lower()
    for safe in whitelist:
        if safe.lower() in proc_lower:
            return "FILTERED"

    # hex 데이터 합치기
    hex_data = ""
    for hl in hex_lines:
        parts = hl.split()
        for p in parts:
            if re.match(r'^[0-9a-fA-F]{2}$', p):
                hex_data += p + " "

    hex_data = hex_data.strip().lower()

    if not hex_data:
        return None

    # 쉘코드 패턴 매칭
    score = 0
    reasons = []

    for pattern, desc, pts in shellcode_patterns:
        if re.search(pattern, hex_data, re.IGNORECASE):
            score += pts
            reasons.append(desc)

    if score >= 30:
        severity = "CRITICAL" if score >= 80 else "HIGH" if score >= 50 else "MEDIUM"
        return Finding(
            category="코드 인젝션",
            severity=severity,
            title=f"코드 인젝션 의심: {process}",
            detail=f"PID={pid}, 주소={address}, 점수={score}",
            evidence=f"사유: {', '.join(reasons)}\nHex(앞 100자): {hex_data[:100]}"
        )

    return None

def detect_suspicious_network(report):
    """의심 네트워크 연결 탐지"""
    netscan_output = report.raw_outputs.get("netscan", "")
    if not netscan_output:
        print("  [!] netscan 결과가 없습니다.")
        return []

    PRIVATE_RANGES = [
        (r'^10\.', 'RFC1918'),
        (r'^172\.(1[6-9]|2[0-9]|3[01])\.', 'RFC1918'),
        (r'^192\.168\.', 'RFC1918'),
        (r'^127\.', 'Loopback'),
        (r'^0\.0\.0\.0', 'Any'),
        (r'^\*:', 'Wildcard'),
        (r'^::',  'IPv6 Loopback/Any'),
    ]

    SUSPICIOUS_PORTS = {
        4444: ("Metasploit 기본 포트", "CRITICAL"),
        5555: ("RAT 통신 포트", "HIGH"),
        1234: ("일반 백도어 포트", "HIGH"),
        6666: ("IRC/RAT 포트", "HIGH"),
        6667: ("IRC C2 포트", "HIGH"),
        8888: ("대체 C2 포트", "MEDIUM"),
        9999: ("대체 C2 포트", "MEDIUM"),
        31337: ("Back Orifice 포트", "CRITICAL"),
        12345: ("NetBus 포트", "CRITICAL"),
        20000: ("RAT 포트", "HIGH"),
        1337: ("해커 포트", "HIGH"),
        7777: ("RAT 포트", "HIGH"),
        3389: ("RDP", "MEDIUM"),
        5900: ("VNC", "MEDIUM"),
        5901: ("VNC", "MEDIUM"),
        22: ("SSH", "LOW"),
        23: ("Telnet", "MEDIUM"),
        445: ("SMB", "MEDIUM"),
        135: ("RPC", "MEDIUM"),
        139: ("NetBIOS", "MEDIUM"),
    }

    SAFE_PROCESSES = [
        "svchost.exe", "system", "lsass.exe",
        "services.exe", "dns.exe", "dnsache.exe",
        "msedge.exe", "chrome.exe", "firefox.exe",
        "teams.exe", "outlook.exe", "onedrive.exe",
        "searchapp.exe", "microsoftedgeupdate.exe",
    ]

    rows = parse_vol_output(netscan_output)
    findings = []

    for row in rows:
        # 프로세스 추출
        process = (row.get("Owner") or row.get("Process")
                   or row.get("ImageFileName") or "Unknown").strip()

        # PID 추출
        pid_str = row.get("PID") or row.get("Pid") or row.get("pid") or ""
        try:
            pid = int(pid_str)
        except ValueError:
            pid = 0

        # 상태 추출
        state = (row.get("State") or row.get("Status") or "").strip().upper()

        # 외부 주소 추출
        foreign = (row.get("ForeignAddr") or row.get("Foreign Address")
                   or row.get("RemoteAddr") or "").strip()

        # 로컬 주소 추출
        local = (row.get("LocalAddr") or row.get("Local Address")
                 or row.get("Offset") or "").strip()

        if not foreign:
            continue

        # 외부 IP와 포트 분리
        foreign_ip = ""
        foreign_port = 0
        try:
            if ":" in foreign:
                parts = foreign.rsplit(":", 1)
                foreign_ip = parts[0]
                foreign_port = int(parts[1])
        except (ValueError, IndexError):
            foreign_ip = foreign
            foreign_port = 0

        # 사설 IP 체크
        is_private = False
        for pattern, _ in PRIVATE_RANGES:
            if re.match(pattern, foreign_ip):
                is_private = True
                break

        if is_private:
            continue

        # 안전 프로세스 체크
        proc_lower = process.lower()
        is_safe = False
        for sp in SAFE_PROCESSES:
            if sp.lower() in proc_lower:
                is_safe = True
                break

        # 1) 의심 포트 체크
        if foreign_port in SUSPICIOUS_PORTS:
            desc, severity = SUSPICIOUS_PORTS[foreign_port]
            findings.append(Finding(
                category="네트워크",
                severity=severity,
                title=f"의심 포트 연결: {process}→{foreign}",
                detail=f"PID={pid}, 상태={state}, 포트설명={desc}",
                evidence=f"로컬={local}, 외부={foreign}"
            ))
            continue

        # 2) ESTABLISHED 외부 연결 (안전 프로세스 제외)
        if "ESTABLISHED" in state and not is_safe:
            findings.append(Finding(
                category="네트워크",
                severity="MEDIUM",
                title=f"외부 연결: {process}→{foreign_ip}",
                detail=f"PID={pid}, 상태={state}, 포트={foreign_port}",
                evidence=f"로컬={local}, 외부={foreign}"
            ))
            continue

        # 3) 비표준 높은 포트 LISTENING
        if "LISTEN" in state and foreign_port > 10000 and not is_safe:
            findings.append(Finding(
                category="네트워크",
                severity="MEDIUM",
                title=f"비표준 포트 리스닝: {process}:{foreign_port}",
                detail=f"PID={pid}, 상태={state}",
                evidence=f"로컬={local}, 외부={foreign}"
            ))

    return findings


def detect_suspicious_processes(report):
    """의심 프로세스 탐지"""
    pslist_output = report.raw_outputs.get("pslist", "")
    if not pslist_output:
        print("  [!] pslist 결과가 없습니다.")
        return []

    SUSPICIOUS_NAMES = [
        (r'mimikatz', '자격증명 탈취 도구', 'CRITICAL', 100),
        (r'lazagne', '패스워드 탈취 도구', 'CRITICAL', 100),
        (r'procdump', '프로세스 덤프 도구', 'HIGH', 70),
        (r'psexec', '원격 실행 도구', 'HIGH', 80),
        (r'cobaltstrike', 'CobaltStrike 비콘', 'CRITICAL', 100),
        (r'beacon', '비콘 (C2)', 'HIGH', 70),
        (r'meterpreter', 'Metasploit 페이로드', 'CRITICAL', 100),
        (r'nc\.exe', 'Netcat', 'HIGH', 80),
        (r'ncat', 'Ncat', 'HIGH', 80),
        (r'netcat', 'Netcat', 'HIGH', 80),
        (r'pwdump', '패스워드 덤프', 'CRITICAL', 90),
        (r'wce\.exe', 'Windows Credential Editor', 'CRITICAL', 90),
        (r'gsecdump', '자격증명 덤프', 'CRITICAL', 90),
        (r'sekurlsa', 'LSASS 메모리 덤프', 'CRITICAL', 100),
        (r'rubeus', 'Kerberos 공격 도구', 'CRITICAL', 100),
        (r'sharphound', 'BloodHound 수집기', 'CRITICAL', 90),
        (r'bloodhound', 'AD 정찰 도구', 'HIGH', 80),
        (r'certutil', '인증서 유틸리티 (다운로드 악용)', 'MEDIUM', 40),
        (r'bitsadmin', 'BITS 다운로드 악용', 'MEDIUM', 40),
        (r'mshta', 'HTA 스크립트 실행', 'MEDIUM', 50),
        (r'wscript', 'Windows Script Host', 'MEDIUM', 30),
        (r'cscript', 'Console Script Host', 'MEDIUM', 30),
        (r'regsvr32', 'DLL 등록 (악용 가능)', 'MEDIUM', 40),
        (r'rundll32', 'DLL 실행 (악용 가능)', 'LOW', 20),
        (r'msiexec', 'MSI 설치 (악용 가능)', 'MEDIUM', 30),
        (r'payload', '페이로드 키워드', 'HIGH', 70),
        (r'shell\.exe', '쉘 키워드', 'HIGH', 60),
        (r'reverse', '리버스 쉘 키워드', 'HIGH', 70),
        (r'bind\.exe', '바인드 쉘 키워드', 'HIGH', 60),
        (r'inject', '인젝션 키워드', 'HIGH', 60),
        (r'keylog', '키로거 키워드', 'CRITICAL', 90),
        (r'ransom', '랜섬웨어 키워드', 'CRITICAL', 100),
        (r'crypt', '암호화 키워드 (랜섬)', 'HIGH', 50),
        (r'miner', '암호화폐 채굴', 'HIGH', 70),
        (r'xmrig', 'XMRig 채굴', 'HIGH', 80),
    ]

    SAFE_PROCESSES = [
        "system", "registry", "smss.exe", "csrss.exe",
        "wininit.exe", "services.exe", "svchost.exe",
        "lsass.exe", "winlogon.exe", "explorer.exe",
        "dwm.exe", "taskhostw.exe", "sihost.exe",
        "fontdrvhost.exe", "spoolsv.exe", "lsaiso.exe",
        "dllhost.exe", "conhost.exe", "ctfmon.exe",
        "searchindexer.exe", "searchhost.exe",
        "runtimebroker.exe", "shellexperiencehost.exe",
        "startmenuexperiencehost.exe", "textinputhost.exe",
        "securityhealthservice.exe", "securityhealthsystray.exe",
        "sgrmbroker.exe", "memorystatus.exe",
        "applicationframehost.exe", "systemsettings.exe",
        "lockapp.exe", "wmiprvse.exe", "wmiapsrv.exe",
        "taskmgr.exe", "mmc.exe", "notepad.exe",
        "msedge.exe", "chrome.exe", "firefox.exe",
        "onedrive.exe", "teams.exe", "outlook.exe",
    ]

    rows = parse_vol_output(pslist_output)
    findings = []

    for row in rows:
        # PID 추출 (다양한 컬럼명 대응)
        pid_str = row.get("PID") or row.get("Pid") or row.get("pid") or ""
        try:
            pid = int(pid_str)
        except ValueError:
            continue

        # 프로세스명 추출
        process = (row.get("ImageFileName") or row.get("Name")
                   or row.get("Process") or "Unknown").strip()

        # PPID 추출
        ppid = row.get("PPID") or row.get("PPid") or row.get("ppid") or "?"

        process_lower = process.lower()

        if process_lower in SAFE_PROCESSES:
            continue

        for pattern, desc, severity, score in SUSPICIOUS_NAMES:
            if re.search(pattern, process_lower, re.IGNORECASE):
                findings.append(Finding(
                    category="프로세스",
                    severity=severity,
                    title=f"의심 프로세스: {process}",
                    detail=f"PID={pid}, PPID={ppid}",
                    evidence=f"매칭: {desc} (점수: {score})"
                ))
                break

    return findings


def detect_suspicious_callbacks(report):
    """의심 콜백 탐지"""
    callbacks_output = report.raw_outputs.get("callbacks", "")
    if not callbacks_output:
        print("  [!] callbacks 결과가 없습니다.")
        return []

    KNOWN_MODULES = [
        "ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe",
        "hal.dll", "ndis.sys", "tcpip.sys", "fltmgr.sys",
        "ci.dll", "ksecdd.sys", "cng.sys", "wdf01000.sys",
        "wd", "defender", "kaspersky", "avast", "avg",
        "symantec", "mcafee", "eset", "bitdefender",
        "classpnp.sys", "volsnap.sys", "iorate.sys",
        "storport.sys", "ntfs.sys", "fwpkclnt.sys",
        "tm.sys", "clfs.sys", "clipsp.sys",
    ]

    rows = parse_vol_output(callbacks_output)
    findings = []

    for row in rows:
        # 모듈명 추출
        module = (row.get("Module") or row.get("Driver")
                  or row.get("Owner") or row.get("Detail") or "").strip()

        if not module:
            continue

        module_lower = module.lower()

        # 알려진 모듈 체크
        is_known = False
        for km in KNOWN_MODULES:
            if km.lower() in module_lower:
                is_known = True
                break

        if is_known:
            continue

        # 콜백 타입 추출
        cb_type = (row.get("Type") or row.get("Callback")
                   or row.get("CallbackType") or "Unknown").strip()

        # 주소 추출
        address = (row.get("Callback") or row.get("Address")
                   or row.get("Offset") or "").strip()

        findings.append(Finding(
            category="콜백",
            severity="HIGH",
            title=f"비신뢰 모듈 콜백: {module}",
            detail=f"콜백 타입: {cb_type}, 주소: {address}",
            evidence=f"모듈: {module}"
        ))

    return findings

def detect_suspicious_cmdline(report):
    """의심 커맨드라인 탐지"""
    cmdline_output = report.raw_outputs.get("cmdline", "")
    if not cmdline_output:
        print("  [!] cmdline 결과가 없습니다.")
        return []

    SUSPICIOUS_PATTERNS = [
        (r'powershell.*-enc', 'PowerShell 인코딩 실행', 80),
        (r'powershell.*-e\s', 'PowerShell 인코딩 실행 (약어)', 80),
        (r'powershell.*-nop', 'PowerShell NoProfile', 60),
        (r'powershell.*-w\s+hidden', 'PowerShell Hidden', 70),
        (r'powershell.*downloadstring', 'PowerShell 다운로드', 90),
        (r'powershell.*iex', 'PowerShell IEX 실행', 85),
        (r'cmd.*/c.*powershell', 'CMD→PowerShell 체인', 75),
        (r'certutil.*-urlcache', 'Certutil 다운로드', 90),
        (r'bitsadmin.*transfer', 'BitsAdmin 다운로드', 85),
        (r'mshta.*http', 'MSHTA 원격 실행', 90),
        (r'regsvr32.*/s.*/u.*scrobj', 'Regsvr32 스크립틀릿', 90),
        (r'rundll32.*javascript', 'Rundll32 JS 실행', 90),
        (r'wmic.*process.*call.*create', 'WMIC 원격 실행', 80),
        (r'schtasks.*/create', '예약 작업 생성', 50),
        (r'net\s+user.*\/add', '사용자 추가', 70),
        (r'base64', 'Base64 문자열 포함', 40),
        (r'invoke-', 'PowerShell Invoke 호출', 60),
        (r'\.ps1', 'PowerShell 스크립트 실행', 40),
        (r'bypass', '보안 우회 키워드', 50),
    ]

    rows = parse_vol_output(cmdline_output)
    findings = []

    for row in rows:
        # PID 추출
        pid_str = row.get("PID") or row.get("Pid") or row.get("pid") or ""
        try:
            pid = int(pid_str)
        except ValueError:
            continue

        # 프로세스명 추출
        process = (row.get("ImageFileName") or row.get("Name")
                   or row.get("Process") or "Unknown").strip()

        # 커맨드라인 추출
        cmdline = (row.get("Args") or row.get("CmdLine")
                   or row.get("CommandLine") or row.get("Cmdline") or "").strip()

        if not cmdline:
            continue

        score = 0
        reasons = []

        for pattern, desc, pts in SUSPICIOUS_PATTERNS:
            if re.search(pattern, cmdline, re.IGNORECASE):
                score += pts
                reasons.append(desc)

        if score >= 40:
            severity = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM"
            findings.append(Finding(
                category="커맨드라인",
                severity=severity,
                title=f"의심 명령어: {process}",
                detail=f"PID={pid}, 점수={score}",
                evidence=f"사유: {', '.join(reasons)}\n명령어: {cmdline[:500]}"
            ))

    return findings

def detect_suspicious_dlls(report):
    """의심 DLL 탐지"""
    dlllist_output = report.raw_outputs.get("dlllist", "")
    if not dlllist_output:
        print("  [!] dlllist 결과가 없습니다.")
        return []

    SUSPICIOUS_DLL_PATTERNS = [
        (r'\\temp\\', 'Temp 폴더에서 로드된 DLL', 60),
        (r'\\tmp\\', 'Tmp 폴더에서 로드된 DLL', 60),
        (r'\\appdata\\local\\temp', 'AppData Temp에서 로드', 50),
        (r'\\downloads\\', 'Downloads 폴더에서 로드', 40),
        (r'\\desktop\\', 'Desktop에서 로드', 50),
        (r'\\users\\public\\', 'Public 폴더에서 로드', 60),
        (r'\\programdata\\', 'ProgramData에서 로드', 30),
        (r'[a-z]{1}\.dll$', '한 글자 DLL 이름', 70),
        (r'[a-f0-9]{8,}\.dll', '랜덤 해시명 DLL', 50),
    ]

    SAFE_PATHS = [
        "\\windows\\system32\\",
        "\\windows\\syswow64\\",
        "\\windows\\winsxs\\",
        "\\program files\\",
        "\\program files (x86)\\",
        "\\windows\\assembly\\",
        "\\windows\\microsoft.net\\",
    ]

    rows = parse_vol_output(dlllist_output)
    findings = []

    for row in rows:
        # PID 추출
        pid_str = row.get("PID") or row.get("Pid") or row.get("pid") or ""
        try:
            pid = int(pid_str)
        except ValueError:
            continue

        # 프로세스명 추출
        process = (row.get("ImageFileName") or row.get("Name")
                   or row.get("Process") or "Unknown").strip()

        # DLL 경로 추출
        dll_path = (row.get("Path") or row.get("MappedPath")
                    or row.get("FullDllName") or row.get("Name") or "").strip()

        if not dll_path:
            continue

        dll_lower = dll_path.lower()

        # 안전 경로 체크
        is_safe = False
        for sp in SAFE_PATHS:
            if sp in dll_lower:
                is_safe = True
                break

        if is_safe:
            continue

        score = 0
        reasons = []

        for pattern, desc, pts in SUSPICIOUS_DLL_PATTERNS:
            if re.search(pattern, dll_lower, re.IGNORECASE):
                score += pts
                reasons.append(desc)

        # 비표준 확장자 체크
        if not is_safe and score == 0:
            known_ext = dll_lower.endswith('.dll') or dll_lower.endswith('.drv')
            if not known_ext:
                score += 30
                reasons.append("비표준 확장자")

        if score >= 40:
            severity = "HIGH" if score >= 60 else "MEDIUM"
            dll_name = row_path_name(dll_path)
            findings.append(Finding(
                category="DLL",
                severity=severity,
                title=f"의심 DLL 로드: {dll_name}",
                detail=f"PID={pid}, 프로세스={process}",
                evidence=f"사유: {', '.join(reasons)}\n경로: {dll_path}"
            ))

    return findings


def detect_suspicious_handles(report):
    """의심 핸들(뮤텍스) 탐지"""
    handles_output = report.raw_outputs.get("handles", "")
    if not handles_output:
        print("  [!] handles 결과가 없습니다.")
        return []

    SUSPICIOUS_MUTEX = [
        (r'dc_mutex', 'DarkComet RAT', 'CRITICAL'),
        (r'darkcomet', 'DarkComet RAT', 'CRITICAL'),
        (r'poison', 'PoisonIvy RAT', 'CRITICAL'),
        (r'njrat', 'njRAT', 'CRITICAL'),
        (r'nj_mutex', 'njRAT', 'CRITICAL'),
        (r'asyncmutex', 'AsyncRAT', 'CRITICAL'),
        (r'async_mutex', 'AsyncRAT', 'CRITICAL'),
        (r'quasar', 'QuasarRAT', 'CRITICAL'),
        (r'remcos', 'Remcos RAT', 'CRITICAL'),
        (r'warzone', 'WarzoneRAT', 'CRITICAL'),
        (r'nanocore', 'NanoCore RAT', 'CRITICAL'),
        (r'orcus', 'Orcus RAT', 'CRITICAL'),
        (r'plugx', 'PlugX', 'CRITICAL'),
        (r'cobalt', 'CobaltStrike', 'CRITICAL'),
        (r'meterpreter', 'Metasploit', 'CRITICAL'),
        (r'empire', 'Empire C2', 'HIGH'),
        (r'havoc', 'Havoc C2', 'CRITICAL'),
        (r'sliver', 'Sliver C2', 'CRITICAL'),
        (r'[a-f0-9]{32}', '해시형 뮤텍스 (의심)', 'MEDIUM'),
    ]

    rows = parse_vol_output(handles_output)
    findings = []

    for row in rows:
        # 타입 확인 - Mutant/Mutex만 필터링
        handle_type = (row.get("Type") or row.get("type") or "").strip().lower()
        if "mutant" not in handle_type and "mutex" not in handle_type:
            continue

        # PID 추출
        pid_str = row.get("PID") or row.get("Pid") or row.get("pid") or ""
        try:
            pid = int(pid_str)
        except ValueError:
            continue

        # 프로세스명 추출
        process = (row.get("ImageFileName") or row.get("Name")
                   or row.get("Process") or "Unknown").strip()

        # 핸들 이름 추출
        handle_name = (row.get("HandleValue") or row.get("Details")
                       or row.get("Name") or "").strip()

        if not handle_name:
            continue

        handle_lower = handle_name.lower()

        for pattern, desc, severity in SUSPICIOUS_MUTEX:
            if re.search(pattern, handle_lower, re.IGNORECASE):
                findings.append(Finding(
                    category="핸들/뮤텍스",
                    severity=severity,
                    title=f"악성 뮤텍스 탐지: {desc}",
                    detail=f"PID={pid}, 프로세스={process}",
                    evidence=f"뮤텍스: {handle_name}"
                ))
                break

    return findings

# =====================================================================
# 추가 탐지 함수 (7단계)
# =====================================================================

def detect_ssdt_hooks(report):
    ssdt_output = report.raw_outputs.get("ssdt", "")
    if not ssdt_output: return []

    # 윈도우 정상 커널 및 그래픽 모듈 기본 화이트리스트
    KNOWN_KERNEL_MODULES = ["ntoskrnl", "win32k", "hal.dll", "ntkrnlmp"]
    findings = []

    for line in ssdt_output.strip().split('\n'):
        if not line.strip() or "Address" in line or "Volatility" in line:
            continue  # 헤더 및 가비지 라인 패스

        parts = line.split()
        if len(parts) < 4: continue

        # Volatility 3 출력 구조: Index | Address | Module | Symbol
        module = parts[2].lower().strip()
        symbol = parts[3] if len(parts) > 3 else "Unknown"

        # 정상 모듈에 포함되지 않는 경우만 진짜 후킹(위협)으로 판단
        is_safe = any(km in module for km in KNOWN_KERNEL_MODULES)
        if not is_safe and not module.startswith('-'):
            findings.append(Finding(
                category="SSDT 후킹", severity="CRITICAL",
                title=f"비정상 SSDT 후킹 탐지: {module} ({symbol})",
                detail=f"정상 커널 영역 외부의 모듈이 시스템 콜 변조",
                evidence=line.strip()
            ))
    return findings


def detect_suspicious_services(report):
    svcscan_output = report.raw_outputs.get("svcscan", "")
    if not svcscan_output: return []

    findings = []
    
    path_regex = re.compile(r'[a-zA-Z]:\\(?!windows\\system32\\)[^"\t\n\r]+\.(?:exe|sys)', re.IGNORECASE)

    for line in svcscan_output.strip().split('\n'):
        if not line.strip() or "SERVICE_" in line: 
            continue 

        # 줄바꿈 및 데이터가 섞여 있는 BinaryPath 검증
        match = path_regex.search(line)
        if match:
            suspicious_path = match.group(0)
            parts = line.split()
            # 서비스명 추출 시도
            svc_name = parts[1] if len(parts) > 1 else "Unknown"
            
            findings.append(Finding(
                category="서비스",
                severity="HIGH",
                title=f"비표준 경로 서비스 탐지: {svc_name}",
                detail=f"System32 외부 경로에서 실행되는 서비스 발견",
                evidence=f"경로: {suspicious_path} | 원본: {line.strip()[:150]}"
            ))
            
    return findings


def detect_suspicious_registry(report):
    combined_output = report.raw_outputs.get("printkey", "") + "\n" + report.raw_outputs.get("hivelist", "")
    if not combined_output.strip(): return []

    findings = []
    # 1차 필터링: 무조건 잡는 게 아니라 자동실행(Run) 레지스트리 경로 내의 값만 타겟팅
    persistence_regex = re.compile(r'(CurrentVersion\\Run|Winlogon\\Userinit|Image File Execution Options)', re.IGNORECASE)
    # 2차 필터링: 해당 키 내부의 값 중 악성 인자 조사
    malicious_value_regex = re.compile(r'(powershell.*-enc|cmd\.exe.*/c|mshta|eval|base64)', re.IGNORECASE)

    for line in combined_output.strip().split('\n'):
        if persistence_regex.search(line) and malicious_value_regex.search(line):
            findings.append(Finding(
                category="레지스트리", severity="CRITICAL",
                title="악성 자동실행 레지스트리 탐지",
                detail="지속성 확보를 위한 레지스트리 키 내 악성 명령어 발견",
                evidence=line.strip()
            ))
    return findings

# =====================================================================
# Linux 전용 탐지 함수들
# =====================================================================

def detect_linux_syscall_hooks(report):
    """Linux 시스템 콜 후킹 탐지"""
    output = report.raw_outputs.get("check_syscall", "")
    if not output:
        return []

    KNOWN_MODULES = ["kernel", "vmlinux", "[kernel]"]
    findings = []

    for line in output.strip().split('\n'):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < 3:
            continue

        # 마지막 컬럼이 모듈명인 경우가 많음
        module = parts[-1].lower().strip()

        is_known = any(km in module for km in KNOWN_MODULES)
        if not is_known and module and not module.startswith('-'):
            # "HOOKED" 키워드가 있으면 확실
            if "hooked" in line.lower():
                severity = "CRITICAL"
            else:
                severity = "HIGH"

            findings.append(Finding(
                category="시스템 콜 후킹",
                severity=severity,
                title=f"시스템 콜 후킹 탐지: {module}",
                detail="비정상 모듈이 시스템 콜을 후킹하고 있습니다.",
                evidence=f"원본: {line.strip()[:300]}"
            ))

    return findings


def detect_linux_hidden_modules(report):
    """Linux 은닉 커널 모듈 탐지"""
    output = report.raw_outputs.get("check_modules", "")
    if not output:
        return []

    findings = []

    for line in output.strip().split('\n'):
        if not line.strip():
            continue

        line_lower = line.lower()

        # "False" 또는 "not in" 등 불일치 표시가 있으면 은닉 모듈
        if any(kw in line_lower for kw in ["false", "not found", "hidden", "suspicious"]):
            parts = line.split()
            module_name = parts[0] if parts else "Unknown"

            findings.append(Finding(
                category="은닉 커널 모듈",
                severity="CRITICAL",
                title=f"은닉 커널 모듈 탐지: {module_name}",
                detail="sysfs와 모듈 리스트 간 불일치가 감지되었습니다.",
                evidence=f"원본: {line.strip()[:300]}"
            ))

    return findings


def detect_linux_idt_hooks(report):
    """Linux IDT (인터럽트 디스크립터 테이블) 후킹 탐지"""
    output = report.raw_outputs.get("check_idt", "")
    if not output:
        return []

    KNOWN_MODULES = ["kernel", "vmlinux", "[kernel]", "apic"]
    findings = []

    for line in output.strip().split('\n'):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < 3:
            continue

        module = parts[-1].lower().strip()

        is_known = any(km in module for km in KNOWN_MODULES)
        if not is_known and module and not module.startswith('-'):
            findings.append(Finding(
                category="IDT 후킹",
                severity="CRITICAL",
                title=f"IDT 후킹 탐지: {module}",
                detail="비정상 모듈이 인터럽트 핸들러를 후킹하고 있습니다.",
                evidence=f"원본: {line.strip()[:300]}"
            ))

    return findings


def detect_linux_afinfo_hooks(report):
    """Linux 네트워크 프로토콜 함수 후킹 탐지"""
    output = report.raw_outputs.get("check_afinfo", "")
    if not output:
        return []

    KNOWN_MODULES = ["kernel", "vmlinux", "[kernel]", "nf_", "ip_tables", "iptable_"]
    findings = []

    for line in output.strip().split('\n'):
        if not line.strip():
            continue

        line_lower = line.lower()

        # "HOOKED" 또는 비정상 모듈 표시
        if "hooked" in line_lower:
            findings.append(Finding(
                category="네트워크 후킹",
                severity="CRITICAL",
                title="네트워크 프로토콜 함수 후킹 탐지",
                detail="af_info 구조체가 변조되었습니다.",
                evidence=f"원본: {line.strip()[:300]}"
            ))
            continue

        parts = line.split()
        if len(parts) >= 3:
            module = parts[-1].lower().strip()
            is_known = any(km in module for km in KNOWN_MODULES)
            if not is_known and module and not module.startswith('-'):
                findings.append(Finding(
                    category="네트워크 후킹",
                    severity="HIGH",
                    title=f"의심 네트워크 함수 모듈: {module}",
                    detail="비정상 모듈이 네트워크 함수를 후킹하고 있습니다.",
                    evidence=f"원본: {line.strip()[:300]}"
                ))

    return findings


def detect_linux_suspicious_sockets(report):
    """Linux 의심 소켓 연결 탐지"""
    output = report.raw_outputs.get("sockstat", "")
    if not output:
        return []

    SUSPICIOUS_PORTS = {
        4444: ("Metasploit 기본 포트", "CRITICAL"),
        5555: ("RAT 통신 포트", "HIGH"),
        1234: ("백도어 포트", "HIGH"),
        6666: ("IRC/RAT 포트", "HIGH"),
        6667: ("IRC C2 포트", "HIGH"),
        31337: ("Back Orifice 포트", "CRITICAL"),
        12345: ("NetBus 포트", "CRITICAL"),
        1337: ("해커 포트", "HIGH"),
        7777: ("RAT 포트", "HIGH"),
        8888: ("대체 C2 포트", "MEDIUM"),
        9999: ("대체 C2 포트", "MEDIUM"),
        20000: ("RAT 포트", "HIGH"),
    }

    PRIVATE_RANGES = [
        r'^10\.',
        r'^172\.(1[6-9]|2[0-9]|3[01])\.',
        r'^192\.168\.',
        r'^127\.',
        r'^0\.0\.0\.0',
        r'^::',
    ]

    findings = []
    rows = parse_vol_output(output)

    for row in rows:
        # 프로세스 정보 추출
        process = (row.get("Name") or row.get("Process")
                   or row.get("Comm") or "Unknown").strip()
        pid_str = row.get("PID") or row.get("Pid") or row.get("pid") or ""
        try:
            pid = int(pid_str)
        except ValueError:
            pid = 0

        # 외부 주소 추출
        foreign = (row.get("ForeignAddr") or row.get("Remote")
                   or row.get("Peer") or "").strip()

        if not foreign:
            continue

        # IP와 포트 분리
        foreign_ip = ""
        foreign_port = 0
        try:
            if ":" in foreign:
                parts = foreign.rsplit(":", 1)
                foreign_ip = parts[0]
                foreign_port = int(parts[1])
        except (ValueError, IndexError):
            foreign_ip = foreign
            foreign_port = 0

        # 사설 IP 스킵
        is_private = any(re.match(p, foreign_ip) for p in PRIVATE_RANGES)
        if is_private:
            continue

        # 의심 포트 체크
        if foreign_port in SUSPICIOUS_PORTS:
            desc, severity = SUSPICIOUS_PORTS[foreign_port]
            findings.append(Finding(
                category="Linux 네트워크",
                severity=severity,
                title=f"의심 포트 연결: {process}→{foreign}",
                detail=f"PID={pid}, 포트설명={desc}",
                evidence=f"외부: {foreign}"
            ))
        elif foreign_port > 10000 and foreign_ip:
            findings.append(Finding(
                category="Linux 네트워크",
                severity="MEDIUM",
                title=f"비표준 외부 연결: {process}→{foreign}",
                detail=f"PID={pid}, 포트={foreign_port}",
                evidence=f"외부: {foreign}"
            ))

    return findings


def detect_linux_suspicious_creds(report):
    """Linux 권한 상승 / 자격증명 이상 탐지"""
    output = report.raw_outputs.get("check_creds", "")
    if not output:
        return []

    findings = []
    rows = parse_vol_output(output)

    for row in rows:
        process = (row.get("Name") or row.get("Process")
                   or row.get("Comm") or "Unknown").strip()
        pid_str = row.get("PID") or row.get("Pid") or row.get("pid") or ""
        try:
            pid = int(pid_str)
        except ValueError:
            pid = 0

        # UID/GID 추출
        uid = row.get("UID") or row.get("uid") or ""
        gid = row.get("GID") or row.get("gid") or ""
        euid = row.get("EUID") or row.get("euid") or ""

        # root(0)로 실행 중인 비정상 프로세스 
        # UID와 EUID 불일치 (권한 상승 의심)
        if uid and euid and uid != euid:
            try:
                uid_int = int(uid)
                euid_int = int(euid)
                if euid_int == 0 and uid_int != 0:
                    findings.append(Finding(
                        category="권한 상승",
                        severity="CRITICAL",
                        title=f"권한 상승 의심: {process}",
                        detail=f"PID={pid}, UID={uid}→EUID={euid}",
                        evidence=f"일반 사용자(UID={uid})가 root 권한(EUID=0)으로 실행 중"
                    ))
                elif uid_int != euid_int:
                    findings.append(Finding(
                        category="권한 상승",
                        severity="HIGH",
                        title=f"UID/EUID 불일치: {process}",
                        detail=f"PID={pid}, UID={uid}, EUID={euid}",
                        evidence=f"UID와 EUID가 일치하지 않습니다."
                    ))
            except ValueError:
                pass

    return findings


def detect_linux_suspicious_bash(report):
    """Linux Bash 히스토리 의심 명령어 탐지"""
    output = report.raw_outputs.get("bash", "")
    if not output:
        return []

    SUSPICIOUS_PATTERNS = [
        (r'wget\s+http', '원격 파일 다운로드 (wget)', 60),
        (r'curl\s+.*http', '원격 파일 다운로드 (curl)', 60),
        (r'chmod\s+\+x', '실행 권한 부여', 40),
        (r'chmod\s+777', '전체 권한 부여 (777)', 70),
        (r'/dev/tcp/', 'Bash 리버스 쉘 시도', 90),
        (r'/dev/udp/', 'Bash UDP 연결', 80),
        (r'nc\s+-[elvnp]', 'Netcat 연결/리스닝', 80),
        (r'ncat\s', 'Ncat 연결', 70),
        (r'bash\s+-i', 'Bash 인터랙티브 쉘', 80),
        (r'python.*import\s+socket', 'Python 소켓 리버스 쉘', 90),
        (r'python.*pty\.spawn', 'Python PTY 스폰', 90),
        (r'perl.*socket', 'Perl 소켓 리버스 쉘', 90),
        (r'ruby.*socket', 'Ruby 소켓 리버스 쉘', 90),
        (r'php.*fsockopen', 'PHP 소켓 리버스 쉘', 90),
        (r'base64\s+-d', 'Base64 디코딩', 50),
        (r'echo\s.*\|\s*base64', 'Base64 인코딩 파이프', 60),
        (r'rm\s+-rf\s+/', '루트 삭제 시도', 100),
        (r'mkfifo', '명명된 파이프 생성 (리버스 쉘)', 80),
        (r'crontab\s+-e', '크론탭 수정', 40),
        (r'echo\s.*>>\s*/etc/crontab', '크론탭 직접 수정', 80),
        (r'useradd\s', '사용자 추가', 60),
        (r'usermod\s.*-aG.*sudo', 'sudo 그룹 추가', 80),
        (r'passwd\s', '패스워드 변경', 50),
        (r'ssh-keygen', 'SSH 키 생성', 40),
        (r'authorized_keys', 'SSH 인증 키 수정', 70),
        (r'iptables\s+-F', '방화벽 규칙 삭제', 70),
        (r'iptables\s+-P.*ACCEPT', '방화벽 전체 허용', 60),
        (r'history\s+-c', '히스토리 삭제', 80),
        (r'export\s+HISTSIZE=0', '히스토리 비활성화', 80),
        (r'unset\s+HISTFILE', '히스토리 파일 삭제', 80),
        (r'shred\s', '파일 영구 삭제', 70),
        (r'dd\s+if=/dev', 'DD 디스크 작업', 50),
        (r'/etc/shadow', 'Shadow 파일 접근', 80),
        (r'/etc/passwd', 'Passwd 파일 접근', 40),
        (r'insmod\s', '커널 모듈 삽입', 70),
        (r'rmmod\s', '커널 모듈 제거', 60),
        (r'modprobe\s', '커널 모듈 로드', 50),
    ]

    findings = []

    for line in output.strip().split('\n'):
        if not line.strip():
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        # PID 추출 시도
        pid = 0
        try:
            pid = int(parts[0])
        except ValueError:
            pass

        # 명령어 부분 추출 (PID 이후 전체)
        cmd = line.strip()

        score = 0
        reasons = []

        for pattern, desc, pts in SUSPICIOUS_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                score += pts
                reasons.append(desc)

        if score >= 40:
            severity = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM"
            findings.append(Finding(
                category="Bash 히스토리",
                severity=severity,
                title=f"의심 Bash 명령어 탐지",
                detail=f"PID={pid}, 점수={score}",
                evidence=f"사유: {', '.join(reasons)}\n명령어: {cmd[:500]}"
            ))

    return findings


def detect_linux_keyboard_hooks(report):
    """Linux 키보드 노티파이어 (키로거) 탐지"""
    output = report.raw_outputs.get("keyboard_notifiers", "")
    if not output:
        return []

    KNOWN_MODULES = [
        "kernel", "vmlinux", "[kernel]",
        "atkbd", "i8042", "input",
        "hid", "usbhid", "evdev",
        "xkb", "kbd",
    ]

    findings = []

    for line in output.strip().split('\n'):
        if not line.strip():
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        # 모듈명 추출 (마지막 컬럼)
        module = parts[-1].lower().strip()

        is_known = any(km in module for km in KNOWN_MODULES)

        if not is_known and module and not module.startswith('-'):
            # "hooked" 키워드 확인
            if "hooked" in line.lower():
                severity = "CRITICAL"
            else:
                severity = "HIGH"

            findings.append(Finding(
                category="키로거",
                severity=severity,
                title=f"키보드 후킹 탐지: {module}",
                detail="비정상 모듈이 키보드 입력을 가로채고 있습니다.",
                evidence=f"원본: {line.strip()[:300]}"
            ))

    return findings



# =====================================================================
# 보고서 생성
# =====================================================================

def generate_report(report):
    """최종 분석 보고서 생성"""

    report.end_time = datetime.now()
    elapsed = (report.end_time - report.start_time).total_seconds()

    separator = "=" * 70
    sub_sep = "-" * 70

    lines = []
    lines.append(separator)
    lines.append("  메모리 포렌식 자동 분석 보고서")
    lines.append(separator)
    lines.append(f"  분석 시작: {report.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  분석 종료: {report.end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  소요 시간: {elapsed:.1f}초")
    lines.append(f"  총 발견 사항: {len(report.findings)}건")
    lines.append(separator)

    # 심각도별 요약
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    severity_counts = {}
    for sev in severity_order:
        count = len([f for f in report.findings if f.severity == sev])
        severity_counts[sev] = count

    lines.append("\n[요약]")
    lines.append(sub_sep)
    for sev in severity_order:
        if severity_counts[sev] > 0:
            marker = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡" if sev == "MEDIUM" else "🔵" if sev == "LOW" else "⚪"
            lines.append(f"  {marker} {sev}: {severity_counts[sev]}건")
    lines.append(sub_sep)

    # 카테고리별 상세
    categories = {}
    for f in report.findings:
        if f.category not in categories:
            categories[f.category] = []
        categories[f.category].append(f)

    for cat, cat_findings in categories.items():
        lines.append(f"\n[{cat}] ({len(cat_findings)}건)")
        lines.append(sub_sep)

        # 심각도 높은 순 정렬
        cat_findings.sort(key=lambda x: severity_order.index(x.severity) if x.severity in severity_order else 99)

        for i, f in enumerate(cat_findings, 1):
            lines.append(f"  #{i} [{f.severity}] {f.title}")
            lines.append(f"     상세: {f.detail}")
            if f.evidence:
                ev_lines = f.evidence.split('\n')
                for ev in ev_lines:
                    lines.append(f"     증거: {ev}")
            lines.append("")

    lines.append(sub_sep)

    # 위험도 평가
    total_score = 0
    for f in report.findings:
        if f.severity == "CRITICAL":
            total_score += 100
        elif f.severity == "HIGH":
            total_score += 60
        elif f.severity == "MEDIUM":
            total_score += 30
        elif f.severity == "LOW":
            total_score += 10

    if total_score >= 500:
        risk_level = "매우 위험 (CRITICAL)"
        risk_emoji = "🔴"
    elif total_score >= 300:
        risk_level = "위험 (HIGH)"
        risk_emoji = "🟠"
    elif total_score >= 100:
        risk_level = "주의 (MEDIUM)"
        risk_emoji = "🟡"
    elif total_score > 0:
        risk_level = "낮음 (LOW)"
        risk_emoji = "🔵"
    else:
        risk_level = "정상 (CLEAN)"
        risk_emoji = "🟢"

    lines.append(f"\n[종합 위험도 평가]")
    lines.append(sub_sep)
    lines.append(f"  {risk_emoji} 위험도: {risk_level}")
    lines.append(f"  총점: {total_score}")
    lines.append(sub_sep)

    # 권고사항
    lines.append(f"\n[권고사항]")
    lines.append(sub_sep)

    if severity_counts.get("CRITICAL", 0) > 0:
        lines.append("  [!] CRITICAL 수준의 위협이 탐지되었습니다.")
        lines.append("      - 즉시 네트워크 격리를 권장합니다.")
        lines.append("      - 침해사고 대응 절차를 시작하십시오.")
        lines.append("      - 관련 프로세스의 전체 메모리 덤프를 확보하십시오.")
        lines.append("")

    if severity_counts.get("HIGH", 0) > 0:
        lines.append("  [!] HIGH 수준의 위협이 탐지되었습니다.")
        lines.append("      - 해당 프로세스에 대한 추가 분석이 필요합니다.")
        lines.append("      - 바이러스 토탈 등 외부 위협 인텔리전스를 활용하십시오.")
        lines.append("      - 관련 파일의 해시를 확인하십시오.")
        lines.append("")

    if severity_counts.get("MEDIUM", 0) > 0:
        lines.append("  [!] MEDIUM 수준의 의심 활동이 탐지되었습니다.")
        lines.append("      - 정상 활동 여부를 확인하십시오.")
        lines.append("      - 운영 환경에 맞는 화이트리스트를 점검하십시오.")
        lines.append("")

    if total_score == 0:
        lines.append("  [✓] 현재 분석 결과 특이사항이 없습니다.")
        lines.append("      - 정기적인 모니터링을 유지하십시오.")
        lines.append("")

    lines.append(separator)
    lines.append("  분석 완료")
    lines.append(separator)

    report_text = '\n'.join(lines)

    # 파일 저장
    report_path = os.path.join(report.output_dir, "analysis_report.txt")
    try:
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_text)
        print(f"\n  [✓] 보고서 저장 완료: {report_path}")
    except Exception as e:
        print(f"\n  [✗] 보고서 저장 실패: {e}")

    # JSON 보고서도 함께 생성
    json_report = {
        "meta": {
            "start_time": report.start_time.strftime('%Y-%m-%d %H:%M:%S'),
            "end_time": report.end_time.strftime('%Y-%m-%d %H:%M:%S'),
            "elapsed_seconds": elapsed,
            "total_findings": len(report.findings),
            "risk_level": risk_level,
            "risk_score": total_score,
        },
        "summary": severity_counts,
        "findings": []
    }

    for f in report.findings:
        json_report["findings"].append({
            "category": f.category,
            "severity": f.severity,
            "title": f.title,
            "detail": f.detail,
            "evidence": f.evidence,
        })

    json_path = os.path.join(report.output_dir, "analysis_report.json")
    try:
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(json_report, f, ensure_ascii=False, indent=2)
        print(f"  [✓] JSON 보고서 저장 완료: {json_path}")
    except Exception as e:
        print(f"  [✗] JSON 보고서 저장 실패: {e}")

    # 콘솔 출력
    print("\n" + report_text)

    # 마크다운 보고서 생성
    md_lines = []
    md_lines.append(f"# 메모리 포렌식 분석 보고서")
    md_lines.append("")
    md_lines.append("## 기본 정보")
    md_lines.append("")
    md_lines.append(f"| 항목 | 값 |")
    md_lines.append(f"|------|-----|")
    md_lines.append(f"| 분석 대상 | `{report.memory_image}` |")
    md_lines.append(f"| 분석 시작 | {report.start_time.strftime('%Y-%m-%d %H:%M:%S')} |")
    md_lines.append(f"| 분석 종료 | {report.end_time.strftime('%Y-%m-%d %H:%M:%S')} |")
    md_lines.append(f"| 소요 시간 | {elapsed:.1f}초 |")
    md_lines.append(f"| 총 발견 사항 | {len(report.findings)}건 |")
    md_lines.append(f"| 종합 위험도 | {risk_emoji} {risk_level} (점수: {total_score}) |")
    md_lines.append("")

    # 심각도별 요약 테이블
    md_lines.append("## 심각도별 요약")
    md_lines.append("")
    md_lines.append("| 심각도 | 건수 |")
    md_lines.append("|--------|------|")
    for sev in severity_order:
        if severity_counts[sev] > 0:
            marker = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡" if sev == "MEDIUM" else "🔵" if sev == "LOW" else "⚪"
            md_lines.append(f"| {marker} {sev} | {severity_counts[sev]}건 |")
    md_lines.append("")

    # 카테고리별 상세
    for cat, cat_findings in categories.items():
        md_lines.append(f"## {cat} ({len(cat_findings)}건)")
        md_lines.append("")

        cat_findings_sorted = sorted(
            cat_findings,
            key=lambda x: severity_order.index(x.severity) if x.severity in severity_order else 99
        )

        for i, f in enumerate(cat_findings_sorted, 1):
            marker = "🔴" if f.severity == "CRITICAL" else "🟠" if f.severity == "HIGH" else "🟡" if f.severity == "MEDIUM" else "🔵" if f.severity == "LOW" else "⚪"
            md_lines.append(f"### {i}. {marker} [{f.severity}] {f.title}")
            md_lines.append("")
            md_lines.append(f"- **상세**: {f.detail}")
            if f.evidence:
                md_lines.append(f"- **증거**:")
                md_lines.append(f"```")
                md_lines.append(f"{f.evidence}")
                md_lines.append(f"```")
            md_lines.append("")

    # 권고사항
    md_lines.append("## 권고사항")
    md_lines.append("")
    if severity_counts.get("CRITICAL", 0) > 0:
        md_lines.append("- ⚠️ **CRITICAL 수준의 위협이 탐지되었습니다.**")
        md_lines.append("  - 즉시 네트워크 격리를 권장합니다.")
        md_lines.append("  - 침해사고 대응 절차를 시작하십시오.")
        md_lines.append("  - 관련 프로세스의 전체 메모리 덤프를 확보하십시오.")
        md_lines.append("")
    if severity_counts.get("HIGH", 0) > 0:
        md_lines.append("- ⚠️ **HIGH 수준의 위협이 탐지되었습니다.**")
        md_lines.append("  - 해당 프로세스에 대한 추가 분석이 필요합니다.")
        md_lines.append("  - 바이러스 토탈 등 외부 위협 인텔리전스를 활용하십시오.")
        md_lines.append("")
    if severity_counts.get("MEDIUM", 0) > 0:
        md_lines.append("- **MEDIUM 수준의 의심 활동이 탐지되었습니다.**")
        md_lines.append("  - 정상 활동 여부를 확인하십시오.")
        md_lines.append("  - 운영 환경에 맞는 화이트리스트를 점검하십시오.")
        md_lines.append("")
    if total_score == 0:
        md_lines.append("- ✅ **현재 분석 결과 특이사항이 없습니다.**")
        md_lines.append("  - 정기적인 모니터링을 유지하십시오.")
        md_lines.append("")

    md_lines.append("---")
    md_lines.append(f"*보고서 생성: {report.end_time.strftime('%Y-%m-%d %H:%M:%S')}*")

    md_text = '\n'.join(md_lines)

    # OS 이름 기반 파일명으로 저장
    # os_name은 main()에서 설정된 변수 → report에 저장해서 전달
    os_name_safe = getattr(report, 'os_name', 'Unknown_OS')
    # 파일명에 사용 불가 문자 제거
    os_name_safe = re.sub(r'[\\/:*?"<>|]', '_', os_name_safe)
    md_filename = f"{os_name_safe}.md"
    md_path = os.path.join(report.output_dir, md_filename)

    try:
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(md_text)
        print(f"  [✓] 마크다운 보고서 저장 완료: {md_path}")
    except Exception as e:
        print(f"  [✗] 마크다운 보고서 저장 실패: {e}")


    return report_text


# =====================================================================
# 메인 실행
# =====================================================================

def main():

    print("=" * 70)
    print("  메모리 포렌식 자동 분석 도구")
    print("  Memory Forensic Auto Analyzer")
    print("=" * 70)

    parser = argparse.ArgumentParser(
        description="Volatility 3 기반 메모리 포렌식 자동 분석 도구"
    )
    parser.add_argument(
        "memory_image",
        help="분석할 메모리 이미지 파일 경로"
    )
    parser.add_argument(
        "-o", "--output",
        default="forensic_output",
        help="결과 저장 디렉토리 (기본: forensic_output)"
    )
    parser.add_argument(
        "-v", "--volatility",
        default="vol",
        help="Volatility 3 실행 경로 (기본: vol)"
    )
    parser.add_argument(
        "--plugins",
        nargs='+',
        default=None,
        help="실행할 플러그인 목록 (기본: 전체)"
    )

    args = parser.parse_args()

    # 메모리 이미지 존재 확인
    if not os.path.isfile(args.memory_image):
        print(f"\n  [✗] 메모리 이미지를 찾을 수 없습니다: {args.memory_image}")
        sys.exit(1)

    # 출력 디렉토리 생성
    os.makedirs(args.output, exist_ok=True)
    # Volatility 경로 결정
    if args.volatility == "vol":
        print("\n  [→] Volatility 자동 감지 중...")
        version, vol_cmd = detect_volatility_version()
        if vol_cmd:
            args.volatility = vol_cmd
            print(f"  [✓] Volatility {version} 감지: {vol_cmd}")
        else:
            print("  [✗] Volatility를 자동 감지할 수 없습니다.")
            print("      -v 옵션으로 경로를 지정하십시오.")
            sys.exit(1)
    else:
        # 사용자 지정 경로 유효성 확인
        try:
            cmd_parts = args.volatility.split()
            result = subprocess.run(
                cmd_parts + ["-h"],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode != 0:
                print(f"\n  [✗] Volatility 실행 실패: {args.volatility}")
                sys.exit(1)
            print(f"\n  [✓] Volatility 확인 완료: {args.volatility}")
        except FileNotFoundError:
            print(f"\n  [✗] Volatility를 찾을 수 없습니다: {args.volatility}")
            sys.exit(1)
        except subprocess.TimeoutExpired:
            print(f"\n  [✗] Volatility 실행 시간 초과")
            sys.exit(1)

    # 전역 변수 설정
    global VOL_PATH, MEM_PATH
    VOL_PATH = args.volatility
    MEM_PATH = args.memory_image

    # 분석 보고서 초기화
    report = AnalysisReport()
    report.memory_image = args.memory_image
    report.output_dir = args.output
    report.start_time = datetime.now()

    print(f"\n  [→] 분석 대상: {args.memory_image}")
    print(f"  [→] 출력 디렉토리: {args.output}")
    print(f"  [→] 분석 시작 시간: {report.start_time.strftime('%Y-%m-%d %H:%M:%S')}")


    # =========================================
    # OS 자동 감지
    # =========================================
    print("\n  [→] OS 프로파일 자동 감지 중...")
    detected_os = "windows"  # 기본값

    os_info = run_volatility("windows.info")
    if os_info and os_info.strip() and "error" not in os_info.lower()[:200]:
        detected_os = "windows"
        print("  [✓] Windows 메모리 이미지 감지됨")
        # OS 이름 추출
        os_name = "Windows"
        for line in os_info.strip().split('\n'):
            if "NtMajorVersion" in line:
                parts = line.split()
                if len(parts) >= 2:
                    major = parts[-1]
                    os_name = f"Windows_{major}"
            if "NtBuildLab" in line or "19041" in line or "Build" in line:
                parts = line.split()
                if len(parts) >= 2:
                    os_name = f"Windows_Build_{parts[-1]}"
    else:
        os_info = run_volatility("linux.info")
        if os_info and os_info.strip() and "error" not in os_info.lower()[:200]:
            detected_os = "linux"
            print("  [✓] Linux 메모리 이미지 감지됨")
            os_name = "Linux"
            for line in os_info.strip().split('\n'):
                if "version" in line.lower() or "kernel" in line.lower():
                    parts = line.split()
                    if len(parts) >= 2:
                        os_name = f"Linux_{parts[-1]}"
                        break
        else:
            print("  [!] OS 감지 실패. Windows 기본값으로 진행합니다.")
            os_name = "Unknown_OS"

    # OS 정보를 보고서에 저장
    report.raw_outputs["os_info"] = os_info if os_info else ""
    report.os_name = os_name

    # =========================================
    # 1단계: Volatility 플러그인 실행
    # =========================================
    print("\n" + "=" * 70)
    print("  1단계: Volatility 플러그인 실행")
    print("=" * 70)

    if detected_os == "windows":
        DEFAULT_PLUGINS = [
            "windows.pslist.PsList",
            "windows.psscan.PsScan",
            "windows.pstree.PsTree",
            "windows.cmdline.CmdLine",
            "windows.netscan.NetScan",
            "windows.netstat.NetStat",
            "windows.dlllist.DllList",
            "windows.handles.Handles",
            "windows.callbacks.Callbacks",
            "windows.svcscan.SvcScan",
            "windows.malfind.Malfind",
            "windows.ssdt.SSDT",
            "windows.modules.Modules",
            "windows.driverscan.DriverScan",
            "windows.registry.hivelist.HiveList",
            "windows.registry.printkey.PrintKey",
        ]
        PLUGIN_KEY_MAP = {
            "windows.pslist.PsList": "pslist",
            "windows.psscan.PsScan": "psscan",
            "windows.pstree.PsTree": "pstree",
            "windows.cmdline.CmdLine": "cmdline",
            "windows.netscan.NetScan": "netscan",
            "windows.netstat.NetStat": "netstat",
            "windows.dlllist.DllList": "dlllist",
            "windows.handles.Handles": "handles",
            "windows.callbacks.Callbacks": "callbacks",
            "windows.svcscan.SvcScan": "svcscan",
            "windows.malfind.Malfind": "malfind",
            "windows.ssdt.SSDT": "ssdt",
            "windows.modules.Modules": "modules",
            "windows.driverscan.DriverScan": "driverscan",
            "windows.registry.hivelist.HiveList": "hivelist",
            "windows.registry.printkey.PrintKey": "printkey",
        }
    else:
        # 리눅스 플러그인
        DEFAULT_PLUGINS = [
            "linux.pslist.PsList",
            "linux.psscan.PsScan",
            "linux.bash.Bash",
            "linux.lsof.Lsof",
            "linux.malfind.Malfind",
            "linux.proc.Maps",
            "linux.check_afinfo.Check_afinfo",
            "linux.check_creds.Check_creds",
            "linux.check_idt.Check_idt",
            "linux.check_modules.Check_modules",
            "linux.check_syscall.Check_syscall",
            "linux.tty_check.tty_check",
            "linux.sockstat.Sockstat",
            "linux.mount.Mount",
            "linux.ifconfig.Ifconfig",
            "linux.keyboard_notifiers.Keyboard_notifiers",
        ]
        PLUGIN_KEY_MAP = {
            "linux.pslist.PsList": "pslist",
            "linux.psscan.PsScan": "psscan",
            "linux.bash.Bash": "bash",
            "linux.lsof.Lsof": "lsof",
            "linux.malfind.Malfind": "malfind",
            "linux.proc.Maps": "proc_maps",
            "linux.check_afinfo.Check_afinfo": "check_afinfo",
            "linux.check_creds.Check_creds": "check_creds",
            "linux.check_idt.Check_idt": "check_idt",
            "linux.check_modules.Check_modules": "check_modules",
            "linux.check_syscall.Check_syscall": "check_syscall",
            "linux.tty_check.tty_check": "tty_check",
            "linux.sockstat.Sockstat": "sockstat",
            "linux.mount.Mount": "mount",
            "linux.ifconfig.Ifconfig": "ifconfig",
            "linux.keyboard_notifiers.Keyboard_notifiers": "keyboard_notifiers",
        }

    plugins = args.plugins if args.plugins else DEFAULT_PLUGINS


     # 병렬 처리 워커 수 결정
    cpu_count = os.cpu_count() or 1
    max_workers = max(1, min(4, cpu_count - 1))
    print(f"\n  [i] CPU 코어: {cpu_count}개 / 병렬 작업: {max_workers}개")

    def _run_single_plugin(plugin):
        """단일 플러그인 실행 (병렬용)"""
        plugin_key = PLUGIN_KEY_MAP.get(plugin, plugin.split('.')[-1].lower())
        output = run_volatility(plugin)
        return plugin, plugin_key, output

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_run_single_plugin, p): p for p in plugins}
        for future in as_completed(futures):
            try:
                plugin, plugin_key, output = future.result()
                if output and output.strip():
                    report.raw_outputs[plugin_key] = output
                    output_file = os.path.join(args.output, f"{plugin_key}.txt")
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(output)
                    line_count = len(output.strip().split('\n'))
                    print(f"  [✓] {plugin}: {line_count}줄 수집 완료")
                else:
                    print(f"  [!] {plugin}: 결과 없음 또는 오류")
            except Exception as e:
                print(f"  [✗] {futures[future]} 오류: {e}")

    # =========================================
    # 2단계~7단계: 탐지 분석 수행
    # =========================================

    # === 공통 분석 (Windows + Linux 모두) ===
    print("\n" + "=" * 70)
    print("  2단계: 프로세스 분석")
    print("=" * 70)

    print("\n  [→] 은닉 프로세스 탐지 중...")
    hidden_findings = detect_hidden_processes(report)
    report.findings.extend(hidden_findings)
    print(f"  [✓] 은닉 프로세스 탐지: {len(hidden_findings)}건")

    print("\n  [→] 의심 프로세스 탐지 중...")
    proc_findings = detect_suspicious_processes(report)
    report.findings.extend(proc_findings)
    print(f"  [✓] 의심 프로세스 탐지: {len(proc_findings)}건")

    print("\n" + "=" * 70)
    print("  3단계: 코드 인젝션 분석")
    print("=" * 70)

    print("\n  [→] Malfind (코드 인젝션) 분석 중...")
    malfind_findings = detect_code_injection(report)
    report.findings.extend(malfind_findings)
    print(f"  [✓] Malfind 탐지: {len(malfind_findings)}건")

    # === Windows 전용 분석 ===
    if detected_os == "windows":

        print("\n" + "=" * 70)
        print("  4단계: 네트워크 분석")
        print("=" * 70)

        print("\n  [→] 의심 네트워크 연결 탐지 중...")
        net_findings = detect_suspicious_network(report)
        report.findings.extend(net_findings)
        print(f"  [✓] 의심 네트워크 탐지: {len(net_findings)}건")

        print("\n" + "=" * 70)
        print("  5단계: 커맨드라인 / DLL / 핸들 분석")
        print("=" * 70)

        print("\n  [→] 의심 커맨드라인 탐지 중...")
        cmd_findings = detect_suspicious_cmdline(report)
        report.findings.extend(cmd_findings)
        print(f"  [✓] 의심 커맨드라인 탐지: {len(cmd_findings)}건")

        print("\n  [→] 의심 DLL 탐지 중...")
        dll_findings = detect_suspicious_dlls(report)
        report.findings.extend(dll_findings)
        print(f"  [✓] 의심 DLL 탐지: {len(dll_findings)}건")

        print("\n  [→] 의심 핸들 탐지 중...")
        handle_findings = detect_suspicious_handles(report)
        report.findings.extend(handle_findings)
        print(f"  [✓] 의심 핸들 탐지: {len(handle_findings)}건")

        print("\n" + "=" * 70)
        print("  6단계: 콜백 / SSDT 분석")
        print("=" * 70)

        print("\n  [→] 의심 콜백 탐지 중...")
        cb_findings = detect_suspicious_callbacks(report)
        report.findings.extend(cb_findings)
        print(f"  [✓] 의심 콜백 탐지: {len(cb_findings)}건")

        print("\n  [→] SSDT (시스템콜 후킹) 분석 중...")
        ssdt_findings = detect_ssdt_hooks(report)
        report.findings.extend(ssdt_findings)
        print(f"  [✓] SSDT 후킹 탐지: {len(ssdt_findings)}건")

        print("\n" + "=" * 70)
        print("  7단계: 서비스 / 레지스트리 분석")
        print("=" * 70)

        print("\n  [→] 의심 서비스 분석 중...")
        svc_findings = detect_suspicious_services(report)
        report.findings.extend(svc_findings)
        print(f"  [✓] 의심 서비스 탐지: {len(svc_findings)}건")

        print("\n  [→] 의심 레지스트리 분석 중...")
        reg_findings = detect_suspicious_registry(report)
        report.findings.extend(reg_findings)
        print(f"  [✓] 의심 레지스트리 탐지: {len(reg_findings)}건")

    # === Linux 전용 분석 ===
    else:

        print("\n" + "=" * 70)
        print("  4단계: Linux 커널 무결성 분석")
        print("=" * 70)

        # check_syscall 결과 분석
        check_syscall_output = report.raw_outputs.get("check_syscall", "")
        if check_syscall_output:
            print("\n  [→] 시스템 콜 후킹 탐지 중...")
            syscall_findings = detect_linux_syscall_hooks(report)
            report.findings.extend(syscall_findings)
            print(f"  [✓] 시스템 콜 후킹 탐지: {len(syscall_findings)}건")
        else:
            print("\n  [!] check_syscall 결과 없음 — 건너뜀")

        # check_modules 결과 분석
        check_modules_output = report.raw_outputs.get("check_modules", "")
        if check_modules_output:
            print("\n  [→] 은닉 커널 모듈 탐지 중...")
            module_findings = detect_linux_hidden_modules(report)
            report.findings.extend(module_findings)
            print(f"  [✓] 은닉 커널 모듈 탐지: {len(module_findings)}건")
        else:
            print("\n  [!] check_modules 결과 없음 — 건너뜀")

        # check_idt 결과 분석
        check_idt_output = report.raw_outputs.get("check_idt", "")
        if check_idt_output:
            print("\n  [→] IDT 후킹 탐지 중...")
            idt_findings = detect_linux_idt_hooks(report)
            report.findings.extend(idt_findings)
            print(f"  [✓] IDT 후킹 탐지: {len(idt_findings)}건")
        else:
            print("\n  [!] check_idt 결과 없음 — 건너뜀")

        print("\n" + "=" * 70)
        print("  5단계: Linux 네트워크 / 자격증명 분석")
        print("=" * 70)

        # check_afinfo 결과 분석
        check_afinfo_output = report.raw_outputs.get("check_afinfo", "")
        if check_afinfo_output:
            print("\n  [→] 네트워크 함수 후킹 탐지 중...")
            afinfo_findings = detect_linux_afinfo_hooks(report)
            report.findings.extend(afinfo_findings)
            print(f"  [✓] 네트워크 함수 후킹 탐지: {len(afinfo_findings)}건")
        else:
            print("\n  [!] check_afinfo 결과 없음 — 건너뜀")

        # sockstat 결과 분석
        sockstat_output = report.raw_outputs.get("sockstat", "")
        if sockstat_output:
            print("\n  [→] 의심 소켓 연결 탐지 중...")
            sock_findings = detect_linux_suspicious_sockets(report)
            report.findings.extend(sock_findings)
            print(f"  [✓] 의심 소켓 탐지: {len(sock_findings)}건")
        else:
            print("\n  [!] sockstat 결과 없음 — 건너뜀")

        # check_creds 결과 분석
        check_creds_output = report.raw_outputs.get("check_creds", "")
        if check_creds_output:
            print("\n  [→] 권한 상승 탐지 중...")
            creds_findings = detect_linux_suspicious_creds(report)
            report.findings.extend(creds_findings)
            print(f"  [✓] 권한 상승 탐지: {len(creds_findings)}건")
        else:
            print("\n  [!] check_creds 결과 없음 — 건너뜀")

        print("\n" + "=" * 70)
        print("  6단계: Linux Bash / TTY / 키보드 분석")
        print("=" * 70)

        # bash 히스토리 분석
        bash_output = report.raw_outputs.get("bash", "")
        if bash_output:
            print("\n  [→] Bash 히스토리 분석 중...")
            bash_findings = detect_linux_suspicious_bash(report)
            report.findings.extend(bash_findings)
            print(f"  [✓] 의심 Bash 명령어 탐지: {len(bash_findings)}건")
        else:
            print("\n  [!] bash 결과 없음 — 건너뜀")

        # keyboard_notifiers 분석
        kb_output = report.raw_outputs.get("keyboard_notifiers", "")
        if kb_output:
            print("\n  [→] 키로거 탐지 중...")
            kb_findings = detect_linux_keyboard_hooks(report)
            report.findings.extend(kb_findings)
            print(f"  [✓] 키로거 탐지: {len(kb_findings)}건")
        else:
            print("\n  [!] keyboard_notifiers 결과 없음 — 건너뜀")

    # =========================================
    # 8단계: 보고서 생성
    # =========================================
    print("\n" + "=" * 70)
    print("  8단계: 보고서 생성")
    print("=" * 70)

    generate_report(report)

    print("\n" + "=" * 70)
    print("  분석이 완료되었습니다.")
    print(f"  결과 디렉토리: {os.path.abspath(args.output)}")
    print("=" * 70)



# =====================================================================
# 엔트리 포인트
# =====================================================================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  [!] 사용자에 의해 분석이 중단되었습니다.")
        sys.exit(130)
    except Exception as e:
        print(f"\n  [✗] 예기치 않은 오류가 발생했습니다: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)