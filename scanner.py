import ast
import json
import os
import subprocess
import sys
import tempfile

MAX_CODE_CHARS = 5000
SCAN_TIMEOUT = 10
BLOCKING = {"MEDIUM", "HIGH"}
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

# Bandit 規則編號 -> 白話說明
EXPLAIN = {
    "B105": "密碼寫死在程式裡，推上 GitHub 等於公開",
    "B106": "密碼寫死在函式參數裡",
    "B107": "密碼寫死在預設參數裡",
    "B608": "把輸入直接拼進 SQL 指令，駭客可以偷資料（SQL Injection）",
    "B324": "使用已不安全的雜湊演算法（如 MD5、SHA1）",
    "B602": "把輸入交給系統 shell 執行，駭客可以下任意指令",
    "B605": "透過 shell 啟動程序，輸入可能被拿來注入指令",
    "B307": "使用 eval，會把字串當成程式執行",
    "B102": "使用 exec，會把字串當成程式執行",
    "B301": "pickle 反序列化不受信任的資料，可能執行任意程式",
    "B506": "使用不安全的 YAML 載入方式",
    "B201": "Flask 開著除錯模式，會洩漏內部資訊並可能被遠端執行",
    "B104": "綁定到所有網路介面，服務會對外開放",
    "B113": "網路請求沒有設定逾時，可能被拖到卡死",
    "B501": "關閉了 HTTPS 憑證驗證，連線可能被竊聽",
}


def _result(passed, stages, issues):
    blocking = sum(1 for i in issues if i["severity"] in BLOCKING)
    return {
        "passed": passed,
        "stages": stages,
        "issues": issues,
        "blocking": blocking,
    }


def scan_code(code):
    """只做靜態分析，絕不執行使用者的程式碼。"""
    stages = []

    # 關卡 1：語法檢查（只解析，不執行）
    try:
        if "\x00" in code:
            raise ValueError("程式碼含有不合法的字元")
        ast.parse(code)
    except SyntaxError as exc:
        line = f"（第 {exc.lineno} 行）" if exc.lineno else ""
        stages.append(
            {"name": "語法檢查", "status": "fail",
             "detail": f"語法錯誤{line}，無法進入掃描"}
        )
        stages.append({"name": "安全掃描", "status": "skip", "detail": "已略過"})
        return _result(False, stages, [])
    except (ValueError, RecursionError, MemoryError):
        stages.append(
            {"name": "語法檢查", "status": "fail",
             "detail": "內容無法解析，視為未通過"}
        )
        stages.append({"name": "安全掃描", "status": "skip", "detail": "已略過"})
        return _result(False, stages, [])
    stages.append({"name": "語法檢查", "status": "pass", "detail": "語法正確"})

    # 關卡 2：靜態安全掃描
    with tempfile.TemporaryDirectory() as workdir:
        path = os.path.join(workdir, "submitted.py")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(code)
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "bandit", "-f", "json",
                 "--ignore-nosec", "-q", path],
                capture_output=True,
                text=True,
                timeout=SCAN_TIMEOUT,
                check=False,
            )
            report = json.loads(proc.stdout)
        except subprocess.TimeoutExpired:
            stages.append(
                {"name": "安全掃描", "status": "fail",
                 "detail": "掃描逾時，掃描失敗一律視為未通過"}
            )
            return _result(False, stages, [])
        except (json.JSONDecodeError, OSError):
            stages.append(
                {"name": "安全掃描", "status": "fail",
                 "detail": "掃描工具沒有正常回應，視為未通過"}
            )
            return _result(False, stages, [])

    issues = []
    for item in report.get("results", []):
        issues.append(
            {
                "id": item.get("test_id", "?"),
                "severity": item.get("issue_severity", "LOW"),
                "line": item.get("line_number", 0),
                "title": EXPLAIN.get(item.get("test_id"), item.get("issue_text", "")),
            }
        )
    issues.sort(key=lambda i: (SEVERITY_ORDER.get(i["severity"], 3), i["line"]))

    blocking = sum(1 for i in issues if i["severity"] in BLOCKING)
    if blocking:
        stages.append(
            {"name": "安全掃描", "status": "fail",
             "detail": f"發現 {blocking} 個中等以上的問題"}
        )
    else:
        stages.append(
            {"name": "安全掃描", "status": "pass",
             "detail": "沒有中等以上的問題"}
        )
    return _result(blocking == 0, stages, issues)
