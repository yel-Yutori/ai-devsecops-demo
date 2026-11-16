# AI 時代的 DevSecOps 流水線示範

這是一個教學用專題：AI 讓程式碼產出變快，檢查卻跟不上，所以需要自動化流水線把關。
網站本身只是示範對象，重點是它背後的流程。

## 先看這個（不用安裝任何東西）

點上方 **Actions** 分頁，看歷次執行紀錄：

| 找這一筆 | 你會看到 |
|---|---|
| `Add AI-generated user service (contains vulnerabilities)` | 測試綠色、**安全掃描紅色**，容器沒有被打包或發布 |
| `Fix vulnerabilities flagged by security scan` | 修好之後全部變綠 |

重點：功能正常的程式，仍然可能不安全。

## 流程

寫程式 → 自動測試 → 安全掃描（Bandit）→ 容器打包 → 發布映像檔 → 伺服器拉取並做健康檢查，失敗則回復舊版

## 自己在本機跑跑看（需要先安裝 Docker）

```bash
git clone https://github.com/yel-Yutori/ai-devsecops-demo.git
cd ai-devsecops-demo
docker build -t demo-app .
docker run -d --name demo -p 127.0.0.1:5000:5000 \
  --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges:true demo-app
```

驗證服務有跑起來：

```bash
curl localhost:5000/health
```

應該回傳 `{"status":"ok"}`。也可以用瀏覽器開 http://localhost:5000。

用完後關掉：

```bash
docker stop demo
docker rm demo
```

## 自己玩玩看：讓掃描器抓你一次

1. 點右上角 **Fork**，在你自己的帳號下建立一份副本。
2. 到你 Fork 的 **Actions** 分頁，按下啟用流水線（GitHub 預設會停用）。
3. 把你 Fork 的專案複製到本機（網址換成你自己的帳號），再取回有漏洞的版本並推上去：

```bash
git clone https://github.com/你的帳號/ai-devsecops-demo.git
cd ai-devsecops-demo
git show a8978b9:ai_generated/user_service.py > ai_generated/user_service.py
git add ai_generated
git commit -m "Try the vulnerable version"
git push
```

4. 推送時帳號輸入你的 GitHub 帳號，密碼貼上**你自己建立的 Token**。
5. 看你的 Fork 的 Actions：安全掃描會變紅，映像檔不會被發布。
6. 挑戰：試著寫一段有漏洞、但掃描器抓不到的程式碼，看看工具的限制在哪裡。

## 重要說明

- `ai_generated/user_service.py` 的歷史版本是**故意放入漏洞的示範**，密碼是假的，請勿用於任何真實系統。
- 漏洞程式是人工模仿常見錯誤寫成，並非某個 AI 的真實輸出。
- 目前的掃描只涵蓋 Python 程式碼，不包含依賴套件與容器映像檔的掃描。
- 這是單機環境的示範，不代表正式營運環境的完整做法。

## 為什麼不用 Trivy

2026 年 3 月 Trivy 的 GitHub Action 發生供應鏈攻擊，所以本專案改用 Bandit，並把 Actions 固定到 commit SHA。
