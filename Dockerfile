FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 建置時傳入 commit 編號，網頁會顯示它
ARG GIT_SHA=dev
ENV APP_VERSION=${GIT_SHA}

# 建立一般使用者，避免容器內以管理員(root)身分執行
RUN useradd --create-home --uid 10001 appuser
COPY --chown=appuser:appuser . .
USER appuser

EXPOSE 5000

CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app"]
