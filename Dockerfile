FROM python:3.13-slim

LABEL maintainer="jianlai-sec"
LABEL description="剑来 (Jianlai-Sec) — AI-driven autonomous vulnerability discovery agent"

# 安装系统依赖和安全工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    gnupg \
    ca-certificates \
    git \
    nmap \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# 安装 Go（用于 subfinder/httpx/nuclei）
RUN wget -q https://go.dev/dl/go1.23.4.linux-amd64.tar.gz -O /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# 安装 ProjectDiscovery 安全工具
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# 清理 Go 缓减小镜像
RUN rm -rf /root/go/pkg /root/go/src /usr/local/go

WORKDIR /app

# 先复制依赖文件，利用 Docker 缓存
COPY pyproject.toml ./
RUN pip install --no-cache-dir -e . 2>/dev/null || pip install --no-cache-dir \
    openai>=1.50.0 \
    httpx>=0.27.0 \
    aiosqlite>=0.20.0 \
    pydantic>=2.9.0 \
    pydantic-settings>=2.5.0 \
    rich>=13.9.0 \
    click>=8.1.0 \
    beautifulsoup4>=4.12.0 \
    tldextract>=5.1.0 \
    dnspython>=2.7.0

# 复制项目代码
COPY . .
RUN pip install --no-cache-dir -e .

# 创建数据目录
RUN mkdir -p /app/data /app/output

# 更新 nuclei 模板
RUN nuclei -update-templates 2>/dev/null || true

ENTRYPOINT ["jianlai"]
CMD ["--help"]
