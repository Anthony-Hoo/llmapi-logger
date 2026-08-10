# 模块 15：Nginx 与部署

## 1. 目标

Nginx 只把需要审计的模型接口转给审计代理，其他 NewAPI 页面和 API 维持原来的直连方式。

首版提供一份可复制的单机/Docker 示例，不建设复杂高可用方案。

## 2. 基本拓扑

```text
客户端 -> Nginx
          |- 模型白名单 -> audit-proxy:8080 -> NewAPI:3000
          `- 其他路径 ----------------------> NewAPI:3000
```

管理端口默认 `127.0.0.1:8081`，不放进公开 Nginx server。`admin_token` 即使在 loopback 上也必填；静态 React UI shell 可直接加载，但 API、health、ready 和 metrics 都必须携带 Bearer token。

## 3. 公共代理参数

```nginx
proxy_http_version 1.1;
proxy_request_buffering off;
proxy_buffering off;
proxy_cache off;

proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;

proxy_connect_timeout 5s;
proxy_send_timeout 1h;
proxy_read_timeout 1h;
```

`proxy_pass` 后不要附加 URI 后缀，避免改变原 Path 和 Query。

## 4. 完整示例

```nginx
upstream newapi_backend {
    server 127.0.0.1:3000;
}

upstream audit_proxy_backend {
    server 127.0.0.1:8080;
}

server {
    listen 80;
    server_name _;

    client_max_body_size 512m;

    location = /v1/chat/completions {
        proxy_pass http://audit_proxy_backend;
        include /etc/nginx/snippets/audit-proxy.conf;
    }

    location = /v1/completions {
        proxy_pass http://audit_proxy_backend;
        include /etc/nginx/snippets/audit-proxy.conf;
    }

    location = /v1/responses {
        proxy_pass http://audit_proxy_backend;
        include /etc/nginx/snippets/audit-proxy.conf;
    }

    location = /v1/responses/compact {
        proxy_pass http://audit_proxy_backend;
        include /etc/nginx/snippets/audit-proxy.conf;
    }

    location = /v1/messages {
        proxy_pass http://audit_proxy_backend;
        include /etc/nginx/snippets/audit-proxy.conf;
    }

    location ~ ^/v1beta/models/[A-Za-z0-9._-]+:(generateContent|streamGenerateContent)$ {
        proxy_pass http://audit_proxy_backend;
        include /etc/nginx/snippets/audit-proxy.conf;
    }

    location / {
        proxy_pass http://newapi_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 5. 故障行为

推荐默认行为是审计代理不可达时模型请求失败，这样最容易理解。

如果个人部署更重视可用性，可以让 Nginx 临时改回 NewAPI 直连，但这段时间不会产生审计记录。不要配置对模型 POST 的自动重试，避免重复调用和计费。

## 6. Docker 构建与运行

### 6.1 多阶段镜像

构建阶段需要 Node/npm 生成 React 静态资源，也需要 Go 编译后端。前端源码固定在 `internal/web/frontend`，Vite 输出 `internal/web/dist`，`internal/web/embed.go` 把 dist 打进 Go 二进制。运行镜像不安装 Node/npm，也不启动独立前端服务。

首版 SQLite driver 固定使用纯 Go 的 `modernc.org/sqlite`，并在 `go.mod` 锁定版本；不引入依赖 C 编译器和动态 libc 的 SQLite driver。这样 `CGO_ENABLED=0` 生成的单一二进制可直接运行在 `distroless/static`。若以后改用需要 CGO 的 driver，必须另行修改构建和运行镜像，不属于首版范围。

```dockerfile
FROM node:22-alpine AS web-build
WORKDIR /src/internal/web/frontend
COPY internal/web/frontend/package.json internal/web/frontend/package-lock.json ./
RUN npm ci
COPY internal/web/frontend/ ./
RUN npm run build

FROM golang:1.25-alpine AS go-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web-build /src/internal/web/dist ./internal/web/dist
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/audit-proxy ./cmd/audit-proxy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=go-build /out/audit-proxy /audit-proxy
USER nonroot:nonroot
ENTRYPOINT ["/audit-proxy"]
```

`package-lock.json` 和 `go.mod` 记录首版依赖；发布前用 `CGO_ENABLED=0` 完成一次构建和 SQLite 读写 smoke test 即可。最终镜像只包含 Go 二进制及其已嵌入的 HTML/CSS/JS/font，不包含 C 工具链、动态 SQLite 库、前端源码、`node_modules`、npm cache 或 Node 运行时。

### 6.2 Compose 示例

```yaml
services:
  nginx:
    image: nginx:alpine
    ports: ["80:80"]
    volumes:
      - ./nginx:/etc/nginx/conf.d:ro
    depends_on: [audit-proxy, newapi]

  audit-proxy:
    image: audit-proxy:local
    command: ["--config", "/etc/audit-proxy/config.yaml"]
    ports: ["127.0.0.1:8081:8081"]
    volumes:
      - ./audit-data:/data
      - ./configs/audit-proxy.docker.yaml:/etc/audit-proxy/config.yaml:ro
      # 启用 Token 名称关联时再挂载：
      # - ./newapi-data:/newapi-data:ro
    expose: ["8080"]

  newapi:
    image: calciumion/new-api:latest
    volumes:
      - ./newapi-data:/data
    expose: ["3000"]
```

Docker 配置中的 listen 使用 `0.0.0.0:8080`，`admin_listen` 使用 `0.0.0.0:8081`，newapi_url 使用 `http://newapi:3000`，db_path/key_path 放在 `/data`，并始终配置非空 `admin_token`。承载 token 的配置文件只授予当前部署账户读取权限。Nginx 的 Docker 版 upstream 改为 `audit-proxy:8080` 和 `newapi:3000`，不要沿用宿主机示例里的 `127.0.0.1`。

生产使用时建议固定镜像版本；个人本地测试可以先使用明确记录的可用标签。

Compose 示例只把管理端口发布到宿主机 loopback。浏览器可无 token 加载静态 shell，随后在 React 页面输入 token；token 只存在当前页面内存，所有数据请求携带 Bearer。若完全不需要管理页面，可删除 ports 映射。启用 Token 关联时，newapi_token_db_path 指向只读挂载目录中的 NewAPI SQLite 文件。

## 7. Trailer 限制

- Go 代理会尽力保留 NewAPI 响应 Trailer。
- Nginx 新版本可通过 `proxy_pass_trailers on` 转发响应 Trailer。
- 客户端请求 Trailer 经 Nginx 是否保留取决于实际版本和配置，首版不作保证。

普通 JSON/SSE 模型接口通常不依赖请求 Trailer，因此把它记录为已知限制即可。

## 8. 部署步骤

1. 启动 NewAPI。
2. 启动审计代理，并执行 `curl -H "Authorization: Bearer <admin_token>" http://127.0.0.1:8081/healthz`。
3. 执行 `nginx -t`。
4. reload Nginx。
5. 分别请求一个模型接口和 `/health`。
6. 打开静态 UI shell、输入 token，确认列表、详情、原始查看、删除确认、导出和缺口提示可用。
7. 确认运行主机或容器中没有 Node 服务和 Node 监听端口。

## 9. 完成定义

- 白名单模型路径经过审计代理。
- 其他路径直连 NewAPI。
- SSE buffering 关闭。
- 管理端口不进入公开 Nginx，且所有数据/健康/指标端点都要求 Bearer。
- React/TypeScript/Vite/Tailwind CSS/shadcn/ui 已由 Go embed 提供，静态 shell 不含数据。
- SQLite 使用 `modernc.org/sqlite`，`CGO_ENABLED=0` 构建可在 `distroless/static` 启动并完成读写 smoke test。
- 运行镜像不包含 Node/npm 或前端构建依赖。
- 单机和 Docker 至少有一个可运行示例。
