# layer-audit — OCI 白化层审计服务

卫星载荷镜像入库前，本服务对多层交付物按 OCI 白化（whiteout）规则做联合叠加裁决：
确认已撤销的校准文件不会残留、下层内容不会被错误继承。调用方提交按底到顶排列的
gzip+Base64 TAR 层（至多 6 层），取回**冻结**的最终路径清单、每条路径的来源层以及
删除证据。

## 运行

```bash
# 构建并启动 app + verify；verify 全部通过后以退出码 0 结束
HOST_PORT=8080 docker compose up --build --exit-code-from verify

# 仅启动服务（宿主端口可通过 HOST_PORT 环境变量配置，默认 8080）
HOST_PORT=9090 docker compose up --build app
```

- `app` 容器： distroless 镜像，内置 `healthcheck` 子命令供 Compose 健康检查
  （`GET /healthz`，容器内端口固定 8080，可用 `PORT` 环境变量覆盖）。
- `verify` 容器： 依次执行 ① 构建检查（`go vet` / `go build`）② 白化规则测试
  （`go test`）③ HTTP 冒烟（提交含 opaque 与重建路径的审计并逐路径核对结果），
  任一步失败即非零退出，全部通过退出码为 0。

## API

### `POST /audits`

```json
{
  "id": "audit-2026-001",
  "layers": ["<base64(gzip(tar)) 底层>", "...", "<base64(gzip(tar)) 顶层>"]
}
```

- `id`：`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`；裁决一旦冻结，同 `id` 重复提交返回 `409`。
- `layers`：1–6 个元素，按底到顶排列。
- 响应：`201` 返回与 `GET` 一致的冻结裁决；请求格式错误 `400`；层校验/裁决失败 `422`。

### `GET /audits/{id}`

```json
{
  "id": "audit-2026-001",
  "layers": 3,
  "paths": [
    {"path": "/app", "type": "dir", "layer": 0},
    {"path": "/app/config.txt", "type": "file", "layer": 1},
    {"path": "/real-hard.txt", "type": "file", "layer": 0, "link": "/real.txt"}
  ],
  "deletions": [
    {"path": "/app/old-cal.bin", "type": "file", "layer": 0, "deletedBy": 1, "reason": "whiteout"}
  ]
}
```

- `paths`：最终联合视图，按字典序排列；`layer` 为引入该路径的层（0 起）；
  硬链接附带 `link` 目标。
- `deletions`：删除证据，含被删路径、来源层 `layer`、执行删除的层 `deletedBy`
  及原因 `reason`（`whiteout` / `opaque` / `replaced`）。
- 未找到返回 `404`；**任何一层失败都不会留下部分裁决**（失败后该 `id` 可修正重试）。

### `GET /healthz`

返回 `200 {"status":"ok"}`。

## 层校验规则（逐层，任一失败整体拒绝）

- **框架**：Base64 严格解码；gzip 单流完整消费（拒绝截断、尾随垃圾、多流拼接）；
  TAR 长度按 512 字节块对齐、末尾须有两个零块结束标记、标记后只允许零填充；
  头部校验和由 `archive/tar` 验证。
- **条目**：只接受目录、普通文件和硬链接（拒绝符号链接、设备等）；拒绝绝对路径、
  `..` 穿越、归档根自身、层内重复条目（按规范路径判定）。
- **硬链接**：目标必须是**本层**中先于它出现的普通文件（允许链接到同层硬链接），
  否则视为悬空链接拒绝；目标不得为目录或下层文件。

## 联合裁决语义

- 以规范路径维护联合文件树；同路径目录跨层合并时保留较低来源层。
- `.wh.<name>`：删除同目录下 `<name>`（文件或整个子树），下层内容不会在此后
  复活；目标不存在为空操作。随后层可在原路径重新创建。
- `.wh..wh..opq`：清空所在目录的**下层**子项（同层条目保留）。
- 文件↔目录相互替换：旧子树整体移除并记录 `replaced` 证据；文件覆盖文件同样记录。
- 父路径被下层文件占用时拒绝该层（`422`）。

## 本地开发

```bash
go test ./...        # 白化规则单元测试
go build ./... && ./layer-audit &          # 默认 :8080，PORT 可覆盖
go run ./cmd/smoke   # 对本地服务跑 HTTP 冒烟（AUDIT_URL 可覆盖）
```
