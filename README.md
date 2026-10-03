# 卫星载荷镜像 Overlay 审计服务

归档工程师在载荷镜像入库前，用本服务确认多层交付物按 OCI 白化（whiteout）
规则叠加后，不会保留已撤销的校准文件或错误继承下层内容。

调用方以审计标识向 `POST /audits` 提交 **1–6 层**（自底向上排列）的
`base64(gzip(tar))` 数据；服务逐层严格校验后在内存中构建联合文件树，
冻结最终裁决。`GET /audits/{id}` 返回冻结的最终路径清单、每条路径的
来源层以及删除证据。任一层失败，整个审计被拒绝，不留下部分裁决。

## 运行（Docker Compose）

```bash
docker compose build
docker compose up --abort-on-container-exit --exit-code-from verify
echo "verify exit code: $?"
```

* `app`：审计服务。宿主端口可配置：`AUDIT_HOST_PORT=9000 docker compose up app`
  （默认 `8080`）。Compose 健康检查打 `/healthz`。
* `verify`：依赖 `app` 健康后启动，**先**运行白化规则单元测试与构建检查
  （`compileall` 字节编译），**再**提交一份含 opaque 目录与重建路径的审计
  并读回结果做 HTTP 冒烟，最后以退出码结束（0 = 全部通过）。

无 Docker 时本地等价流程：

```bash
python3 -m unittest discover -s tests -t . -v   # 白化规则测试
python3 -m compileall -q app tests              # 构建检查
PORT=8080 python3 -m app.server &               # 启动服务
APP_ADDR=http://127.0.0.1:8080 python3 -m app.smoke
```

## API

### `POST /audits`

```json
{
  "id": "run-2026-10-03-a",
  "layers": ["H4sIAAAAAAAC/...", "..."]
}
```

* `id`：审计标识，`[A-Za-z0-9._-]`，1–128 字符；冻结后不可复用（重复 `409`）。
* `layers`：1–6 个元素，`layers[0]` 为最底层。
* 成功：`201` + 冻结结果；校验失败：`400 {"error": "layer N: ..."}`，不存任何状态。

### `GET /audits/{id}`

```json
{
  "id": "run-2026-10-03-a",
  "layerCount": 3,
  "paths": [
    {"path": "payload/calib/gain.txt", "type": "file", "layer": 2},
    {"path": "payload/calib/gain.link", "type": "file", "layer": 2,
     "link": "payload/calib/gain.txt"}
  ],
  "deletions": [
    {"path": "payload/calib/gain.txt", "layer": 0, "kind": "whiteout",
     "byLayer": 1, "via": "payload/calib/.wh.gain.txt"}
  ]
}
```

* `paths[].layer`：路径来源层（0 = 最底层）；硬链接条目附 `link` 目标。
* `deletions[]`：删除证据。`kind` ∈ `whiteout`（`.wh.<name>` 删除）、
  `opaque`（`.wh..wh..opq` 清空下层子项）、`replaced`（文件/目录替换，
  目录被替换时其整棵子树逐条记录）；`byLayer` 为执行删除的层，`via`
  为触发该删除的条目路径。
* 另有 `GET /audits`（列出已冻结 id）与 `GET /healthz`。

## 层校验规则（`app/tarparse.py`）

每层必须是**恰好一个被完整消费的 gzip 成员**，解压出**恰好一个 TAR 归档**：

* 512 字节块对齐；ustar 头校验和逐块核验；数字字段必须是八进制
  （拒绝 base-256）；文件数据后零填充；两个零块结束标记，之后只允许零填充；
  gzip 成员之后有任何字节（含第二个成员）即拒绝。
* 只接受目录、普通文件、硬链接；符号链接、设备、FIFO、PAX/GNU 扩展头一律拒绝。
* 路径必须相对且规范：拒绝绝对路径、`..` 穿越、`.`/空分量、文件尾斜杠。
* 层内重复规范路径拒绝；硬链接目标必须在本层先前出现且当前仍存在
  （悬空链接拒绝）。

## 白化裁决规则（`app/engine.py`）

* `.wh.<name>`：删除同目录下 `<name>` 及其子树；白化条目本身不进结果。
* `.wh..wh..opq`：所在目录对下层不透明——清除该目录所有来自下层的子项，
  本层新增子项保留，目录本身保留下层来源层。
* 普通条目覆盖下层不同类型条目（文件↔目录）；目录被替换时删除其整棵子树；
  同层后层文件取代前层文件记为 `replaced` 证据；重复声明目录不改变其来源层。
* 被白化删除的路径可在后续层重新创建，来源层记为新层。
* 所有层在私有树上裁决，任一失败整体抛弃——审计是原子的。

## 资源限制

请求体 ≤ 64 MiB；单层压缩后 ≤ 16 MiB、解压后 ≤ 64 MiB；单层条目 ≤ 4096；
单文件 ≤ 32 MiB；层数 1–6。
