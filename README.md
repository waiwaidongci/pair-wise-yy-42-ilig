# 山火事件指挥与离线人员调度

维护火线、风向、资源和任务区，合并离线现场记录并防止人员重复分配。

## 模块结构

- `app.py`：参数解析、依赖组装和HTTP服务启动。
- `src/domain.py`：数据结构、错误、状态和基础校验。
- `src/rules.py`：状态机、角色矩阵、优先级、期限和关闭不变量；观测折叠、三方合并与处置许可判定。
- `src/repository.py`：SQLite建表、事务、版本控制和审计链；任务区版本链、观测批次存储与许可占用。
- `src/service.py`：权限检查、用例编排、并发控制和审计；批次幂等、整批失败保留与断网恢复。
- `src/http_api.py`：JSON路由和统一错误响应（请求入口，不包含业务判定）。
- `src/audit.py`：UTC时间和SHA-256审计事件。
- `static/index.html`：最小演示页。
- `tests/`：完整流程、规则和失败测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8319
```

默认端口为`8319`，首次启动自动建库。使用`X-Actor`和`X-Role`请求头传递身份。

## 主要接口

- `GET /health`
- `GET /api/items`
- `POST /api/items`
- `GET /api/items/{id}`
- `POST /api/items/{id}/records`
- `POST /api/items/{id}/transition`，必须提交`expected_version`
- `GET /api/audit`

允许角色：field_commander, incident_commander, logistics, viewer。火线长度、风向变化和离线记录数量影响风险等级；同一资源不能同时出现在多个活动任务中。

## 离线观测批次与处置许可（任务区版本链）

任务区、观测批次、处置许可接在同一条按任务区链接的SHA-256版本链（`zone_events`）上，与既有全局审计链并存。

- `POST /api/zones`（field_commander）：建立任务区，可设`danger_length`、初始`wind`、`fireline_length`，并可关联`item_id`。
- `POST /api/zones/{id}/batches`（field_commander）：提交观测批次，载荷为
  `{"ticket_no","field_time","base_version"?,"observations":[...]}`，观测`kind`为
  `wind`、`fireline_length`或`resource`（后两者资源观测带`task_code`/`resource_code`）。
  - **现场单号幂等**：同`(zone, ticket_no)`重放直接沿用首次结果，不二次应用。
  - **整批原子**：批次先整批排队，再在单事务内写观测/状态/许可；业务失败时整批保留为
    `failed`（载荷不丢、不写半条观测），恢复后可重试。
  - **三方合并**：以`base_version`快照为基线，与服务器当前值、现场新值三方合并；
    风向/火线长度/资源任务两边都改过且取值不同时，保留两份登记为待复核冲突，任务区进入
    `review`。不带`base_version`视为在线快进提交。
  - **许可失效重算**：风向或火线长度一变化，已批准许可立即`invalidated`、活动占用立即
    释放，并按新值生成`proposed`提案；冲突复核前（`review`）以及`expected_version`
    不匹配时一律挡住放行。
- `POST /api/zones/{id}/recover`（field_commander）：断网恢复，未应用批次按`field_time`
  现场时刻排序依次整批合并，单个失败不阻断其余批次。
- `POST /api/zones/{id}/batches/{ticket_no}/retry`：对失败保留的批次原地重试。
- `GET /api/zones/{id}/batches?status=`：批次列表（`queued`/`failed`/`applied`）。
- `GET /api/zones/{id}/conflicts?status=`、
  `POST /api/zones/{id}/conflicts/{cid}/resolve`（incident_commander，
  `{"resolution":"server"|"field"}`）：复核两边都改过的火线长度/风向/资源。
- `GET /api/zones/{id}/permits`、
  `POST /api/zones/{id}/permits/{pid}/approve`（incident_commander，
  必须提交`expected_version`）。
- `GET /api/zones/{id}/events`、`GET /api/zones/{id}/verify`：版本链事件与哈希校验。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
