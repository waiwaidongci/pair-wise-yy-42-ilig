from __future__ import annotations
from .domain import ConflictError, ValidationError, require_number, require_text
TITLE='山火事件指挥与离线人员调度'; ENTITY='山火事件'; ID_PREFIX='WF'
# 观测类型：风向 / 火线长度 / 资源
OBS_WIND='wind_direction'; OBS_FIRELINE='fire_line_length'; OBS_RESOURCE='resource'
OBSERVATION_KINDS=(OBS_WIND,OBS_FIRELINE,OBS_RESOURCE)
# 允许的风向方位
WIND_DIRECTIONS=('north','south','east','west','northeast','northwest','southeast','southwest')
# 批次状态：待处理 / 已应用 / 失败 / 待复核
BATCH_PENDING='pending'; BATCH_APPLIED='applied'; BATCH_FAILED='failed'; BATCH_REVIEW='review'
BATCH_STATUSES=(BATCH_PENDING,BATCH_APPLIED,BATCH_FAILED,BATCH_REVIEW)
# 许可状态：有效 / 失效 / 已放行
PERMIT_ACTIVE='active'; PERMIT_INVALID='invalid'; PERMIT_RELEASED='released'
PERMIT_STATUSES=(PERMIT_ACTIVE,PERMIT_INVALID,PERMIT_RELEASED)
# 资源动作：编入 / 撤出
RESOURCE_ASSIGN='assign'; RESOURCE_RELEASE='release'; RESOURCE_ACTIONS=(RESOURCE_ASSIGN,RESOURCE_RELEASE)
# 资源占用状态
OCCUPIED='occupied'; RELEASED='released'
# 复核结论取值
SIDE_ONLINE='online'; SIDE_OFFLINE='offline'; SIDES=(SIDE_ONLINE,SIDE_OFFLINE)
SEVERITIES=['low', 'moderate', 'high', 'extreme']; STATES=['reported', 'active', 'contained', 'controlled', 'closed']; TRANSITIONS={'reported': ['active'], 'active': ['contained'], 'contained': ['controlled'], 'controlled': ['closed'], 'closed': []}; TRANSITION_ROLES={'active': ['incident_commander'], 'contained': ['incident_commander'], 'controlled': ['incident_commander'], 'closed': ['incident_commander']}
CREATE_ROLES=set(['field_commander']); RECORD_ROLES=set(['field_commander', 'logistics']); AUDIT_ROLES=set(['incident_commander', 'viewer']); VIEW_ROLES=set(['field_commander', 'incident_commander', 'logistics', 'viewer'])
BATCH_ROLES=set(['field_commander','logistics']); REVIEW_ROLES=set(['incident_commander']); PERMIT_ROLES=set(['incident_commander'])
SEVERITY_WEIGHT={'low': 1.0, 'moderate': 3.0, 'high': 6.0, 'extreme': 9.0}; DEADLINE_HOURS={'low': 72, 'moderate': 24, 'high': 8, 'extreme': 4}; TERMINAL_STATES=set(['closed'])
def priority_score(severity,quantity=0.0,threshold=1.0,open_records=0):
    if severity not in SEVERITY_WEIGHT: raise ValidationError("unknown severity")
    ratio=quantity/threshold if threshold>0 else 1.0
    return max(0,min(10,int(round(SEVERITY_WEIGHT[severity]+min(4.0,ratio*4.0)+min(3.0,float(open_records))))))
def response_deadline_hours(severity,quantity=0.0,threshold=1.0):
    if severity not in DEADLINE_HOURS: raise ValidationError("unknown severity")
    ratio=quantity/threshold if threshold>0 else 1.0
    return max(1,int(DEADLINE_HOURS[severity]/max(1.0,ratio)))
def escalation_required(severity,quantity=0.0,threshold=1.0):
    return severity==SEVERITIES[-1] or (threshold>0 and quantity>=threshold)
def can_transition(current,target): return target in TRANSITIONS.get(current,[])
def validate_transition(current,target):
    if current not in STATES or target not in STATES: raise ValidationError("未知状态")
    if not can_transition(current,target): raise ConflictError(f"不能从{current}转换到{target}")
def completion_blockers(target,open_records): return ["仍有未关闭事项"] if target in TERMINAL_STATES and open_records>0 else []
def role_for_transition(target): return set(TRANSITION_ROLES.get(target,[]))


def validate_observation(obs):
    """校验并归一化一条现场观测。观测判定入口。"""
    if not isinstance(obs,dict): raise ValidationError("观测必须是JSON对象")
    kind=obs.get("kind")
    if kind not in OBSERVATION_KINDS: raise ValidationError("未知观测类型")
    observed_at=require_text(obs.get("observed_at"),"observed_at",40)
    raw=obs.get("value")
    if kind==OBS_WIND:
        if not isinstance(raw,str) or raw not in WIND_DIRECTIONS:
            raise ValidationError("风向不在允许范围内")
        value=raw
    elif kind==OBS_FIRELINE:
        value=require_number(raw,"fire_line_length",0.0)
    else:
        if not isinstance(raw,dict): raise ValidationError("资源观测必须是对象")
        resource=require_text(raw.get("resource"),"resource",100)
        action=raw.get("action",RESOURCE_ASSIGN)
        if action not in RESOURCE_ACTIONS: raise ValidationError("资源动作必须是assign或release")
        value={"resource":resource,"action":action}
    return {"kind":kind,"value":value,"observed_at":observed_at}


def validate_ticket_no(ticket_no):
    return require_text(ticket_no,"ticket_no",100)


def validate_observations(observations):
    if not isinstance(observations,list) or not observations:
        raise ValidationError("观测列表不能为空")
    return [validate_observation(o) for o in observations]


def _obs_value(obs):
    return obs["value"]


def merge_observations(history,incoming):
    """按现场时刻合并历史观测与断网批次观测。

    history: 已应用观测（在线一侧），元素含 kind/value/observed_at。
    incoming: 本批次观测（现场/离线一侧）。
    返回合并结果与冲突清单：火线或资源两边都改过且取值不一致时保留两份待复核。
    """
    tagged=[]
    for o in history: tagged.append({**o,"_side":SIDE_ONLINE})
    for o in incoming: tagged.append({**o,"_side":SIDE_OFFLINE})
    tagged.sort(key=lambda o:o["observed_at"])

    # 风向：标量，按现场时刻取最新值，不产生两份
    wind=None
    for o in tagged:
        if o["kind"]==OBS_WIND: wind=o["value"]

    # 火线长度：按现场时刻取最新值；两边都改过且不一致则保留两份
    fire_online=None; fire_offline=None
    for o in tagged:
        if o["kind"]==OBS_FIRELINE:
            if o["_side"]==SIDE_ONLINE: fire_online=o["value"]
            else: fire_offline=o["value"]
    fire_conflict=None
    fire_merged=None
    if fire_online is not None and fire_offline is not None:
        if abs(float(fire_online)-float(fire_offline))>1e-9:
            fire_conflict={SIDE_ONLINE:fire_online,SIDE_OFFLINE:fire_offline}
    if fire_conflict is None:
        latest=None; latest_ts=""
        for o in tagged:
            if o["kind"]==OBS_FIRELINE and o["observed_at"]>=latest_ts:
                latest=o["value"]; latest_ts=o["observed_at"]
        fire_merged=latest

    # 资源：按资源分别合并；两边都改过且动作不一致则保留两份
    res_online={}; res_offline={}
    for o in tagged:
        if o["kind"]==OBS_RESOURCE:
            res=o["value"]["resource"]; action=o["value"]["action"]
            if o["_side"]==SIDE_ONLINE: res_online[res]=action
            else: res_offline[res]=action
    resource_conflicts=[]; resource_merged={}
    for res in set(res_online)|set(res_offline):
        on=res_online.get(res); off=res_offline.get(res)
        if on is not None and off is not None and on!=off:
            resource_conflicts.append({"resource":res,SIDE_ONLINE:on,SIDE_OFFLINE:off})
        else:
            resource_merged[res]=on if on is not None else off
    for c in resource_conflicts:
        res=c["resource"]; latest_action=None; latest_ts=""
        for o in tagged:
            if o["kind"]==OBS_RESOURCE and o["value"]["resource"]==res and o["observed_at"]>=latest_ts:
                latest_action=o["value"]["action"]; latest_ts=o["observed_at"]
        resource_merged[res]=latest_action

    return {
        "wind_direction":wind,
        "fire_line_length":fire_merged,
        "fire_line_conflict":fire_conflict,
        "resources":dict(resource_merged),
        "resource_conflicts":resource_conflicts,
        "has_conflict":fire_conflict is not None or bool(resource_conflicts),
    }


def judge_conditions(wind_direction,fire_line_length,severity,threshold):
    """按当前风向与火线长度重算许可条件（风险分）。"""
    wind_factor={"north":1.0,"south":1.2,"east":1.1,"west":1.1,
                 "northeast":1.15,"northwest":1.15,"southeast":1.2,"southwest":1.3}
    wf=wind_factor.get(wind_direction,1.0) if wind_direction else 1.0
    ratio=(float(fire_line_length or 0)/float(threshold)) if threshold and threshold>0 else 0.0
    risk=max(0,min(10,int(round(wf*(5.0+min(5.0,ratio*5.0))))))
    return {"wind_direction":wind_direction,"fire_line_length":fire_line_length,
            "risk_score":risk,"wind_factor":wf}


def conditions_changed(prev_conditions,wind_direction,fire_line_length):
    """风向或火线长度较上次许可条件发生变化。"""
    if not prev_conditions: return True
    return (prev_conditions.get("wind_direction")!=wind_direction or
            prev_conditions.get("fire_line_length")!=fire_line_length)
