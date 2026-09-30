from __future__ import annotations
from .domain import ConflictError, ValidationError
TITLE='山火事件指挥与离线人员调度'; ENTITY='山火事件'; ID_PREFIX='WF'
SEVERITIES=['low', 'moderate', 'high', 'extreme']; STATES=['reported', 'active', 'contained', 'controlled', 'closed']; TRANSITIONS={'reported': ['active'], 'active': ['contained'], 'contained': ['controlled'], 'controlled': ['closed'], 'closed': []}; TRANSITION_ROLES={'active': ['incident_commander'], 'contained': ['incident_commander'], 'controlled': ['incident_commander'], 'closed': ['incident_commander']}
CREATE_ROLES=set(['field_commander']); RECORD_ROLES=set(['field_commander', 'logistics']); AUDIT_ROLES=set(['incident_commander', 'viewer']); VIEW_ROLES=set(['field_commander', 'incident_commander', 'logistics', 'viewer'])
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

# ---------------------------------------------------------------------------
# 离线观测批次：观测类型、三方合并与处置许可判定
# ---------------------------------------------------------------------------
OBS_WIND='wind'; OBS_LENGTH='fireline_length'; OBS_RESOURCE='resource'
OBSERVATION_KINDS=(OBS_WIND,OBS_LENGTH,OBS_RESOURCE)
# 允许开展处置的风向集合（其余风向会顶着火头推进，许可不予放行）
SAFE_WINDS=('downhill','with_slope','cross_slope')
BATCH_STATUSES=('queued','failed','applied')
TASK_STATUSES=('proposed','active','released')
# 各观测字段在任务区状态快照中的键
SCALAR_FIELDS=(OBS_WIND,OBS_LENGTH)
DEFAULT_DANGER_LENGTH=1000.0

def fold_observations(observations,default_field_time):
    """把一个批次内的观测按现场时刻归并成 {wind, fireline_length, tasks}。
    同一字段以现场时刻靠后的观测为准；资源观测按任务编码覆盖。"""
    folded={OBS_WIND:None,OBS_LENGTH:None,'tasks':{}}
    times={OBS_WIND:None,OBS_LENGTH:None,'tasks':None}
    for obs in observations:
        when=obs.get('field_time') or default_field_time
        kind=obs['kind']
        if kind==OBS_WIND:
            if times[OBS_WIND] is None or when>=times[OBS_WIND]:
                folded[OBS_WIND]=obs['value']; times[OBS_WIND]=when
        elif kind==OBS_LENGTH:
            if times[OBS_LENGTH] is None or when>=times[OBS_LENGTH]:
                folded[OBS_LENGTH]=obs['value']; times[OBS_LENGTH]=when
        elif kind==OBS_RESOURCE:
            if times['tasks'] is None or when>=times['tasks']:
                folded['tasks'][obs['task_code']]=obs['resource_code']; times['tasks']=when
    return folded

def merge_scalar(field,base,server,incoming):
    """标量字段（风向/火线长度）三方合并：两边都改过且取值不同则保留两份待复核。"""
    incoming_changed=incoming is not None and incoming!=base
    server_changed=server!=base
    if incoming_changed and server_changed and server!=incoming:
        return {'field':field,'kind':field,'base':base,'server':server,'observed':incoming}
    if incoming_changed:
        return {'field':field,'value':incoming}
    return {'field':field,'value':server}

def merge_tasks(base,server,incoming):
    """资源任务映射（任务编码->资源编码）三方合并。
    基线中不存在的键视为新增；两边改过同一任务且资源不同则双份保留。"""
    changes={}
    conflicts=[]
    keys=set(base)|set(server)|set(incoming)
    for task_code in keys:
        b=base.get(task_code); s=server.get(task_code); i=incoming.get(task_code)
        incoming_changed=i is not None and i!=b
        server_changed=s!=b
        if incoming_changed and server_changed and s!=i:
            conflicts.append({'field':'resource','kind':'resource','task_code':task_code,
                              'base':b,'server':s,'observed':i})
        elif incoming_changed:
            changes[task_code]=i
        elif server_changed:
            changes[task_code]=s
    return changes,conflicts

def three_way_merge(base_snapshot,current_snapshot,folded):
    """返回 (标量结果, 资源任务变更, 冲突列表)。只返回真正需要落库的内容。"""
    scalars={}
    conflicts=[]
    for field in SCALAR_FIELDS:
        base=base_snapshot.get(field)
        outcome=merge_scalar(field,base,current_snapshot.get(field),
                             folded.get(field))
        if 'value' in outcome:
            # 只要相对基线确实发生变化就落库（即使新值恰好与服务器当前值相同）
            if outcome['value']!=base:
                scalars[field]=outcome['value']
        else:
            conflicts.append(outcome)
    task_changes,task_conflicts=merge_tasks(
        base_snapshot.get('tasks',{}),current_snapshot.get('tasks',{}),folded.get('tasks',{}))
    conflicts.extend(task_conflicts)
    return scalars,task_changes,conflicts

def disposal_decision(wind,fireline_length,danger_length):
    """按当前风向与火线长度重算处置许可。"""
    length_safe=fireline_length is not None and fireline_length<danger_length
    wind_safe=wind is not None and wind in SAFE_WINDS
    reasons=[]
    if fireline_length is None: reasons.append("缺少火线长度观测")
    elif not length_safe: reasons.append("火线长度达到或超过危险阈值")
    if wind is None: reasons.append("缺少风向观测")
    elif not wind_safe: reasons.append("当前风向不利于处置作业")
    return {'can_approve':length_safe and wind_safe,'reasons':reasons}
