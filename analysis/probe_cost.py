"""Per-program accounting windows with explicit profiling overhead limits."""
U64=2**64
FIELDS={'begin_ns','end_ns','run_time_ns','run_cnt','recursion_misses','id','type','info_length','xlated_bytes','name'}


def analyze(rows,owned,window_start,window_finish,endpoint=None):
    if type(window_start) is not int or type(window_finish) is not int or not 0<=window_start<window_finish<U64:raise ValueError('Invalid profile window')
    if len(owned)!=28 or any(set(r)!={'id','name'} or type(r['id']) is not int or not 0<r['id']<2**32 or not isinstance(r['name'],str) or not r['name'] for r in owned) or len({r['id'] for r in owned})!=28 or len({r['name'] for r in owned})!=28:raise ValueError('Exactly 28 unique owned identities required')
    if endpoint is not None and (len(endpoint)!=2 or any(type(v) is not int or not 0<=v<U64 for v in endpoint)):raise ValueError('Invalid endpoint clocks')
    if len(rows)!=28:raise ValueError('Every owned program needs two samples')
    expected={r['id']:r['name'] for r in owned};seen=set();answer=[]
    for pair in rows:
        if set(pair)!={'before','after'}:raise ValueError('Unexpected profile pair fields')
        a,b=pair['before'],pair['after']
        for s in (a,b):
            if set(s)!=FIELDS or not isinstance(s['name'],str):raise ValueError('Private/unknown sample fields')
            if any(type(v) is not int or not 0<=v<U64 for k,v in s.items() if k!='name'):raise ValueError('Rounded/overflowed profile value')
            if not window_start<=s['begin_ns']<=s['end_ns']<=window_finish:raise ValueError('Snapshot outside owned descriptor window')
        identity=a['id']
        if identity not in expected or identity in seen:raise ValueError('Unowned/repeated program')
        seen.add(identity)
        for k in ('id','name','type','info_length','xlated_bytes'):
            if a[k]!=b[k]:raise ValueError('Program identity/ABI changed')
        if a['name']!=expected[identity][:15] or not a['type'] or not a['info_length'] or not a['xlated_bytes']:raise ValueError('Wrong owned program metadata')
        if not a['end_ns']<=b['begin_ns']:raise ValueError('Overlapping/reversed snapshots')
        if endpoint is not None and not a['end_ns']<=endpoint[0]<endpoint[1]<=b['begin_ns']:raise ValueError('Endpoint not covered by every program window')
        deltas={k:b[k]-a[k] for k in ('run_time_ns','run_cnt','recursion_misses')}
        if any(v<0 for v in deltas.values()):raise ValueError('Counter reset or wrap')
        if deltas['run_time_ns'] and not deltas['run_cnt']:raise ValueError('Runtime without an invocation')
        answer.append(dict(program=expected[identity],**deltas,outer_window_ns=b['end_ns']-a['begin_ns'],
            inner_window_ns=b['begin_ns']-a['end_ns'],snapshot_span_ns=(a['end_ns']-a['begin_ns'])+(b['end_ns']-b['begin_ns'])))
    if seen!=set(expected):raise ValueError('Owned set incomplete')
    total=sum(r['run_time_ns'] for r in answer);calls=sum(r['run_cnt'] for r in answer);misses=sum(r['recursion_misses'] for r in answer)
    answer.sort(key=lambda r:(-r['run_time_ns'],r['program']))
    return dict(programs=answer,aggregate_owned_runtime_ns=total,aggregate_owned_invocations=calls,recursion_misses=misses,
        accounting_quality_passed=not misses,profiling_overhead_present=True,simultaneous_snapshots=False,
        foreground_only_accounting=False,endpoint_speed_comparison=False,unprofiled_cpu_cost_qualified=False)
