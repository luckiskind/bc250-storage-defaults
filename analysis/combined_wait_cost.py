"""Fixed selected-worker cost screen; no accelerator or application verdict."""
import random
from trace_overhead import estimate

CONTRACT=dict(version=1,seed=255,pairs_per_scenario=24,minimum_valid_pairs=20,
    hypothesis='The unchanged combined observer meets the 3% point and 5% upper exploratory cost limits in every cold selected-worker condition',
    scenarios=['plain-read','plain-mmap','encoded-read','encoded-mmap'],conditions=['off','combined'],
    warmup_trials_per_scenario=2,point_limit=.03,upper_interval_limit=.05,bootstrap_draws=5000,
    post_setup_idle_seconds=.25,background_cpu_fraction_max=.10,minimum_available_bytes=2*2**30,
    pre_workload_device_bytes_max=128*1024,timed_write_bytes_max=128*1024,timed_read_bytes_max=8*2**20+128*1024,
    capture_seconds=3,max_saved_records=50000,maximum_retained_raw_bytes=128*2**20,
    fixture_bytes=8*2**20,logical_bytes=2*2**20,root_memory_max_bytes=2*2**30,parent_runtime_seconds=1200,
    endpoint='Unchanged inherited-descriptor worker start through read/fault and FNV content hash',
    cache_scope='Only selected private fixture data; metadata and SSD-internal caches not claimed cold',
    exclusion_scope='Whole pair; every capture/content/proof failure remains disqualifying even if environmentally excluded',
    io_exclusion_scope='Same global NVMe read/write bounds in both arms; no selected-versus-unrelated I/O attribution',
    scope='Total combined observer cost at four cold selected-worker endpoints; setup cost and general application overhead separate')


def planned_order(contract=CONTRACT):
    rng=random.Random(contract['seed']);order=[]
    if contract['conditions']!=['off','combined'] or contract['pairs_per_scenario']%2:raise ValueError('Two arms and even fixed pair count required')
    for scenario in contract['scenarios']:
        order.extend(dict(scenario=scenario,pair=-1,condition=c,warmup=True) for c in contract['conditions'])
        firsts=contract['conditions']*(contract['pairs_per_scenario']//2);rng.shuffle(firsts)
        for pair,first in enumerate(firsts):
            order.extend(dict(scenario=scenario,pair=pair,condition=c,warmup=False) for c in (first,'combined' if first=='off' else 'off'))
    return order


def summarize(rows,contract):
    expected=planned_order(contract)
    if len(rows)!=len(expected) or any({k:r[k] for k in item}!=item for r,item in zip(rows,expected)):raise ValueError('Incomplete/reordered fixed cost collection')
    for r in rows:
        if type(r['workload']['elapsed_ns']) is not int or r['workload']['elapsed_ns']<=0:raise ValueError('Invalid endpoint duration')
        if type(r['capture_integrity']) is not bool or not isinstance(r['environment_exclusions'],list) or any(type(v) is not str for v in r['environment_exclusions']):raise ValueError('Invalid cost quality fields')
    results={}
    for scenario in contract['scenarios']:
        selected=[r for r in rows if r['scenario']==scenario];valid=[];excluded=[];failed=[];durations=[]
        warmup_bad=[r['condition'] for r in selected if r['warmup'] and not r['capture_integrity']]
        for pair in range(contract['pairs_per_scenario']):
            group=[r for r in selected if not r['warmup'] and r['pair']==pair]
            reasons=sorted({reason for r in group for reason in r['environment_exclusions']});bad=[r['condition'] for r in group if not r['capture_integrity']]
            if reasons:excluded.append(dict(pair=pair,reasons=reasons))
            if bad:failed.append(dict(pair=pair,conditions=bad))
            if not reasons and not bad:
                by={r['condition']:r['workload']['elapsed_ns'] for r in group};durations.append((by['off'],by['combined']));valid.append(pair)
        value=estimate(durations,seed=contract['seed'],draws=contract['bootstrap_draws']) if durations else None
        enough=len(valid)>=contract['minimum_valid_pairs']
        fit=bool(value and enough and not failed and not warmup_bad and value['geometric_overhead']<=contract['point_limit'] and value['paired_percentile_95'][1]<=contract['upper_interval_limit'])
        results[scenario]=dict(valid_pairs=valid,environment_excluded_pairs=excluded,capture_integrity_failed_pairs=failed,warmup_capture_failures=warmup_bad,
            estimate=value,minimum_pairs_met=enough,fit_for_selected_worker_screen=fit)
    return dict(scenarios=results,fit_for_selected_worker_screen=all(v['fit_for_selected_worker_screen'] for v in results.values()),
        total_trials=len(rows),instrumented_trials=sum(r['condition']=='combined' for r in rows),
        application_tracing_qualified=False,absolute_wrapper_cost_qualified=False,whole_application_critical_path_qualified=False,
        accelerator_gain_comparison=False,stage1_gate_passed=False,pair_independence_established=False,scope=contract['scope'])
