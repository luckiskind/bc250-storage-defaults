"""Frozen incremental tracing-cost screen for one selected native application."""
import copy
import random
from trace_v2_overhead import summarize as control_summary

CONTRACT = dict(version=1, seed=254, pairs_per_scenario=24, minimum_valid_pairs=20,
    scenarios=['selected-data-cold', 'selected-data-warm'], conditions=['off', 'v2'],
    warmup_pairs_per_scenario=1, point_limit=.03, upper_interval_limit=.05,
    post_setup_idle_seconds=.25, background_cpu_fraction_max=.10,
    pre_workload_device_bytes_max=128*1024, minimum_available_bytes=2*2**30,
    capture_seconds=2, max_saved_records=200000,
    maximum_retained_raw_bytes=128*2**20,
    endpoint='Unchanged owned Konsole PTY-ready marker',
    fixed_corpus_shared_by_conditions=True, complete_application_input_closure=False,
    foreground_attribution_qualified=False, absolute_wrapper_cost_qualified=False,
    scope='Incremental v2 cost within one selected native Konsole fixture; no accelerator comparison')


def planned_order(contract=CONTRACT):
    rng=random.Random(contract['seed']); result=[]
    for scenario in contract['scenarios']:
        result.extend(dict(scenario=scenario,pair=-1,condition=condition,warmup=True)
                      for condition in contract['conditions'])
        firsts=['off','v2']*(contract['pairs_per_scenario']//2)
        if len(firsts)!=contract['pairs_per_scenario']:raise ValueError('Even pair count required')
        rng.shuffle(firsts)
        for pair,first in enumerate(firsts):
            result.extend(dict(scenario=scenario,pair=pair,condition=condition,warmup=False)
                          for condition in (first,'v2' if first=='off' else 'off'))
    return result


def summarize(rows,contract):
    expected=planned_order(contract)
    if len(rows)!=len(expected) or any({key:row[key] for key in item}!=item for row,item in zip(rows,expected)):
        raise ValueError('Collection differs from complete frozen order')
    for row in rows:
        elapsed=row['workload']['elapsed_ns']
        if type(elapsed) is not int or elapsed<=0:raise ValueError('Invalid endpoint elapsed time')
    result=copy.deepcopy(control_summary(rows,contract))
    result['fit_for_selected_application_screen']=result.pop('fit_for_control_screen')
    result['selected_konsole_incremental_tracing_cost_qualified']=result['fit_for_selected_application_screen']
    result.update(application_tracing_qualified=False,absolute_wrapper_cost_qualified=False,
        foreground_attribution_qualified=False,stage1_gate_passed=False,
        scope=contract['scope'],pair_independence_established=False)
    for value in result['scenarios'].values():
        if value['estimate']:
            value['estimate']['interval_scope']='Exploratory paired resampling for this fixed fixture; independence and general application overhead unproven'
    return result
