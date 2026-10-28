"""Same causal graph, with explicit absence of optional unlock observations."""
import copy
from combined_wait import validate as full_validate


def validate(raw):
    if raw.get('kind')!='bc250-compact-wait-diagnostic' or raw.get('unlock_hook_loaded') is not False:raise ValueError('Wrong compact protocol or unlock omission')
    if any(r['stage']==12 for r in raw['records']):raise ValueError('Compact stream contains an omitted unlock event')
    projected=copy.deepcopy(raw);projected.pop('unlock_hook_loaded');projected['kind']='bc250-combined-wait-diagnostic'
    result=full_validate(projected)
    # Null denotes unavailable, not an observed zero/census. The full reader
    # still supplies every transport, request, vector and scheduler verdict.
    result.update(folio_unlock_calls=None,unparented_unlock_calls=None,folio_unlock_hook_loaded=False,folio_unlock_count_available=False)
    return result
