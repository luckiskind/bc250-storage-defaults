"""Checked composition of frozen request and folio references into a new format."""
import json
import re
from request_bio_loader import generate as request_generate


def folio_extension(source):
    def change(old,new):
        nonlocal source
        if source.count(old)!=1:raise ValueError('Folio reference template differs: '+old[:70])
        source=source.replace(old,new)
    change('#include "read_lineage.bpf.c"','/* Shared read reference is included by the request observer. */')
    change('FW_MATCH_BEGIN=13','FW_MATCH_BEGIN=24')
    change('if(!cfg || cfg->pad){fw_inc(6);return 0;}','if(!cfg || !cv_folio_enabled()){fw_inc(6);return 0;}')
    change('if(bpf_map_update_elem(&fw_calls,&thread,&call,BPF_NOEXIST))',
        'cv_vector_edge(folio,call.c.id,bio_id);\n    if(bpf_map_update_elem(&fw_calls,&thread,&call,BPF_NOEXIST))')
    return source


def ready_ids(log):
    for line in log.split(b'\n')[:-1]:
        if line.startswith(b'BC250_COMBINED_WAIT_READY '):
            ids=json.loads(line.split(b' ',1)[1])['program_ids']
            if len(ids)!=29 or len(set(ids))!=29 or any(type(v) is not int or v<=0 for v in ids):raise ValueError('Twenty-nine distinct owned program IDs required')
            return ids
    return None


def generate(source):
    source=request_generate(source)
    def change(old,new,count=1):
        nonlocal source
        if source.count(old)!=count:raise ValueError('Request loader template differs: '+old[:70])
        source=source.replace(old,new)
    change('#define PROGRAMS 24','#define PROGRAMS 29')
    change('if(argc!=9 || geteuid()!=0)','if(argc!=11 || geteuid()!=0)')
    change('long proof=number(argv[6],0,1),issue_proof=number(argv[8],0,1);',
        'long proof=number(argv[6],0,1),issue_proof=number(argv[8],0,1),vector_proof=number(argv[9],0,1),folio_proof=number(argv[10],0,1);')
    change('if(proof<0 || issue_proof<0 || stat(argv[7],&device)',
        'if(proof<0 || issue_proof<0 || vector_proof<0 || folio_proof<0 || stat(argv[7],&device)')
    change('if(bpf_object__load(object))goto cleanup;',
        'const char *replaced[]={"bio_enter","data_enter","data_exit","sleep_enter","sleep_exit"};\n'
        '    for(unsigned i=0;i<5;i++){struct bpf_program *p=bpf_object__find_program_by_name(object,replaced[i]);if(!p || bpf_program__set_autoload(p,0))goto cleanup;}\n'
        '    if(bpf_object__load(object))goto cleanup;')
    match=re.search(r'const char \*names\[\]=\{[^;]+\};',source)
    if not match:raise ValueError('Missing request program list')
    names=match[0]
    for old,new in [('bio_enter','cv_bio_enter'),('data_enter','cv_data_enter'),('data_exit','cv_data_exit'),('sleep_enter','fw_sleep_enter'),('sleep_exit','fw_sleep_exit')]:names=names.replace('"'+old+'"','"'+new+'"')
    names=names.replace('};',',"fw_match_enter","fw_match_exit","fw_sched_switch","fw_sched_waking","fw_sched_wakeup"};');change(match[0],names)
    change('fprintf(stderr,"BC250_PHYSICAL_SEED_READY\\n");',
        'struct cv_options {uint32_t vector,folio;} options={vector_proof,folio_proof};int cvfd=bpf_object__find_map_fd_by_name(object,"cv_cfg");\n'
        '    if(cvfd<0 || bpf_map_update_elem(cvfd,&zero,&options,BPF_ANY))goto cleanup;\n'
        '    fprintf(stderr,"BC250_PHYSICAL_SEED_READY\\n");')
    change('BC250_REQUEST_BIO_READY','BC250_COMBINED_WAIT_READY');change('bc250-request-bio-diagnostic','bc250-combined-wait-diagnostic')
    change('"pr_requests","pr_members"};unsigned pending[9]={};','"pr_requests","pr_members","fw_slots","fw_calls","cv_bookmarks","cv_origins"};unsigned pending[13]={};')
    change('for(unsigned i=0;i<9;i++)','for(unsigned i=0;i<13;i++)',2)
    change('const char *maps[]={',
        'uint64_t wait_stats[16]={},vector_stats[16]={};int waitfd=bpf_object__find_map_fd_by_name(object,"fw_counters"),vectorfd=bpf_object__find_map_fd_by_name(object,"cv_counters");\n'
        '    if(waitfd<0 || vectorfd<0)goto cleanup;\n'
        '    for(uint32_t i=0;i<16;i++){if(bpf_map_lookup_elem(waitfd,&i,&wait_stats[i]) || bpf_map_lookup_elem(vectorfd,&i,&vector_stats[i]))goto cleanup;}\n'
        '    const char *maps[]={')
    change(r'printf("],\"records\":[");',
        r'printf("],\"wait_counters\":[");for(unsigned i=0;i<16;i++){printf("%s%" PRIu64,i?",":"",wait_stats[i]);}printf("],\"vector_counters\":[");for(unsigned i=0;i<16;i++){printf("%s%" PRIu64,i?",":"",vector_stats[i]);}printf("],\"records\":[");')
    change(r'\"callback_identity_witnessed\":true',r'\"vector_proof_enabled\":%s,\"folio_proof_enabled\":%s,\"callback_identity_witnessed\":true')
    change(',issue_proof?"true":"false");status=0;',',issue_proof?"true":"false",vector_proof?"true":"false",folio_proof?"true":"false");status=0;')
    return source
