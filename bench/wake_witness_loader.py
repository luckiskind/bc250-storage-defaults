"""Checked addition of three independent wake witness programs."""
import json
import re
from handoff_wait_loader import generate as handoff_generate,replace_once


def generate(source):
    s=handoff_generate(source)
    for old,new in [('#define PROGRAMS 28','#define PROGRAMS 31'),('if(argc!=11 || geteuid()!=0)','if(argc!=12 || geteuid()!=0)'),
        ('vector_proof=number(argv[9],0,1),folio_proof=number(argv[10],0,1);','vector_proof=number(argv[9],0,1),folio_proof=number(argv[10],0,1),witness_proof=number(argv[11],0,1);'),
        ('if(proof<0 || issue_proof<0 || vector_proof<0 || folio_proof<0 || stat(argv[7],&device)',
         'if(proof<0 || issue_proof<0 || vector_proof<0 || folio_proof<0 || witness_proof<0 || stat(argv[7],&device)'),
        ('BC250_HANDOFF_WAIT_READY','BC250_WAKE_WITNESS_READY'),('bc250-handoff-wait-diagnostic','bc250-wake-witness-diagnostic'),
        ('"cv_bookmarks","cv_origins"};unsigned pending[13]={};','"cv_bookmarks","cv_origins","tw_calls"};unsigned pending[14]={};')]:s=replace_once(s,old,new)
    if s.count('for(unsigned i=0;i<13;i++)')!=2:raise ValueError('Handoff pending map loop drift')
    s=s.replace('for(unsigned i=0;i<13;i++)','for(unsigned i=0;i<14;i++)')
    names=re.search(r'const char \*names\[\]=\{[^;]+\};',s)
    if not names:raise ValueError('Missing handoff attach list')
    s=replace_once(s,names[0],names[0].replace('};',',"tw_enter","tw_waking","tw_exit"};'))
    s=replace_once(s,'fprintf(stderr,"BC250_PHYSICAL_SEED_READY\\n");',
        'uint32_t witness_option=witness_proof;int twfd=bpf_object__find_map_fd_by_name(object,"tw_cfg");\n'
        '    if(twfd<0 || bpf_map_update_elem(twfd,&zero,&witness_option,BPF_ANY))goto cleanup;\n'
        '    fprintf(stderr,"BC250_PHYSICAL_SEED_READY\\n");')
    s=replace_once(s,'const char *maps[]={',
        'uint64_t witness_stats[16]={};int twstats=bpf_object__find_map_fd_by_name(object,"tw_counters");\n'
        '    if(twstats<0)goto cleanup;\n'
        '    for(uint32_t i=0;i<16;i++){if(bpf_map_lookup_elem(twstats,&i,&witness_stats[i]))goto cleanup;}\n'
        '    const char *maps[]={')
    s=replace_once(s,r'printf("],\"records\":[");',
        r'printf("],\"witness_counters\":[");for(unsigned i=0;i<16;i++){printf("%s%" PRIu64,i?",":"",witness_stats[i]);}printf("],\"records\":[");')
    s=replace_once(s,r'\"scheduler_timestamp_basis\":\"hook-entry-v1\"',r'\"witness_enabled\":%s,\"scheduler_timestamp_basis\":\"hook-entry-v1\"')
    s=replace_once(s,',folio_proof?"true":"false");status=0;',',folio_proof?"true":"false",witness_proof?"true":"false");status=0;')
    return s


def ready_ids(log):
    for line in log.split(b'\n')[:-1]:
        if line.startswith(b'BC250_WAKE_WITNESS_READY '):
            ids=json.loads(line.split(b' ',1)[1])['program_ids']
            if len(ids)!=31 or len(set(ids))!=31 or any(type(n) is not int or n<=0 for n in ids):raise ValueError('Thirty-one distinct owned programs required')
            return ids
    return None
