"""Checked request-generation loader derivation without changing either reference."""
import json
import re
from physical_bio_loader import generate as physical_generate


def ready_ids(log):
    for line in log.split(b'\n')[:-1]:
        if line.startswith(b'BC250_REQUEST_BIO_READY '):
            ids=json.loads(line.split(b' ',1)[1])['program_ids']
            if len(ids)!=24 or len(set(ids))!=24 or any(type(n) is not int or n<=0 for n in ids):raise ValueError('Twenty-four distinct program IDs required')
            return ids
    return None


def generate(source):
    source=physical_generate(source)
    def change(old,new,count=1):
        nonlocal source
        if source.count(old)!=count:raise ValueError('Physical loader template differs: '+old[:70])
        source=source.replace(old,new)
    change('#define PROGRAMS 22','#define PROGRAMS 24')
    change('if(argc!=8 || geteuid()!=0)','if(argc!=9 || geteuid()!=0)')
    change('long proof=number(argv[6],0,1);struct stat device;',
        'long proof=number(argv[6],0,1),issue_proof=number(argv[8],0,1);struct stat device;')
    change('if(proof<0 || stat(argv[7],&device)','if(proof<0 || issue_proof<0 || stat(argv[7],&device)')
    change('if(bpf_object__load(object))goto cleanup;',
        'struct bpf_program *old=bpf_object__find_program_by_name(object,"pb_complete");\n'
        '    if(!old || bpf_program__set_autoload(old,0))goto cleanup;\n'
        '    if(bpf_object__load(object))goto cleanup;')
    match=re.search(r'const char \*names\[\]=\{[^;]+\};',source)
    if not match:raise ValueError('Missing physical program list')
    change(match[0],match[0].replace('"pb_complete"','"pr_issue","pr_requeue","pr_complete"'))
    change('fprintf(stderr,"BC250_PHYSICAL_SEED_READY\\n");',
        'uint32_t issue_enabled=issue_proof;int issuefd=bpf_object__find_map_fd_by_name(object,"pr_cfg");\n'
        '    if(issuefd<0 || bpf_map_update_elem(issuefd,&zero,&issue_enabled,BPF_ANY))goto cleanup;\n'
        '    fprintf(stderr,"BC250_PHYSICAL_SEED_READY\\n");')
    change('BC250_PHYSICAL_BIO_READY','BC250_REQUEST_BIO_READY')
    change('bc250-physical-bio-diagnostic','bc250-request-bio-diagnostic')
    change('"pb_bios","pb_splits"};unsigned pending[7]={};','"pb_bios","pb_splits","pr_requests","pr_members"};unsigned pending[9]={};')
    change('for(unsigned i=0;i<7;i++)','for(unsigned i=0;i<9;i++)',2)
    change('uint64_t key=0,next=0;if(m<0)goto cleanup;','uint64_t key[2]={},next[2]={};if(m<0)goto cleanup;')
    change('int r=bpf_map_get_next_key(m,NULL,&key);','int r=bpf_map_get_next_key(m,NULL,key);')
    change('r=bpf_map_get_next_key(m,&key,&next);key=next;','r=bpf_map_get_next_key(m,key,next);memcpy(key,next,sizeof(key));')
    change('const char *maps[]={',
        'uint64_t request_stats[24]={};int requestfd=bpf_object__find_map_fd_by_name(object,"pr_counters");if(requestfd<0)goto cleanup;\n'
        '    for(uint32_t i=0;i<24;i++){if(bpf_map_lookup_elem(requestfd,&i,&request_stats[i]))goto cleanup;}\n'
        '    const char *maps[]={')
    change(r'printf("],\"records\":[");',
        r'printf("],\"request_counters\":[");for(unsigned i=0;i<24;i++){printf("%s%" PRIu64,i?",":"",request_stats[i]);}printf("],\"records\":[");')
    change(r'\"callback_identity_witnessed\":true',r'\"issue_proof_enabled\":%s,\"callback_identity_witnessed\":true')
    change(',proof?"true":"false");status=0;',',proof?"true":"false",issue_proof?"true":"false");status=0;')
    return source
