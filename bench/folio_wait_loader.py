"""Checked derivation of a separate loader; the qualified reference stays intact."""
import re


def generate(source):
    def change(old,new,count=1):
        nonlocal source
        if source.count(old)!=count:raise ValueError('Reference loader template differs: '+old[:70])
        source=source.replace(old,new)
    change('#define PROGRAMS 16','#define PROGRAMS 21')
    change('#include <errno.h>','#include <errno.h>\n#include <string.h>')
    change('if(argc!=6 || geteuid()!=0)','if(argc!=7 || geteuid()!=0)')
    change('struct line_config cfg={.pid=pid,.fd=fd};','long proof=number(argv[6],0,1);if(proof<0)return 2;struct line_config cfg={.pid=pid,.fd=fd,.pad=proof?0:1};')
    change('if(bpf_object__load(object))goto cleanup;',
        'struct bpf_program *old0=bpf_object__find_program_by_name(object,"sleep_enter"),*old1=bpf_object__find_program_by_name(object,"sleep_exit");\n'
        '    if(!old0 || !old1 || bpf_program__set_autoload(old0,0) || bpf_program__set_autoload(old1,0))goto cleanup;\n'
        '    if(bpf_object__load(object))goto cleanup;')
    names=['data_exit','decomp_exit','fw_sleep_exit','read_exit','fault_exit','map_exit','data_enter','decomp_enter','fw_sleep_enter',
        'compressed_done','compressed_enter','bio_enter','read_enter','fault_enter','map_enter','unlock_call',
        'fw_match_exit','fw_match_enter','fw_sched_switch','fw_sched_waking','fw_sched_wakeup']
    match=re.search(r'const char \*names\[\]=\{[^;]+\};',source)
    if not match:raise ValueError('Missing program list')
    change(match[0],'const char *names[]={'+','.join('"'+name+'"' for name in names)+'};')
    change('links[i]=bpf_program__attach_trace(p);',
        'const char *section=bpf_program__section_name(p);links[i]=!strncmp(section,"raw_tp/",7)?bpf_program__attach_raw_tracepoint(p,section+7):bpf_program__attach_trace(p);')
    change('"endings","sleeps"};unsigned pending[5]={};','"endings","sleeps","fw_slots","fw_calls"};unsigned pending[7]={};')
    change('for(unsigned i=0;i<5;i++)','for(unsigned i=0;i<7;i++)',2)
    change('BC250_READ_LINEAGE_READY','BC250_FOLIO_WAIT_READY')
    change('bc250-read-lineage-diagnostic','bc250-folio-wait-diagnostic')
    change('const char *maps[]={',
        'uint64_t wait_stats[16]={};int waitfd=bpf_object__find_map_fd_by_name(object,"fw_counters");if(waitfd<0)goto cleanup;\n'
        '    for(uint32_t i=0;i<16;i++){if(bpf_map_lookup_elem(waitfd,&i,&wait_stats[i]))goto cleanup;}\n'
        '    const char *maps[]={')
    change(r'printf("],\"records\":[");',
        r'printf("],\"wait_counters\":[");for(unsigned i=0;i<16;i++){printf("%s%" PRIu64,i?",":"",wait_stats[i]);}printf("],\"records\":[");')
    change(r'printf("],\"links_detached\":true,\"maps_pinned\":false,\"critical_path_attribution_qualified\":false,\"overhead_qualified\":false}\n");status=0;',
        r'printf("],\"folio_proof_enabled\":%s,\"links_detached\":true,\"maps_pinned\":false,\"critical_path_attribution_qualified\":false,\"overhead_qualified\":false}\n",proof?"true":"false");status=0;')
    return source
