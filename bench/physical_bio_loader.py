"""Checked loader derivation; callback identity stays in a temporary BPF map."""
import json
import re


def ready_ids(log):
    # Pipe reads can stop halfway through the JSON, even after seed readiness.
    for line in log.split(b'\n')[:-1]:
        if line.startswith(b'BC250_PHYSICAL_BIO_READY '):
            ids=json.loads(line.split(b' ',1)[1])['program_ids']
            if len(ids)!=22 or any(type(n) is not int or n<=0 for n in ids) or len(set(ids))!=22:
                raise ValueError('Twenty-two distinct owned program IDs required')
            return ids
    return None


def generate(source):
    def change(old,new,count=1):
        nonlocal source
        if source.count(old)!=count:raise ValueError('Reference loader template differs: '+old[:70])
        source=source.replace(old,new)
    change('#define PROGRAMS 16','#define PROGRAMS 22')
    change('#include <errno.h>','#include <errno.h>\n#include <string.h>\n#include <poll.h>\n#include <sys/sysmacros.h>')
    change('if(argc!=6 || geteuid()!=0)','if(argc!=8 || geteuid()!=0)')
    change('struct line_config cfg={.pid=pid,.fd=fd};',
        'long proof=number(argv[6],0,1);struct stat device;\n'
        '    if(proof<0 || stat(argv[7],&device) || !S_ISBLK(device.st_mode))return 2;\n'
        '    struct pb_dev {uint32_t major,minor;} dev={major(device.st_rdev),minor(device.st_rdev)};\n'
        '    struct line_config cfg={.pid=pid,.fd=fd,.pad=proof?0:1};')
    names=['data_exit','decomp_exit','sleep_exit','read_exit','fault_exit','map_exit','data_enter','decomp_enter','sleep_enter',
        'compressed_done','compressed_enter','bio_enter','read_enter','fault_enter','map_enter','unlock_call',
        'pb_witness','pb_root','pb_split_enter','pb_split_exit','pb_submit','pb_complete']
    match=re.search(r'const char \*names\[\]=\{[^;]+\};',source)
    if not match:raise ValueError('Missing program list')
    change(match[0],'const char *names[]={'+','.join('"'+n+'"' for n in names)+'};')
    change('links[i]=bpf_program__attach_trace(p);',
        'const char *section=bpf_program__section_name(p);links[i]=!strncmp(section,"raw_tp/",7)?bpf_program__attach_raw_tracepoint(p,section+7):bpf_program__attach_trace(p);')
    change('uint64_t start=now();cfg.enabled=1;',
        'int identityfd=bpf_object__find_map_fd_by_name(object,"pb_identity"),devfd=bpf_object__find_map_fd_by_name(object,"pb_device");\n'
        '    if(identityfd<0 || devfd<0 || bpf_map_update_elem(devfd,&zero,&dev,BPF_ANY))goto cleanup;\n'
        '    fprintf(stderr,"BC250_PHYSICAL_SEED_READY\\n");fflush(stderr);\n'
        '    struct pollfd input={.fd=STDIN_FILENO,.events=POLLIN};char ack=0;uint64_t identity=0;\n'
        '    if(poll(&input,1,8000)!=1 || read(STDIN_FILENO,&ack,1)!=1 || ack!=\'G\' || bpf_map_lookup_elem(identityfd,&zero,&identity) || !identity)goto cleanup;\n'
        '    uint64_t start=now();cfg.enabled=1;')
    change('BC250_READ_LINEAGE_READY','BC250_PHYSICAL_BIO_READY')
    change('bc250-read-lineage-diagnostic','bc250-physical-bio-diagnostic')
    change('"endings","sleeps"};unsigned pending[5]={};','"endings","sleeps","pb_bios","pb_splits"};unsigned pending[7]={};')
    change('for(unsigned i=0;i<5;i++)','for(unsigned i=0;i<7;i++)',2)
    change('const char *maps[]={',
        'uint64_t physical_stats[16]={};int physicalfd=bpf_object__find_map_fd_by_name(object,"pb_counters");if(physicalfd<0)goto cleanup;\n'
        '    for(uint32_t i=0;i<16;i++){if(bpf_map_lookup_elem(physicalfd,&i,&physical_stats[i]))goto cleanup;}\n'
        '    const char *maps[]={')
    change(r'printf("],\"records\":[");',
        r'printf("],\"physical_counters\":[");for(unsigned i=0;i<16;i++){printf("%s%" PRIu64,i?",":"",physical_stats[i]);}printf("],\"records\":[");')
    change(r'printf("],\"links_detached\":true,\"maps_pinned\":false,\"critical_path_attribution_qualified\":false,\"overhead_qualified\":false}\n");status=0;',
        r'printf("],\"callback_proof_enabled\":%s,\"callback_identity_witnessed\":true,\"links_detached\":true,\"maps_pinned\":false,\"critical_path_attribution_qualified\":false,\"overhead_qualified\":false}\n",proof?"true":"false");status=0;')
    return source
