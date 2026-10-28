#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/mount.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <unistd.h>

int bc_bind(const char *source,const char *target,int recursive,int readonly) {
    if(mount(source,target,NULL,MS_BIND|(recursive?MS_REC:0),NULL))return errno;
    if(readonly && mount(NULL,target,NULL,MS_BIND|MS_REMOUNT|MS_RDONLY,NULL))return errno;
    return 0;
}
int bc_readonly_tree(const char *target) {
    struct mount_attr attr={.attr_set=MOUNT_ATTR_RDONLY};
    if(syscall(SYS_mount_setattr,AT_FDCWD,target,AT_RECURSIVE,&attr,sizeof(attr)))return errno;
    return 0;
}
int bc_tmpfs(const char *target) {
    if(mount("tmpfs",target,"tmpfs",MS_NOSUID|MS_NODEV,"size=16m,mode=0755"))return errno;
    return 0;
}
