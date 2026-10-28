#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/openat2.h>
#include <sys/syscall.h>
#include <unistd.h>

/* O_PATH observes metadata only. Absolute symlinks stay inside the pinned root;
 * proc-style magic links are refused instead of escaping the selected view. */
int bc_open_rooted(int rootfd,const char *path) {
    struct open_how how={.flags=O_PATH|O_CLOEXEC,
        .resolve=RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS};
    return syscall(SYS_openat2,rootfd,path,&how,sizeof(how));
}
