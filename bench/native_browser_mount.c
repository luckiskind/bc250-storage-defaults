#include "native_input_mount.c"

/* This runs only inside the fixture's private mount namespace while root.
 * Make the new mount the namespace root so nested user namespaces remain
 * available to Firefox/Glycin after the controller drops its privileges. */
int bc_pivot(const char *root) {
    if(chdir(root))return errno;
    if(syscall(SYS_pivot_root,".","."))return errno;
    if(umount2(".",MNT_DETACH))return errno;
    if(chdir("/"))return errno;
    return 0;
}
