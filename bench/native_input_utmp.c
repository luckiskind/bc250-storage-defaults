#define _GNU_SOURCE
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <utmpx.h>

int main(int argc,char **argv) {
    if(argc!=2 || strncmp(argv[1],"pts/",4))return 2;
    struct passwd *pw=getpwuid(getuid());if(!pw)return 2;
    if(utmpxname("/run/utmp"))return 2;
    unsigned total=0,matching=0;struct utmpx *row;
    setutxent();
    while((row=getutxent())) {
        total++;
        if(row->ut_type==USER_PROCESS && !strncmp(row->ut_line,argv[1],sizeof(row->ut_line))
            && !strncmp(row->ut_user,pw->pw_name,sizeof(row->ut_user)))matching++;
    }
    endutxent();
    printf("{\"records\":%u,\"owned_user_tty_records\":%u}\n",total,matching);
    return matching==1?0:1;
}
