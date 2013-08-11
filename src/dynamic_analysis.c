/*
  This code is based on Michal Zalewski's fakebust, available on:
  http://lcamtuf.coredump.cx/soft/fakebust.tgz

  fakebust is distributed under the GNU Lesser General Public License v2.1, as
  can be seen on the LICENSE file available with the project.
*/

#include "util.h"
#include "dynamic_analysis.h"

#include <getopt.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <malelf/error.h>
#include <malelf/util.h>

#include "dynanalyse_config.h"
#include "ioctls.h"
#include "messages.h"

#define LAIR_SIZE (16 * 4) /* Must be a multiple of 4 */
#define D_ABORT  0
#define D_PERMIT 1
#define D_ALL    2
#define D_SINK   3
#define NOSINK   0x0DEFACED

#define CRET_NONE	  0
#define CRET_ACCEPT	  1
#define CRET_RECVFROM 2

static struct { char* name; _u32 num; } sclist[] = {
#include "sctab-list.h"
};

static struct Permitted_action { _u32 sysnum; char* filename; char mode; } permitted_actions[256];
static _u32 permitted_count = 0;

static _u8 local, sink_syscall, iamroot;
static _i32 tpid, syscall_result;
static _u32 child_umask, check_ret, rpar1, rpar2, rpar3;
static _u32 secret_lair, secret_copy[LAIR_SIZE/4];
static _u8  secret_buried, skip_eip_check;

static struct termios clean_term, cur_term, canoe_term;

static _u8 isauto = 0;
static FILE* outfd = NULL;

static void clean_exit(_i32 code) {
        static struct user_regs_struct r;

        if (tpid > 0) {
                /* We need to zero registers; otherwise, the current syscall will
                   be carried out before SIGKILL, which is not always what we want. */
                ptrace(PTRACE_SETREGS, tpid, &r, 0);
                kill(tpid, SIGKILL);
        }
        tcsetattr(0, 0, &clean_term);
        exit(code);
}

static void fatal_exit(char* format, ...){
        va_list args;
        va_start(args, format);
        malelf_error(format, args);
        clean_exit(1);
}

static char* getstring(_u32 ptr) {
        static char gsret[MAXSTRING+8];
        _u32* wtab = (_u32*)gsret;
        _u32 cur = 0;

        while (cur < MAXSTRING/4) {
                errno = 0;
                wtab[cur] = ptrace(PTRACE_PEEKDATA, tpid, ptr, 0);
                if (errno) { wtab[cur] = 0; return gsret; }
                if (!(gsret[cur*4] && gsret[cur*4+1] && gsret[cur*4+2] &&
                      gsret[cur*4+3])) return gsret;
                cur++; ptr += 4;
        }

        wtab[cur] = 0;
        return gsret;

}

static char* findpath(_u32 addr) {
        static char fp[MAXSTRING*2+32],cwd[MAXSTRING], rp[PATH_MAX+1];
        char *x = getstring(addr);

        if (!x[0])
                return "<EMPTY PATH>";

        if (x[0] != '/') {
                _i32 rl;
                sprintf(fp,"/proc/%d/cwd",tpid);
                rl = readlink(fp,cwd,MAXSTRING-1);

                if (rl > 0)
                        cwd[rl] = 0;
                else
                        strcpy(cwd,"<UNKNOWN>");

                sprintf(fp,"%s/%s",cwd,x);
                x = fp;
        }

        /* We purposefully ignore the return value.
           Using some tricks so that gcc won't complain about it */
        memset(rp,0,sizeof(rp));
        char* useless = realpath(x,rp);
        (void)useless;
        if (rp[0])
                return rp;
        else
                return x;

        return "<EMPTY PATH>";
}

static char* getfdpath(_u32 fd) {
        static char tmp[128],fp[MAXSTRING+8];
        _i32 rl;

        sprintf(tmp,"/proc/%d/fd/%u",tpid,fd);
        rl = readlink(tmp,fp,MAXSTRING-1);

        if (rl > 0) fp[rl] = 0; else
                sprintf(fp,"<UNKNOWN FILE DESCRIPTOR %d>",fd);

        return fp;

}

static void create_child(char* prog, char** argv) {
        _i32 st;

        if ((tpid = fork()) < 0)
                fatal_exit("Cannot spawn child");

        if (!tpid) {
                if (ptrace(PTRACE_TRACEME, getppid(), 0, 0))
                        fatal_exit("ptrace() failed");

                execvp(prog,argv);

                fatal_exit("Cannot execute program");
        }

        if (waitpid(tpid, &st, WUNTRACED) < 0 || !WIFSTOPPED(st)) {
                malelf_error("--- Error executing program ---\n");
                clean_exit(1);
        }

}

static char* find_sysname(_u32 num) {
        _u32 i = 0;

        while (sclist[i].num < num && sclist[i].name) i++;

        if (sclist[i].name && sclist[i].num == num)
                return sclist[i].name;

        return "<UNKNOWN>";

}

static char* find_ioctl(_u32 num, char* safe) {
        _u32 i = 0;

        *safe = 0;

        while (iolist[i].num < num && iolist[i].name) i++;
        if (iolist[i].name && iolist[i].num == num) {
                *safe = iolist[i].safe;
                return iolist[i].name;
        }

        return "<UNKNOWN>";

}

static void warn_banner(_u8 pri) {

        tcgetattr(0, &cur_term);
        tcsetattr(0, 0, &clean_term);

        if (pri == 0) malelf_print(outfd,".---------------.\n"
                                   "| Security Note |\n"
		                   "`---------------'\n");

        else if (pri == 1) malelf_print(outfd,"********************\n"
                                        "* SECURITY WARNING *\n"
                                        "********************\n");

        else malelf_print(outfd,"******************\n"
                          "* ABUSE ALERT!!! *\n"
                          "******************\n");

        malelf_print(outfd,"\n");

}

static void handle_selection(_i8 def, _i32 defret) {
        _u8 ibuf[256];
        _i32 r;

        if (defret == NOSINK) {

                malelf_print(outfd,
                             ".-----------------------------+-----------------------------.\n"
                             "| 1) Abort program %3s        | 2) Permit action once %3s   |\n"
                             "| 3) Permit future access %3s |                             |\n"
                             "`-----------------------------+-----------------------------'\n"
                             "\n"
                             "Enter your selection: ",
                             def == 0 ? "(*)" : "   ",
                             def == 1 ? "(*)" : "   ",
                             def == 2 ? "(*)" : "   ");

        } else {

                malelf_print(outfd,
                             ".-----------------------------+-----------------------------.\n"
                             "| 1) Abort program %3s        | 2) Permit action once %3s   |\n"
                             "| 3) Permit future access %3s | 4) Sink syscall! %3s        |\n"
                             "`-----------------------------+-----------------------------'\n"
                             "\n"
                             "Enter your selection: ",
                             def == 0 ? "(*)" : "   ",
                             def == 1 ? "(*)" : "   ",
                             def == 2 ? "(*)" : "   ",
                             def == 3 ? "(*)" : "   ");
        }

        if(isauto){
                /* Same outcome of choosing opion 2, i.e., allow the syscall to execute once*/
                malelf_print(outfd,"2 (permit)\n");
                return;
        }

reread_input:

        /* No echo */
        tcsetattr(0, 0, &canoe_term);

        fcntl(0,F_SETFL,O_NONBLOCK);
        while (read(0,ibuf,sizeof(ibuf)) > 0);
        fcntl(0,F_SETFL,O_SYNC);

        r = read(0,ibuf,sizeof(ibuf));

        tcsetattr(0, 0, &cur_term);

        if (r <= 0)
                fatal_exit("Unexpected EOF");

        /* Handle default */
        if (ibuf[0] == '\n')
                ibuf[0] = '1' + def;

        switch (ibuf[0]) {
        case 0x1B: /* ESC */
        case '1':
                malelf_print(outfd,"1 (abort)\n");
                fatal_exit("Program terminated");

        case '2':
                malelf_print(outfd,"2 (permit)\n");
                break;

        case '3':
                //TODO Correctly append this action to the list of permitted

                if (permitted_count < 256){
                        malelf_print(outfd,"3 (allow all)\n");
                        struct Permitted_action perm;
                        perm.sysnum = 0;
                        perm.filename = "/tmp";
                        perm.mode = 'r';
                        permitted_actions[permitted_count] = perm;
                        permitted_count++;
                }
                break;

        case '4':
                if (defret != NOSINK) {
                        malelf_print(outfd,"4 (sink!)\n");
                        sink_syscall = 1;
                        syscall_result = defret;
                        break;
                } /* else fall through */

        default:
                goto reread_input;
        }
}

static void handle_selection_fork(void) {
        _u8 ibuf[256];
        _i32 r;

        malelf_print(outfd,
                     ".--------------------------------+---------------------------------.\n"
                     "| 1) Abort program               | 2) Trace child, kill parent (*) |\n"
                     "| 3) Trace parent, kill child    |                                 |\n"
                     "`--------------------------------+---------------------------------'\n"
                     "\n"
                     "Enter your selection: ");

        if(isauto){
                /* Same outcome of option 2, i.e., kill the parent and trace the child*/
                malelf_print(outfd,"2 (child)\n");
                sink_syscall = 1;
                syscall_result = 0;
                return;
        }

reread_input:

        /* No echo */
        tcsetattr(0, 0, &canoe_term);

        fcntl(0,F_SETFL,O_NONBLOCK);
        while (read(0,ibuf,sizeof(ibuf)) > 0);
        fcntl(0,F_SETFL,O_SYNC);

        r = read(0,ibuf,sizeof(ibuf));
        tcsetattr(0, 0, &cur_term);

        if (r <= 0) fatal_exit("Unexpected EOF");

        switch (ibuf[0]) {
        case 0x1B: /* ESC */
        case '1':
                malelf_print(outfd,"1 (abort)\n");
                fatal_exit("Program terminated");

        case '2':
                malelf_print(outfd,"2 (child)\n");
                sink_syscall = 1; syscall_result = 0;
                break;

        case '3':
                malelf_print(outfd,"3 (parent)\n");
                sink_syscall = 1;
                syscall_result = tpid;
                break;

        default:
                goto reread_input;
        }

}

static char* clean_name(char* name) {
        static char rbuf[80];
        _u32 l = strlen(name),i;

        if (l > 60) {
                strncpy(rbuf,name,25);
                strcat(rbuf,"(...)");
                strcat(rbuf,name+l-25);
        } else strcpy(rbuf,name);

        l = strlen(rbuf);
        for (i=0;i<l;i++) if (rbuf[i] < ' ' || rbuf[i] > '~') rbuf[i]='?';
        return rbuf;

}

static _u8 isroot(void) {
        char tmp[512], isroot = 0;
        FILE* x;
        sprintf(tmp,"/proc/%d/status",tpid);
        x = fopen(tmp,"r");
        if (!x) return iamroot; /* uh? */

        while (fgets(tmp,sizeof(tmp),x)) {
                if (!strncasecmp("Uid:",tmp,4)) {
                        _u32 i;
                        for (i=4;i<strlen(tmp);i++)
                                if (tmp[i] == '0' && !isdigit(tmp[i-1])) { isroot=1; break; }
                        break;
                }
        }

        fclose(x);
        return isroot;

}

static char* check_addr(_u32 fd) {

        struct stat st;
        static char buf[1024];
        _u8 rep = 0;

        sprintf(buf,"/proc/%u/fd/%u", tpid, fd);
        if (stat(buf, &st) || !S_ISSOCK(st.st_mode))
                return "<UNKNOWN>";

        while (rep < 2) {
                FILE* f;
                f = fopen(rep ? "/proc/net/udp" : "/proc/net/tcp","r");

                while (fgets(buf,sizeof(buf),f)) {
                        _u8 sa[4], da[4];
                        _u32 sp, dp, ino;

                        if (sscanf(buf,"%*d: %x:%x %x:%x %*x %*x:%*x %*x:%*x %*x %*x %*x %u",
                                   (_u32*)sa, &sp, (_u32*)da, &dp, &ino) < 5) continue;

                        // malelf_print(outfd,"read ino = %d st.st_ino = %d\n",ino,st.st_ino);

                        if (ino != st.st_ino) continue;

                        sprintf(buf,"%u.%u.%u.%u:%u <-> %u.%u.%u.%u:%u (%s)",
                                sa[0], sa[1], sa[2], sa[3], sp,
                                da[0], da[1], da[2], da[3], dp, rep ? "UDP" : "TCP");
                        fclose(f);
                        return buf;
                }

                fclose(f);
                rep++;
        }

        return "<UNKNOWN>";
}

static void handle_ioctl(struct user_regs_struct* r){
        char safe, *inam;
        inam = find_ioctl((_u32)r->ecx,&safe);

        if (!safe) {
                char* fn = getfdpath(r->ebx);

                warn_banner(1);
                malelf_print(outfd,MSG6);

                malelf_print(outfd,"Request   : %s\n"
                             "Req. code : 0x%04X\n"
                             "File name : %s\n\n",
                             inam,(_u32)r->ecx, clean_name(fn));

                handle_selection(D_PERMIT, 0);
        }
}

static int check_for_shell(char* filename){
        _u32 i = 0;

        while (shells[i]) {
                if (strstr(filename, shells[i]))
                        return 1;
                i++;
        }
        return 0;
}

static void copy_file_contents(char* sourcefile, char* destfile){
        FILE* sf = fopen(sourcefile, "r");
        FILE* df = fopen(destfile, "w");
        _i32 c;

        while((c=getc(sf))!=EOF)
                fprintf(df,"%c",c);

        fclose(sf);
        fclose(df);

}

static void handle_link(_u32 sysnum, struct user_regs_struct* r){
        char* fn = findpath(r->ebx), exists = 1;
        struct stat st;
        if (stat(fn,&st)) exists=0;

        if (local) {
                warn_banner(0);
                malelf_print(outfd,MSG7, sysnum == 9 ? "HARD " : "SYM");
        } else {
                warn_banner(2);
                malelf_print(outfd,MSG8, sysnum == 9 ? "HARD " : "SYM");
        }

        malelf_print(outfd,"File name : %s\n",clean_name(fn));

        if (exists) {
                if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))
                        malelf_print(outfd,"WARNING   : *** This is a special (device) file! ***\n");
                else if (st.st_nlink != 1)
                        malelf_print(outfd,"WARNING   : *** This is a hard link! ***\n");
        }

        fn = findpath(r->ecx);
        malelf_print(outfd,"Link name : %s\n",clean_name(fn));

        malelf_print(outfd,"\n");
        handle_selection(local ? D_PERMIT : D_ABORT, 0);
}

static void handle_unlink(struct user_regs_struct* r){
        char* fn = findpath(r->ebx);

        warn_banner(0);
        malelf_print(outfd,MSG9);

        malelf_print(outfd,"File name : %s\n\n",clean_name(fn));
        handle_selection(D_SINK, 0);
}

static void handle_chmod(_u32 sysnum, struct user_regs_struct* r){
        char* fn = (sysnum == 94) ? getfdpath(r->ebx) : findpath(r->ebx);
        _u8 def = D_ABORT;

        if (r->ecx & (S_ISUID|S_ISGID)) {
                warn_banner(2);
                malelf_print(outfd,MSG13);
        } else if (r->ecx & S_IWOTH) {
                warn_banner(2);
                malelf_print(outfd,MSG14);
        } else {
                if (local) {
                        warn_banner(0);
                        malelf_print(outfd,MSG15);
                        def = D_PERMIT;
                } else {
                        warn_banner(1);
                        malelf_print(outfd,MSG16);
                        def = D_SINK;
                }
        }

        malelf_print(outfd,"File name   : %s\n",clean_name(fn));
        malelf_print(outfd,"Permissions : 0%04o\n\n",r->ecx);
        handle_selection(def, 0);
}

static void handle_chown(_u32 sysnum, struct user_regs_struct* r){
        if (isroot()) {
                char* fn = ((sysnum == 95) || (sysnum == 207)) ?
                        getfdpath(r->ebx) : findpath(r->ebx);

                warn_banner(2);
                malelf_print(outfd,MSG17);

                malelf_print(outfd,"File path : %s\n",clean_name(fn));
                malelf_print(outfd,"New owner : %u.%u\n\n",r->ecx,r->edx);

                handle_selection(D_ABORT, 0);
        }
}

static void handle_mount(struct user_regs_struct* r){
        if (isroot()) {
                char* fn = findpath(r->ebx);

                warn_banner(2);
                malelf_print(outfd,MSG18);

                malelf_print(outfd,"Device      : %s\n",clean_name(fn));
                fn = findpath(r->ecx);
                malelf_print(outfd,"Mount point : %s\n",clean_name(fn));
                fn = getstring(r->edx);
                malelf_print(outfd,"Filesystem  : %s\n\n",clean_name(fn));

                handle_selection(D_ABORT, 0);

        }
}

static void handle_umount(struct user_regs_struct* r){
        if (isroot()) {
                char* fn = findpath(r->ebx);

                warn_banner(2);
                malelf_print(outfd,MSG19);

                malelf_print(outfd,"Mount point : %s\n\n",clean_name(fn));
                handle_selection(D_ABORT, 0);

        }
}

static void handle_stime(struct user_regs_struct* r){
        if (isroot()) {
                _u32 nt;

                errno = 0;
                nt = ptrace(PTRACE_PEEKDATA, tpid, r->ebx, 0);
                if (errno) nt = 0;

                warn_banner(2);
                malelf_print(outfd,MSG20);

                if (nt) {
                        char* x = ctime((time_t*)&nt);
                        if (*(x+strlen(x)-1) == '\n') *(x+strlen(x)-1) = 0;
                        malelf_print(outfd,"New time    : %s\n",x);
                        malelf_print(outfd,"Time offset : %+d seconds\n\n",nt - (_u32)time(0));
                }

                handle_selection(D_SINK, 0);
        }
}

static void handle_ptrace(struct user_regs_struct* r){
        if (r->ebx != PTRACE_ATTACH && r->ebx != PTRACE_TRACEME) return;

        if (r->ebx == PTRACE_TRACEME) {
                warn_banner(1);
                malelf_print(outfd,"Possible anti-debugging trick!!!\n");
                malelf_print(outfd,"Request    : PTRACE_TRACEME\n");
                malelf_print(outfd,ABUSE_TRACEME);

                /* Sync will return SUCCESS for ptrace(PTRACE_TRACEME, 0, 1, 0) */
                handle_selection(D_ABORT, 0);
                return;
        }

        /* r->ebx == PTRACE_ATTACH */

        warn_banner(2);
        malelf_print(outfd,MSG21);
        malelf_print(outfd,"Request    : PTRACE_ATTACH\n"
                     "Target PID : %d\n\n", r->ecx);

        handle_selection(D_ABORT, -ESRCH);
}

static void handle_utime(struct user_regs_struct* r){
        _u32 at, mt;
        char* fn;

        /* NULL update is harmless */
        if (!r->ecx)
                return;

        fn = findpath(r->ebx);

        errno = 0;
        at = ptrace(PTRACE_PEEKDATA, tpid, r->ecx, 0);
        mt = ptrace(PTRACE_PEEKDATA, tpid, r->ecx + 4, 0);

        if (errno)
                at = 0;

        if (local) {
                warn_banner(1);
                malelf_print(outfd,MSG22);
        } else {
                warn_banner(2);
                malelf_print(outfd,MSG23);
        }

        malelf_print(outfd,"File name   : %s\n",clean_name(fn));

        if (at) {
                char* x = ctime((time_t*)&at);
                if (*(x+strlen(x)-1) == '\n')
                        *(x+strlen(x)-1) = 0;

                malelf_print(outfd,"Access time : %s (%+d sec)\n",x, at - (_u32)time(0));

                x = ctime((time_t*)&mt);
                if (*(x+strlen(x)-1) == '\n')
                        *(x+strlen(x)-1) = 0;

                malelf_print(outfd,"Mod. time   : %s (%+d sec)\n",x, mt - (_u32)time(0));
        }

        malelf_print(outfd,"\n");
        handle_selection(D_SINK, 0);

}

static void handle_kill(struct user_regs_struct* r){
        if (!r->ecx)
                return;

        warn_banner(1);
        malelf_print(outfd,MSG24);
        malelf_print(outfd,"Target PID : %d\n"
                     "Signal     : %d\n\n", r->ebx, r->ecx);

        handle_selection(D_SINK, 0);
}

static void handle_rename(struct user_regs_struct* r){
        char* fn = findpath(r->ebx);

        if (local) {
                warn_banner(1);
                malelf_print(outfd,MSG25);
        } else {
                warn_banner(2);
                malelf_print(outfd,MSG26);
        }

        malelf_print(outfd,"Current name : %s\n",clean_name(fn));

        fn = findpath(r->ecx);
        malelf_print(outfd,"New name     : %s\n",clean_name(fn));

        malelf_print(outfd,"\n");
        handle_selection(local ? D_PERMIT : D_ABORT, 0);
}

static void handle_mkdir(struct user_regs_struct* r){
        char* fn = findpath(r->ebx);

        if (local) {
                if ((r->ecx & ~child_umask) & S_IWOTH) {
                        warn_banner(1);
                        malelf_print(outfd,MSG27);
                } else {
                        warn_banner(0);
                        malelf_print(outfd,MSG28);
                }
        } else {
                warn_banner(2);
                malelf_print(outfd,MSG29);
        }

        malelf_print(outfd,"Directory  : %s\n"
                     "Eff. perms : 0%03o\n\n",
                     clean_name(fn), r->ecx & ~child_umask);

        handle_selection(local ? D_PERMIT : D_ABORT, 0);
}

static void handle_rmdir(struct user_regs_struct* r){
        char* fn = findpath(r->ebx);

        if (local) {
                warn_banner(0);
                malelf_print(outfd,MSG30);
        } else {
                warn_banner(1);
                malelf_print(outfd,MSG31);
        }

        malelf_print(outfd,"Directory : %s\n\n",clean_name(fn));
        handle_selection(D_PERMIT, 0);
}

static void handle_acct(struct user_regs_struct* r){
        if (isroot()) {
                warn_banner(2);

                if (r->ebx) {
                        char* fn = findpath(r->ebx);
                        malelf_print(outfd,MSG32, clean_name(fn));
                } else {
                        malelf_print(outfd,MSG33);
                }
                handle_selection(D_SINK, 0);
        }
}

static void handle_chroot(struct user_regs_struct* r){
        if (isroot()) {
                char* fn = findpath(r->ebx);
                warn_banner(2);

                malelf_print(outfd,MSG34, clean_name(fn));
                handle_selection(D_SINK, 0);
        }
}

static void handle_sethostname(struct user_regs_struct* r){
        if (isroot()) {
                char* fn = getstring(r->ebx);

                warn_banner(2);
                malelf_print(outfd,MSG35, clean_name(fn));
                handle_selection(D_SINK, 0);
        }
}

static void handle_swapon(struct user_regs_struct* r){
        if (isroot()) {
                char* fn = findpath(r->ebx);

                warn_banner(2);
                malelf_print(outfd,MSG36, clean_name(fn));
                handle_selection(D_ABORT, 0);
        }
}

static void handle_reboot(){
        if (isroot()) {
                warn_banner(2);
                malelf_print(outfd,MSG37);
                handle_selection(D_SINK, 0);
        }
}

static void handle_ioperm(struct user_regs_struct* r){
        if (isroot() && r->edx) {

                warn_banner(2);
                malelf_print(outfd,MSG38);
                malelf_print(outfd,"First port : 0x%03x\n"
                             "Last port  : 0x%03x\n\n",
                             r->ebx, r->ebx + r->ecx);

                handle_selection(D_ABORT, 0);
        }
}

static void handle_syslog(struct user_regs_struct* r){
        if (isroot()) {

                warn_banner(1);
                malelf_print(outfd,MSG54);
                malelf_print(outfd,"Access type : ");

                switch (r->ebx) {
                case 0: malelf_print(outfd,"CLOSE LOG (0)\n\n"); break;
                case 1: malelf_print(outfd,"OPEN LOG (1)\n\n"); break;
                case 2: malelf_print(outfd,"READ FROM LOG (2)\n\n"); break;
                case 3: malelf_print(outfd,"READ LOG (3)\n\n"); break;
                case 4: malelf_print(outfd,"READ/CLEAR LOG (4)\n\n"); break;
                case 5: malelf_print(outfd,"CLEAR LOG (5)\n\n"); break;
                case 6: malelf_print(outfd,"DISABLE CONSOLE OUTPUT (6)\n\n"); break;
                case 7: malelf_print(outfd,"ENABLE CONSOLE OUTPUT (7)\n\n"); break;
                case 8: malelf_print(outfd,"SET CONSOLE LOG LEVEL (8)\n\n"); break;
                default: malelf_print(outfd,"<UNKNOWN> (%d)\n\n",r->ebx);
                }

                handle_selection(D_SINK, 0);
        }
}

static void handle_iopl(struct user_regs_struct* r){
        if (isroot() && r->ebx) {

                warn_banner(2);
                malelf_print(outfd,MSG55);

                handle_selection(D_ABORT, 0);

        }
}

static void handle_vhangup(){
        if (isroot()) {
                warn_banner(2);
                malelf_print(outfd,MSG56);
                handle_selection(D_SINK, 0);
        }
}

static void handle_vm86(){
        warn_banner(2);
        malelf_print(outfd,MSG57);
        handle_selection(D_SINK, 0);
}

static void handle_swapoff(){
        if (isroot()) {
                warn_banner(2);
                malelf_print(outfd,MSG58);

                handle_selection(D_ABORT, 0);
        }
}

static void handle_ipc(struct user_regs_struct* r){
        switch (r->ebx) {
        case 1: /* SEMOP */
        case 2: /* SEMGET */
        case 4: /* SEMTIMEDOP */
        case 13: /* MSGGET */
        case 22: /* SHMDT */
        case 23: /* SHMGET */
                break;

        case 3: /* SEMCTL */
        case 14: /* MSGCTL */
        case 24: /* SHMCTL */
                /*
                  TODO

                  For the sake of covering all bases, it would be good to check
                  SHMCTL, SEMCTL and MSGCTL for an attempt to delete or chmod
                  shared segments.

                */
                break;

        case 11: /* MSGSND */
                warn_banner(2);
                malelf_print(outfd,MSG59);
                malelf_print(outfd,"Queue ID  : 0x%x\n"
                             "Msg. size : %d bytes\n", r->ecx, r->esi);

                if (r->esi > 0) {
                        _u8 last16[17];
                        _u32 len = ((r->esi + 15) / 16 * 16), cur = 0;

                        if (len > 64) {
                                len = 64;
                                malelf_print(outfd,"\nPayload (first 64 bytes):\n");
                        } else malelf_print(outfd,"\nPayload:\n");

                        errno = 0;

                        while (cur < len) {
                                _u8 x = 0;
                                if (!errno)
                                        x = ptrace(PTRACE_PEEKDATA, tpid, r->esi + cur, 0);

                                if (errno) {
                                        malelf_print(outfd,"   ");
                                        last16[cur % 16] = ' ';
                                } else {
                                        malelf_print(outfd,"%02X ", x);
                                        last16[cur % 16] = (x < ' ' || x > '~') ? '.' : x;
                                }
                                cur++;

                                if (!(cur % 16)) {
                                        last16[16] = 0;
                                        malelf_print(outfd," | %s\n",last16);
                                }
                        }
                }

                malelf_print(outfd,"\n");
                handle_selection(D_ABORT, 0);

                break;

        case 12: /* MSGRCV */

                warn_banner(1);
                malelf_print(outfd,MSG60);
                malelf_print(outfd,"Queue ID  : 0x%x\n"
                             "Msg. size : %d bytes\n\n", r->ecx, r->esi);

                handle_selection(D_ABORT, 0);
                break;

        case 21: /* SHMAT */

                warn_banner(2);
                malelf_print(outfd,MSG61);
                malelf_print(outfd,"Block ID  : 0x%x\n\n", r->ecx);

                handle_selection(D_ABORT, 0);
                break;

        default:

                warn_banner(2);
                malelf_print(outfd,MSG62, r->ebx, r->ecx);

                handle_selection(D_ABORT, 0);
        }
}

static void handle_adjtimex(struct user_regs_struct* r){
        if (isroot()) {

                _u32 mod;

                errno = 0;
                mod = ptrace(PTRACE_POKEDATA, tpid, r->ebx, 0);
                if (errno) return;

                warn_banner(2);

                malelf_print(outfd,MSG63,mod);

                handle_selection(D_SINK, 0);

        }
}

static void handle_create_module(struct user_regs_struct* r){
        if (isroot()) {
                char* x = getstring(r->ebx);

                warn_banner(2);
                malelf_print(outfd,MSG64, clean_name(x));

                handle_selection(D_ABORT, 0);
        }
}

static void handle_delete_module(struct user_regs_struct* r){
        if (isroot()) {
                char* x = getstring(r->ebx);

                warn_banner(2);
                malelf_print(outfd,MSG65, clean_name(x));

                handle_selection(D_ABORT, 0);
        }
}

static void handle_sysctl(struct user_regs_struct* r){
        _u32 nam, naml, nv;

        errno = 0;
        nam  = ptrace(PTRACE_PEEKDATA, tpid, r->ebx, 0);
        naml = ptrace(PTRACE_PEEKDATA, tpid, r->ebx + 4, 0);
        nv   = ptrace(PTRACE_PEEKDATA, tpid, r->ebx + 4*4, 0);
        if (errno)
                return;

        if (nv && naml) {

                warn_banner(2);
                malelf_print(outfd,MSG66);

                if (naml > 10)
                        naml = 10;

                malelf_print(outfd,"Setting code : ");

                for (nv = 0; nv < naml; nv++) {
                        _u32 x;
                        errno = 0;
                        x = ptrace(PTRACE_PEEKDATA, tpid, nam, 0);

                        if (errno)
                                break;

                        malelf_print(outfd,".%d",x);
                        nam += 4;
                }

                malelf_print(outfd,"\n\n");

                handle_selection(D_ABORT, 0);

        }
}

static void handle_sched(struct user_regs_struct* r){
        if (isroot()) {

                if (r->ecx != SCHED_OTHER) {

                        warn_banner(1);
                        malelf_print(outfd,MSG67);

                } else if ((_i32)r->ebx != tpid) {

                        warn_banner(1);
                        malelf_print(outfd,MSG68);

                } else
                        return;

                malelf_print(outfd,"Target PID : %d\n"
                             "Priority   : %d\n\n", r->ebx, r->ecx);

                handle_selection(D_SINK, 0);

        }
}

static void handle_setxattr(_u32 sysnum, struct user_regs_struct* r){
        if (isroot()) {
                char* fn = (sysnum == 228 || sysnum == 237) ?
                        getfdpath(r->ebx) : findpath(r->ebx);

                warn_banner(2);
                malelf_print(outfd,MSG69, clean_name(fn));

                handle_selection(D_ABORT, 0);
        }
}

static void handle_fork(){
        if (local) {
                warn_banner(1);
                malelf_print(outfd,MSG70);
        } else {
                warn_banner(2);
                malelf_print(outfd,MSG71);
        }

        handle_selection_fork();
}

static void handle_clone(){
        warn_banner(2);
        malelf_print(outfd,MSG72);


        handle_selection_fork();
}

static void handle_default(_u32 sysnum, struct user_regs_struct* r){
        if (local) {
                warn_banner(1);
                malelf_print(outfd,MSG73);
        } else {
                warn_banner(2);
                malelf_print(outfd,MSG74);
        }

        malelf_print(outfd,"Syscall number : %u\n"
                     "Syscall name   : %s\n\n",
                     sysnum, find_sysname(sysnum));

        {   char* x;
                _i32 v;

                malelf_print(outfd,"  EBX = 0x%08X ", r->ebx);
                x = getstring(v = r->ebx);
                if (v > -1000000 && v < 1000000)
                        malelf_print(outfd,"[%d] ",v);
                if (x[0])
                        malelf_print(outfd,"\"%s\"",clean_name(x));

                malelf_print(outfd,"\n  ECX = 0x%08X ", r->ecx);
                x = getstring(v = r->ecx);
                if (v > -1000000 && v < 1000000)
                        malelf_print(outfd,"[%d] ",v);
                if (x[0])
                        malelf_print(outfd,"\"%s\"",clean_name(x));

                malelf_print(outfd,"\n  EDX = 0x%08X ", r->edx);
                x = getstring(v = r->edx);
                if (v > -1000000 && v < 1000000)
                        malelf_print(outfd,"[%d] ",v);
                if (x[0])
                        malelf_print(outfd,"\"%s\"",clean_name(x));
        }

        malelf_print(outfd,"\n\n");

        handle_selection(local, 0);
}

static void handle_open(struct user_regs_struct* r){
        char* fn = findpath(r->ebx), exists = 1;
        struct stat st;

        if (stat(fn,&st))
                exists=0;

        if (r->ecx & (O_WRONLY|O_RDWR)) {

                /* For writing */

                if (local) {
                        warn_banner(1);

                        if (exists)
                                malelf_print(outfd,MSG1);
                        else
                                malelf_print(outfd,MSG2);

                } else {
                        warn_banner(2);

                        if (exists)
                                malelf_print(outfd,MSG3);
                        else
                                malelf_print(outfd,MSG4);
                }

                malelf_print(outfd,"File name : %s\n", clean_name(fn));

                if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))
                        malelf_print(outfd,"WARNING   : *** This is a special (device) file! ***\n");
                else if (st.st_nlink != 1)
                        malelf_print(outfd,"WARNING   : *** This is a hard link! ***\n");

                malelf_print(outfd,"\n");

                char* original_file_name = basename(clean_name(fn));
                char copy_file[256];
                memset(copy_file, 0, 256);
                strncpy(copy_file, "/tmp/", 255);
                strncat(copy_file, original_file_name, 255);

                malelf_print(outfd,"WARNING   : Keeping a copy of the original file at %s", copy_file);

                copy_file_contents(clean_name(fn), copy_file);

                //TODO Ask the user if he wants to keep the copy of the file

                malelf_print(outfd,"\n");

                handle_selection(local ? D_PERMIT : D_ABORT, 31337);

        } else {
                _u32 i = 0;

                /* For reading */

                if ((st.st_mode & S_IXOTH) &&
                    (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode)))
                        return;

                while (read_ok[i]) {
                        if (!strcmp(fn,read_ok[i]))
                                return;
                        i++;
                }

                warn_banner(0);
                malelf_print(outfd,MSG5);
                malelf_print(outfd,"File name : %s\n",clean_name(fn));

                if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))
                        malelf_print(outfd,"WARNING   : *** This is a special (device) file! ***\n");
                else if (st.st_nlink != 1)
                        malelf_print(outfd,"WARNING   : *** This is a hard link! ***\n");

                malelf_print(outfd,"\n");
                handle_selection(D_PERMIT, 31337);

        }
}

static void handle_mknod(struct user_regs_struct* r){
        if (!(S_ISBLK(r->ecx) || S_ISCHR(r->ecx)))
                handle_open(r);

        if (isroot()) {
                char* fn = findpath(r->ebx);

                warn_banner(2);
                malelf_print(outfd,MSG12);
                malelf_print(outfd,"Device path : %s\n",clean_name(fn));
                malelf_print(outfd,"Device ID   : %s(%u.%u)\n\n",
                             S_ISBLK(r->ecx) ? "block":"char", r->edx >> 8, r->edx & 0xff);

                handle_selection(D_ABORT, 0);

        }
}

static void handle_execve(struct user_regs_struct* r){
        char* fn = findpath(r->ebx), exists = 1;
        _u32 argp, envp, cv, i;
        struct stat st;

        if (stat(fn,&st))
                exists=0;

        /* We are confused. Or the guy is. */
        if (!exists || !S_ISREG(st.st_mode) || access(fn,X_OK))
                return;

        if (local) {
                warn_banner(1);
                malelf_print(outfd,MSG10);
        } else {
                warn_banner(2);
                malelf_print(outfd,MSG11);
        }

        argp = r->ecx;
        envp = r->edx;

        malelf_print(outfd,"Program    : %s\n", clean_name(fn));

        i = 0;
        do {
                errno = 0;
                cv = ptrace(PTRACE_PEEKDATA, tpid, argp, 0);

                if (errno)
                        cv = 0;

                if (cv) {
                        char* x = getstring(cv);
                        malelf_print(outfd,"  av[%d] = %s\n", i, clean_name(x));
                }

                argp += 4; i++;
        } while (cv && i < 8);

        if (i == 8)
                malelf_print(outfd,"  (...more parameters)\n");
        else if (!i)
                malelf_print(outfd,"  <NO PARAMETERS>\n");

        malelf_print(outfd,"\nNew environment:\n");

        i = 0;
        do {
                errno = 0;
                cv = ptrace(PTRACE_PEEKDATA, tpid, envp, 0);

                if (errno)
                        cv = 0;

                if (cv) {
                        char* x = getstring(cv);
                        char* y = strchr(x,'=');

                        if (y) {
                                char* z;
                                *y=0; y++;
                                z = getenv(x);
                                if (!z || strcmp(z,y)) {
                                        *(y-1) = '=';
                                        malelf_print(outfd,"  %s\n", clean_name(x));
                                        i++;
                                }
                        }
                }

                envp += 4;
        } while (cv && i < 8);

        if (i == 8)
                malelf_print(outfd,"  (...more additions...)\n");
        else if (!i)
                malelf_print(outfd,"  <NO ADDITIONS>\n");

        if (check_for_shell(clean_name(fn)))
                malelf_print(outfd,"\nWARNING - The program that the traced application is \
trying to execute is probably a SHELL - WARNING \n");

        handle_selection(D_ABORT, 0);
}

static void handle_socketcall(_u32 sysnum, struct user_regs_struct* r){
        _u32 p[5];

        errno = 0;
        p[0] = ptrace(PTRACE_PEEKDATA, tpid, r->ecx, 0);
        if (errno) return; /* Sheesh */
        p[1] = ptrace(PTRACE_PEEKDATA, tpid, r->ecx + 4, 0);
        p[2] = ptrace(PTRACE_PEEKDATA, tpid, r->ecx + 8, 0);
        p[3] = ptrace(PTRACE_PEEKDATA, tpid, r->ecx + 12, 0);
        p[4] = ptrace(PTRACE_PEEKDATA, tpid, r->ecx + 16, 0);

        switch (r->ebx) {

        case 1: /* SYS_SOCKET */

                /* Those combinations can be safely handled when specific
                   packets are received or sent later on. Raw sockets and
                   other obscure protocols should be detected early, because
                   of the possibility for mapped network I/O and so on. */

                if ((p[0] == PF_UNIX || p[0] == PF_LOCAL || p[0] == PF_INET ||
                     p[0] == PF_INET6) && (p[1] == SOCK_STREAM ||
                                           p[1] == SOCK_DGRAM || p[1] == SOCK_SEQPACKET ||
                                           p[1] == SOCK_RDM)) return;

                if (p[0] == PF_PACKET || p[1] == SOCK_RAW ||
                    p[1] == SOCK_PACKET) {
                        if (isroot()) {
                                if (local) {
                                        warn_banner(2);
                                        malelf_print(outfd,MSG39);
                                } else {
                                        warn_banner(1);
                                        malelf_print(outfd,MSG40);
                                }

                                malelf_print(outfd,"Protocol family : %d\n"
                                             "Protocol type   : %d/%d\n\n", p[0], p[1], p[2]);
                                handle_selection(D_ABORT,31337);

                        }

                } else {

                        warn_banner(1);
                        malelf_print(outfd,MSG41);

                        malelf_print(outfd,"Protocol family : %d\n"
                                     "Protocol type   : %d/%d\n\n", p[0], p[1], p[2]);
                        handle_selection(D_ABORT,31337);

                }

                break;

        case 2: /* SYS_BIND */

                /* Tylko AF_UNIX */
                if ((ptrace(PTRACE_PEEKDATA, tpid, p[1], 0) & 0xFF) == AF_UNIX) {

                        char* fn = findpath(p[1] + 2 /* sa common */);
                        if (fn[0] == '<') return; /* Private namespace */

                        if (local) {
                                warn_banner(0);
                                malelf_print(outfd,MSG42);
                        } else {
                                warn_banner(1);
                                malelf_print(outfd,MSG43);
                        }

                        malelf_print(outfd,"Socket name : %s\n\n", clean_name(fn));
                        handle_selection(local ? D_PERMIT : D_ABORT, 0);

                }

                break;

        case 3: { /* SYS_CONNECT */
                _u8 af;

                errno = 0;
                af = ptrace(PTRACE_PEEKDATA, tpid, p[1], 0);
                if (errno) return;

                switch (af) {

                case AF_UNSPEC:
                        break;

                case AF_UNIX: {
                        char* fn = findpath(p[1] + 2);
                        _u32 i = 0;

                        if (fn[0] == '<') fn = findpath(p[1] + 3);

                        while (read_ok[i]) {
                                if (!strcmp(fn,read_ok[i])) return;
                                i++;
                        }

                        if (local) {
                                warn_banner(0);
                                malelf_print(outfd,MSG44);
                        } else {
                                warn_banner(1);
                                malelf_print(outfd,MSG45);
                        }

                        malelf_print(outfd,"Socket : %s\n\n", clean_name(fn));
                        handle_selection(D_PERMIT, 0);

		}

                        break;

                case AF_INET: {
                        // Port at p[1] + 2 (2 bytes)
                        // Address at p[1] + 4
                        _u16 pt = ptrace(PTRACE_PEEKDATA, tpid, p[1] + 2, 0);
                        _u32 ad = ptrace(PTRACE_PEEKDATA, tpid, p[1] + 4, 0);
                        _u8* a = (_u8*)&ad;

                        if (local) {
                                warn_banner(2);
                                malelf_print(outfd,MSG46);
                        } else {
                                warn_banner(0);
                                malelf_print(outfd,MSG47);

                        }


                        malelf_print(outfd,"Target host : %u.%u.%u.%u\n"
                                     "Target port : %u%s\n\n", a[0], a[1], a[2], a[3],
                                     ntohs(pt),
                                     ntohs(pt) == 53 ? " (DNS query)" : "" );

                        handle_selection(local ? D_ABORT : D_PERMIT, 0);

		}

                        break;

                case AF_INET6: {
                        // Port at p[1] + 2 (2 bytes)
                        // Address at p[1] + 8 (16 bytes)

                        _u16 pt = ptrace(PTRACE_PEEKDATA, tpid, p[1] + 2);
                        _u32 ad[4];
                        _u8* a = (_u8*)&ad;

                        ad[0] = ptrace(PTRACE_PEEKDATA, tpid, p[1] + 8);
                        ad[1] = ptrace(PTRACE_PEEKDATA, tpid, p[1] + 12);
                        ad[2] = ptrace(PTRACE_PEEKDATA, tpid, p[1] + 16);
                        ad[3] = ptrace(PTRACE_PEEKDATA, tpid, p[1] + 20);

                        if (local) {
                                warn_banner(2);
                                malelf_print(outfd,MSG48);
                        } else {
                                warn_banner(0);
                                malelf_print(outfd,MSG49);
                        }

                        malelf_print(outfd,"Target host : %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X (IPv6)\n"
                                     "Target port : %u\n\n",
			             a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
			             a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15],
			             ntohs(pt));

                        handle_selection(local ? D_ABORT : D_PERMIT, 0);
		}

                        break;

                default:

                        warn_banner(2);
                        malelf_print(outfd,MSG50, af);

                        handle_selection(D_ABORT, 0);

                }

        }

                break;

        case 5: /* SYS_ACCEPT - We will prompt for it on return */
                check_ret = CRET_ACCEPT;
                break;

	case 11: /* SYS_SENDTO */
                if (p[4]) { /* p[4] - struct sockaddr (dest) */
                        _u8 af;

                        errno = 0;
                        af = ptrace(PTRACE_PEEKDATA, tpid, p[4], 0);
                        if (errno) af = 0;

                        if (local) {
                                warn_banner(2);
                                malelf_print(outfd,MSG51);
                        } else if (af != AF_INET && af != AF_INET6 && af != AF_UNIX) {
                                warn_banner(2);
                                malelf_print(outfd,MSG52);
                        } else {
                                warn_banner(1);
                                malelf_print(outfd,MSG53);
                        }

                        malelf_print(outfd,"Descriptor  : %d\n",p[0]);

                        /* On network sockets, do some guessing */
                        if (af != AF_UNIX) {
                                char* sn = check_addr(p[0]);

                                if (sn[0] == '<') { /* RAW? Or something else? */
                                        _u8 tos;
                                        errno = 0;
                                        if (af == PF_PACKET) p[1] += 14;
                                        tos = ptrace(PTRACE_PEEKDATA, tpid, p[1], 0);

                                        if (!errno && tos >= 0x45 && tos <= 0x4F) {
                                                _u8 sa[4], da[4];

                                                *(_u32*)sa = ptrace(PTRACE_PEEKDATA, tpid, p[1] + 12, 0);
                                                *(_u32*)da = ptrace(PTRACE_PEEKDATA, tpid, p[1] + 16, 0);

                                                if (!errno)
                                                        malelf_print(outfd,"Packet data : %u.%u.%u.%u -> %u.%u.%u.%u (RAW)\n",
                                                                     sa[0],sa[1],sa[2],sa[3],da[0],da[1],da[2],da[3]);
                                                else malelf_print(outfd,"Packet data : N/A (bad packet?)\n");
                                        } else malelf_print(outfd,"Packet data : N/A\n");

                                        /* TCP or UDP - boring */
                                } else malelf_print(outfd,"Socket data : %s\n", sn);
                        }

                        /* Interpret toaddr */
                        switch (af) {

                        case AF_UNIX: {
                                char* fn = findpath(p[4] + 2);
                                _u32 i = 0;

                                if (fn[0] == '<') fn = findpath(p[4] + 3);

                                while (read_ok[i]) {
                                        if (!strcmp(fn,read_ok[i])) return;
                                        i++;
                                }

                                malelf_print(outfd,"Target sock : %s\n", fn);

                        }
                                break;

                        case AF_INET: {
                                // Port at p[4] + 2 (2 bytes)
                                // Address at p[4] + 4
                                _u16 pt = ptrace(PTRACE_PEEKDATA, tpid, p[4] + 2, 0);
                                _u32 ad = ptrace(PTRACE_PEEKDATA, tpid, p[4] + 4, 0);
                                _u8* a = (_u8*)&ad;

                                malelf_print(outfd,"Target host : %u.%u.%u.%u\n"
                                             "Target port : %u%s\n", a[0], a[1], a[2], a[3],
                                             ntohs(pt), htons(pt) == 53 ? " (DNS query)" : "" );

                        }

                                break;

                        case AF_INET6: {
                                // Port at p[4] + 2 (2 bytes)
                                // Address at p[4] + 8 (16 bytes)
                                _u16 pt = ptrace(PTRACE_PEEKDATA, tpid, p[4] + 2);
                                _u32 ad[4];
                                _u8* a = (_u8*)&ad;

                                ad[0] = ptrace(PTRACE_PEEKDATA, tpid, p[4] + 8);
                                ad[1] = ptrace(PTRACE_PEEKDATA, tpid, p[4] + 12);
                                ad[2] = ptrace(PTRACE_PEEKDATA, tpid, p[4] + 16);
                                ad[3] = ptrace(PTRACE_PEEKDATA, tpid, p[4] + 20);

                                malelf_print(outfd,"Target host : %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X (IPv6)\n"
                                             "Target port : %u\n",
                                             a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
                                             a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15],
                                             ntohs(pt));

                        }

                                break;

                        default:
                                malelf_print(outfd,"*** UNKNOWN PROTOCOL FAMILY %d - TARGET UNKNOWN ***\n",af);

                        }

                        if (p[1] > 0) {
                                _u8 last16[17];
                                _u32 len = ((p[2] + 15) / 16 * 16), cur = 0;

                                if (len > 64) {
                                        len = 64;
                                        malelf_print(outfd,"\nPayload (first 64 bytes):\n");
                                } else malelf_print(outfd,"\nPayload:\n");

                                errno = 0;

                                while (cur < len) {
                                        _u8 x = 0;
                                        if (!errno) x = ptrace(PTRACE_PEEKDATA, tpid, p[1] + cur, 0);
                                        if (errno) {
                                                malelf_print(outfd,"   ");
                                                last16[cur % 16] = ' ';
                                        } else {
                                                malelf_print(outfd,"%02X ", x);
                                                last16[cur % 16] = (x < ' ' || x > '~') ? '.' : x;
                                        }
                                        cur++;
                                        if (!(cur % 16)) {
                                                last16[16] = 0;
                                                malelf_print(outfd," | %s\n",last16);
                                        }
                                }

                        }

                        malelf_print(outfd,"\n");

                        handle_selection(local ? D_ABORT : D_PERMIT, 0);

                }

                break;

        case 12: /* SYS_RECVFROM */

                check_ret = CRET_RECVFROM;
                rpar1 = p[0];
                rpar2 = p[1];

                if (!(rpar3 = p[4])) {
                        _u32 i;

                        /* Check for overlap between buffer p[1] (length p[2])
                           and secret_lair: */

                        if ((p[1] >= secret_lair && p[1] < secret_lair + LAIR_SIZE) ||
                            (p[1] + p[2] - 1 >= secret_lair && p[1] + p[2] - 1 <=
                             secret_lair + LAIR_SIZE)) return;

                        secret_buried = 1;

                        for (i=0;i<LAIR_SIZE/4;i++)
                                secret_copy[i] = ptrace(PTRACE_PEEKDATA, tpid,
                                                        secret_lair + i * 4, 0);

                        /* Modify p[4] to point to secret_lair */
                        ptrace(PTRACE_PEEKDATA, tpid, r->ecx + 16, secret_lair);

                        /* Modify p[5] to point to integer at the end of lair */
                        ptrace(PTRACE_PEEKDATA, tpid, r->ecx + 20, secret_lair +
                               LAIR_SIZE - 4);

                        /* Modify the integer to incidate lair size ohne the integer */
                        ptrace(PTRACE_PEEKDATA, tpid, secret_lair + LAIR_SIZE - 4,
                               LAIR_SIZE - 4);

                }

                break;

        case 4: /* SYS_LISTEN */	     case 6: /* SYS_GETSOCKNAME */
        case 7: /* SYS_GETPEERNAME */	 case 8: /* SYS_SOCKETPAIR */
        case 9: /* SYS_SEND */	     case 10: /* SYS_RECV */
        case 13: /* SYS_SHUTDOWN */	 case 14: /* SYS_GETSOCKOPT */
        case 15: /* SYS_SETSOCKOPT */
                break;

        default:
                handle_default(sysnum, r);
        }
}

static void soup_nazi(_u32 sysnum, struct user_regs_struct* r) {

        if (!secret_lair)
                secret_lair = (1 + (r->esp / 4096)) * 4096 - LAIR_SIZE;

        _u32 i = 0;
        while (safe_syscalls[i]) {
                if (sysnum == safe_syscalls[i]) return;
                i++;
        }

        /* TODO
           for(i=0; i < 256; i++){
           char* filename = clean_name(getfdpath(r->ebx));;
           char mode = ( r->ecx & (O_WRONLY|O_RDWR) ) ? 'w' : 'r';

           if (sysnum == permitted_actions[i].sysnum &&
           filename == permitted_actions[i].filename &&
           mode == permitted_actions[i].mode)
           return;
           }
        */

        switch (sysnum) {

        case SYS_SIGRETURN:
        case SYS_RT_SIGRETURN:
                skip_eip_check = 1;
                break;

        case SYS_UMASK:
                child_umask = r->ebx & 0777;
                break;

        case SYS_CREAT:
                r->ecx = O_RDWR;
        case SYS_OPEN:
                handle_open(r);
                break;

        case SYS_IOCTL:
                handle_ioctl(r);
                break;

        case SYS_SYMLINK:
        case SYS_LINK:
                handle_link(sysnum, r);
                break;

        case SYS_UNLINK:
                handle_unlink(r);
                break;

        case SYS_EXECVE:
                handle_execve(r);
                break;

        case SYS_MKNOD:
                handle_mknod(r);
                break;

        case SYS_FCHMOD:
        case SYS_CHMOD:
                handle_chmod(sysnum, r);
                break;

        case SYS_FCHOWN16:
        case SYS_FCHOWN:
        case SYS_LCHOWN16:
        case SYS_LCHOWN:
        case SYS_CHOWN16:
        case SYS_CHOWN:
                handle_chown(sysnum, r);
                break;

        case SYS_MOUNT:
                handle_mount(r);
                break;

        case SYS_OLDUMOUNT:
        case SYS_UMOUNT:
                handle_umount(r);
                break;

        case SYS_SETTIMEOFDAY:
        case SYS_STIME:
                handle_stime(r);
                break;

        case SYS_PTRACE:
                handle_ptrace(r);
                break;

        case SYS_UTIME:
                handle_utime(r);
                break;

        case SYS_TKILL:
        case SYS_KILL:
                handle_kill(r);
                break;

        case SYS_RENAME:
                handle_rename(r);
                break;

        case SYS_MKDIR:
                handle_mkdir(r);
                break;

        case SYS_RMDIR:
                handle_rmdir(r);
                break;

        case SYS_ACCT:
                handle_acct(r);
                break;

        case SYS_CHROOT:
        case SYS_PIVOT_ROOT:
                handle_chroot(r);
                break;

        case SYS_SETHOSTNAME:
        case SYS_SETDOMAINNAME:
                handle_sethostname(r);
                break;

        case SYS_SWAPON:
                handle_swapon(r);
                break;

        case SYS_REBOOT:
                handle_reboot();
                break;

        case SYS_IOPERM:
                handle_ioperm(r);
                break;

        case SYS_SOCKETCALL:
                handle_socketcall(sysnum, r);
                break;

        case SYS_SYSLOG:
                handle_syslog(r);
                break;

        case SYS_IOPL:
                handle_iopl(r);
                break;

        case SYS_VHANGUP:
                handle_vhangup();
                break;

        case SYS_VM86OLD:
        case SYS_VM86:
        case SYS_MODIFY_LDT:
                handle_vm86();
                break;

        case SYS_SWAPOFF:
                handle_swapoff();
                break;

        case SYS_IPC:
                handle_ipc(r);
                break;

        case SYS_ADJTIMEX:
                handle_adjtimex(r);
                break;

        case SYS_CREATE_MODULE:
        case SYS_INIT_MODULE:
                handle_create_module(r);
                break;

        case SYS_DELETE_MODULE:
                handle_delete_module(r);
                break;

        case SYS_SYSCTL:
                handle_sysctl(r);
                break;

        case SYS_SCHED_SETSCHEDULER:
                handle_sched(r);
                break;

        case SYS_FSETXATTR:
        case SYS_FREMOVEXATTR:
        case SYS_SETXATTR:
        case SYS_LSETXATTR:
        case SYS_REMOVEXATTR:
        case SYS_LREMOVEXATTR:
                handle_setxattr(sysnum, r);
                break;

        case SYS_FORK:
        case SYS_VFORK:
                handle_fork();
                break;

        case SYS_CLONE:
                handle_clone();
                break;

        default:
                handle_default(sysnum, r);
        }
}

static void handle_return(struct user_regs_struct* r) {

        switch (check_ret) {

        case CRET_ACCEPT:

                if (((_i32)r->eax) > 0) {
                        char* sn = check_addr(r->eax);

                        warn_banner(2);
                        malelf_print(outfd,MSG75, r->eax,sn);
                        handle_selection(D_ABORT,NOSINK);

                }

                break;

        case CRET_RECVFROM:

                if ((_i32)r->eax > 0) {
                        _u8 af;
                        _u32 soad = rpar3 ? rpar3 : secret_lair;

                        errno = 0;
                        af = ptrace(PTRACE_PEEKDATA, tpid, soad, 0);
                        if (errno) af = 0;

                        if (local) {
                                warn_banner(2);
                                malelf_print(outfd,MSG76);

                        } else {
                                warn_banner(1);
                                malelf_print(outfd,MSG77);
                        }

                        malelf_print(outfd,"Descriptor  : %d\n",rpar1);

                        /* On network sockets, do some guessing */
                        if (af != AF_UNIX) {
                                char* sn = check_addr(rpar1);

                                if (sn[0] == '<') { /* RAW? Or something else? */
                                        _u8 tos;
                                        errno = 0;

                                        if (af == PF_PACKET) rpar2 += 14;
                                        tos = ptrace(PTRACE_PEEKDATA, tpid, rpar2, 0);

                                        if (!errno && tos >= 0x45 && tos <= 0x4F) {
                                                _u8 sa[4], da[4];

                                                *(_u32*)sa = ptrace(PTRACE_PEEKDATA, tpid, rpar2 + 12, 0);
                                                *(_u32*)da = ptrace(PTRACE_PEEKDATA, tpid, rpar2 + 16, 0);

                                                if (!errno)
                                                        malelf_print(outfd,"Packet data : %u.%u.%u.%u -> %u.%u.%u.%u (RAW)\n",
                                                                     sa[0],sa[1],sa[2],sa[3],da[0],da[1],da[2],da[3]);
                                                else malelf_print(outfd,"Packet data : N/A (bad packet?)\n");
                                        } else malelf_print(outfd,"Packet data : N/A\n");

                                        /* TCP or UDP - boring */
                                } else malelf_print(outfd,"Socket data : %s\n", sn);
                        }

                        if (!rpar3 && !secret_buried)
                                malelf_print(outfd,"*** NO SOCKET SOURCE ADDRESS DATA - TRICKERY? ***\n");
                        else /* Interpret toaddr */ switch (af) {

                                case AF_UNIX: {
                                        char* fn = findpath(soad + 2);
                                        _u32 i = 0;

                                        if (fn[0] == '<') fn = findpath(soad + 3);

                                        while (read_ok[i]) {
                                                if (!strcmp(fn,read_ok[i])) return;
                                                i++;
                                        }

                                        malelf_print(outfd,"Source sock : %s\n", fn);

                                }
                                        break;

                                case AF_INET: {
                                        // Port at soad + 2 (2 bytes)
                                        // Address at soad + 4
                                        _u16 pt = ptrace(PTRACE_PEEKDATA, tpid, soad + 2, 0);
                                        _u32 ad = ptrace(PTRACE_PEEKDATA, tpid, soad + 4, 0);
                                        _u8* a = (_u8*)&ad;

                                        malelf_print(outfd,"Source host : %u.%u.%u.%u\n"
                                                     "Source port : %u%s\n", a[0], a[1], a[2], a[3],
                                                     ntohs(pt), htons(pt) == 53 ? " (DNS query)" : "" );
                                }

                                        break;

                                case AF_INET6: {
                                        // Port at soad + 2 (2 bytes)
                                        // Address at soad + 8 (16 bytes)
                                        _u16 pt = ptrace(PTRACE_PEEKDATA, tpid, soad + 2);
                                        _u32 ad[4];
                                        _u8* a = (_u8*)&ad;

                                        ad[0] = ptrace(PTRACE_PEEKDATA, tpid, soad + 8);
                                        ad[1] = ptrace(PTRACE_PEEKDATA, tpid, soad + 12);
                                        ad[2] = ptrace(PTRACE_PEEKDATA, tpid, soad + 16);
                                        ad[3] = ptrace(PTRACE_PEEKDATA, tpid, soad + 20);

                                        malelf_print(outfd,"Source host : %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X (IPv6)\n"
                                                     "Source port : %u\n",
                                                     a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
                                                     a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15],
                                                     ntohs(pt));

                                }

                                        break;

                                case AF_PACKET:
                                        malelf_print(outfd,"*** RAW PACKET RECEIPT - SOURCE UNKNOWN ***\n");
                                        break;

                                default:
                                        malelf_print(outfd,"*** UNKNOWN PROTOCOL FAMILY %d - SOURCE UNKNOWN ***\n",af);

                                }

                        if (rpar2 > 0) {
                                _u8 last16[17];
                                _u32 len = ((r->eax + 15) / 16 * 16), cur = 0;

                                if (len > 64) {
                                        len = 64;
                                        malelf_print(outfd,"\nPayload (first 64 bytes):\n");
                                } else malelf_print(outfd,"\nPayload:\n");

                                errno = 0;

                                while (cur < len) {
                                        _u8 x = 0;
                                        if (!errno) x = ptrace(PTRACE_PEEKDATA, tpid, rpar2 + cur, 0);
                                        if (errno) {
                                                malelf_print(outfd,"   ");
                                                last16[cur % 16] = ' ';
                                        } else {
                                                malelf_print(outfd,"%02X ", x);
                                                last16[cur % 16] = (x < ' ' || x > '~') ? '.' : x;
                                        }
                                        cur++;
                                        if (!(cur % 16)) {
                                                last16[16] = 0;
                                                malelf_print(outfd," | %s\n",last16);
                                        }
                                }

                        }

                        /* We displayed all there was to display. Now, let's
                           restore memory if we messed up. */

                        if (secret_buried) {
                                _u32 i;

                                secret_buried = 0;
                                for (i=0;i<LAIR_SIZE/4;i++)
                                        ptrace(PTRACE_POKEDATA, tpid, secret_lair + i * 4,
                                               secret_copy[i]);

                        }

                        malelf_print(outfd,"\n");
                        handle_selection(D_ABORT,NOSINK);

                }

                break;


        default: fatal_exit("UNIBUS FATAL TRAP PROGRAM LOST SORRY");

        }
}

static void trace_loop(void) {
        _u32 sig = 0;
        _i32 st;
        _u8  sysret = 0;
        _u32 sc_ad = 0, sc_num = 0;

        while (1) {
                if (ptrace(PTRACE_SYSCALL,tpid,0,sig))
                        fatal_exit("PTRACE_SYSCALL failed");

                if (waitpid(tpid, &st, WUNTRACED) < 0)
                        fatal_exit("waitpid failed");

                if (WIFEXITED(st)) {
                        kill(tpid, SIGKILL);
                        malelf_print(outfd,"+++ Program exited with code %d +++\n", WEXITSTATUS(st));
                        clean_exit(1);
                } else if (WIFSIGNALED(st)) {
                        kill(tpid, SIGKILL);
                        malelf_print(outfd,"--- Program died on signal %d +++\n", WTERMSIG(st));
                        clean_exit(1);
                } else if (WIFSTOPPED(st)) {
                        sig = WSTOPSIG(st);
                        if (sig == SIGTRAP) sig = 0;
                } else fatal_exit("Strange outcome of waitpid (status = %d)",st);

                if (!sig) {
                        struct user_regs_struct r;
                        ptrace(PTRACE_GETREGS, tpid, 0, &r);

                        if (!sysret) {
                                if (r.eax != 0xffffffda)
                                        fatal_exit("EAX mismatch on syscall entry?");

                                soup_nazi((_u32)r.orig_eax, &r);

                                if (sink_syscall) {
                                        r.orig_eax = 0;
                                        ptrace(PTRACE_SETREGS, tpid, 0, &r);
                                }

                                sc_ad  = r.eip;
                                sc_num = r.orig_eax;
                                sysret = 1;

                        } else {

                                if ((!skip_eip_check && r.eip != sc_ad) || sc_num != r.orig_eax)
                                        fatal_exit("Syscall return EIP/EAX mismatch (EIP %x/%x, EAX %d/%d)",
                                                   sc_ad, (_u32)r.eip, sc_num, (_u32)r.orig_eax);

                                skip_eip_check = 0;

                                if (check_ret) {
                                        handle_return(&r);
                                        check_ret = 0;
                                } else if (sink_syscall) {
                                        r.eax = syscall_result;
                                        ptrace(PTRACE_SETREGS, tpid, 0, &r);
                                        sink_syscall = 0;
                                }
                                sysret = 0;
                        }
                }
        }
}

_i32 dynamic_analyse_input(MalelfBinary *elf_obj, char** argv, FILE* fd){
        outfd = fd;
        _i32 error;

        tcgetattr(0, &clean_term);
        memcpy(&canoe_term,&clean_term,sizeof(struct termios));
        canoe_term.c_lflag = ~(ICANON|ECHO);

        child_umask = umask(0);
        umask(child_umask);

        local = 1;
        iamroot = (geteuid() == 0);

        if (iamroot)
                malelf_print(outfd,
                             "****************************************************************************************\n"
                             "* CAUTION - YOU ARE RUNNING A DYNAMIC ANALYSIS OF A POSSIBLE MALWARE AS ROOT - CAUTION *\n"
                             "****************************************************************************************\n");

        create_child(elf_obj->fname, argv);
        trace_loop();

        error = malelf_binary_close(elf_obj);

        if (error != MALELF_SUCCESS)
                return error;

        return error;
}

_i32 auto_dynamic_analyse_input(MalelfBinary *elf_obj, char** argv, FILE* fd){
        isauto = 1;
        outfd = fd;
        return dynamic_analyse_input(elf_obj, argv, fd);
}

void malelf_dynanalyse_help() {
        HELP("Dynamically analyse the ELF binary for malwares.\n");
        HELP("%s dynanalyse [-h] -i <input> -o <output-file> [,-f <output-format>]\n", "malelf");
        HELP(" -h\tanalyse help\n");
        HELP(" -i <input-binary>\tInput binary file\n");
        HELP(" -o <output-file>\tOutput report\n");
        HELP(" -f <output-format>\tFormat for report\n");
        HELP(" -a \tAutomatic analysis\n");
        exit(MALELF_SUCCESS);
}

void malelf_dynanalyse_init(int argc, char** argv) {
        int c;
        _i32 error = 0;
        char *out_fname = NULL;
        MalelfBinary input;
        input.fname = NULL;
        _i32 automatic = 0;
        FILE* outfd = NULL;

        malelf_binary_init(&input);

        while (1) {
                int option_index = 0;
                static struct option long_options[] = {
                        {"help", 0, 0, 'h'},
                        {"auto", 0, 0, 'a'},
                        {"output", 1, 0, 'o'},
                        {"file", 1, 0, 'i'},
                        {0, 0, 0, 0}
                };

                c = getopt_long(argc, argv, "hao:i:",
                                long_options, &option_index);
                if (c == -1)
                        break;

                switch (c) {
                case 'h':
                        malelf_dynanalyse_help();
                        break;

                case 'i':
                        input.fname = optarg;
                        break;

                case 'o':
                        out_fname = optarg;
                        break;

                case 'a':
                        automatic = 1;
                        break;

                default:
                        printf("?? getopt returned character code 0%o ??\n", c);
                }

        }

        if (input.fname == NULL) {
                MALELF_LOG_ERROR("No input file selected...\n");
                malelf_dynanalyse_help();
                exit(1);
        }

        if (out_fname == NULL) {
                MALELF_LOG_VERBOSE_SUCCESS("Using stdout for log output.\n");
                outfd = stdout;
        } else {
                outfd = fopen(out_fname, "w");
                if (!outfd) {
                        perror("Error when opening output file for writing...");
                        exit(1);
                }
        }

        if ((error = malelf_binary_open(&input, input.fname)) != MALELF_SUCCESS) {
                MALELF_PERROR(error);
                MALELF_LOG_ERROR("Failed to open input file...\n");
                exit(-1);
        }

        if(automatic){
                error = auto_dynamic_analyse_input(&input, argv + optind, outfd);
                if (error != MALELF_SUCCESS) {
                        MALELF_PERROR(error);
                }
        }
        else{
                error = dynamic_analyse_input(&input, argv + optind, outfd);
                if (error != MALELF_SUCCESS) {
                        MALELF_PERROR(error);
                }
        }

        malelf_binary_close(&input);
}

void malelf_dynanalyse_finish()
{

}
