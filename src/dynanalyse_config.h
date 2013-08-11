/*
    This code is based on Michal Zalewski's fakebust, available on: 
    http://lcamtuf.coredump.cx/soft/fakebust.tgz

    fakebust is distributed under the GNU Lesser General Public License v2.1, as
    can be seen on the LICENSE file available with the project.
*/

#ifndef _HAVE_CONFIG_H
#define _HAVE_CONFIG_H

#include <malelf/types.h>
#include "linux_syscalls.h"

#define MAXSTRING	8192

/* Standard configuration files we have no objection to being read by 
   rogue programs, */

static char* read_ok[] = {
  "/etc/ld.so.preload",
  "/etc/ld.so.cache",
  "/etc/nsswitch.conf",
  "/etc/resolv.conf",
  "/etc/ppp/resolv.conf",
  "/etc/host.conf",
  "/etc/hosts",
  "/etc/services",
  "/dev/null",
  "/dev/urandom",
  "/dev/random",
  "/dev/zero",
  "/usr/share/locale/locale.alias",
  "/usr/lib/locale/en_US/LC_IDENTIFICATION",
  "/usr/lib/locale/en",
  "/var/run/.nscd_socket", /* Comment out if you are paranoid */
  0
};

/*
static char* write_unsafe[] = {
  "/etc/passwd",
  "/etc/group",
  "/etc/shadow",
  0
};
*/

static char* shells[] = {
  "sh",
  "bash",
  "ash",
  "bsh",
  "ksh",
  "pdksh",
  "tcsh",
  "csh",
  "zsh",
  "dash",
  0
};


static _u32 safe_syscalls[] = {
     SYS_EXIT,
     SYS_READ,
     SYS_WRITE,
     SYS_CLOSE,
     SYS_WAITPID,
     SYS_CHDIR,
     SYS_TIME,
     SYS_STAT,
     SYS_LSEEK,
     SYS_GETPID,
     SYS_GETUID,
     SYS_ALARM,
     SYS_FSTAT,
     SYS_PAUSE,
     31, /* stty */
     32, /* gtty */
     SYS_ACCESS,
     SYS_NICE,
     35, /* ftime */
     SYS_SYNC,
     SYS_DUP,
     SYS_PIPE,
     SYS_TIMES,
     SYS_BRK,
     SYS_GETGID,
     SYS_SIGNAL,
     SYS_GETEUID,
     SYS_GETEGID,
     SYS_FCNTL,
     SYS_SETPGID,
     58, /* ulimit */
     SYS_OLDUNAME,
     SYS_USTAT,
     SYS_DUP2,
     SYS_GETPPID,
     SYS_GETPGRP,
     SYS_SETSID,
     SYS_SIGACTION,
     SYS_SGETMASK,
     SYS_SSETMASK,
     SYS_SIGSUSPEND,
     SYS_SIGPENDING,
     SYS_SETRLIMIT,
     SYS_OLD_GETRLIMIT,
     SYS_GETRUSAGE,
     SYS_GETTIMEOFDAY,
     SYS_GETGROUPS,
     OLD_SELECT,
     SYS_READLINK,
     SYS_LSTAT,
     SYS_USELIB,
     SYS_READDIR,
     SYS_MMAP,
     SYS_MUNMAP,
     SYS_TRUNCATE,
     SYS_FTRUNCATE,
     SYS_GETPRIORITY,
     SYS_SETPRIORITY,
     SYS_STATFS,
     SYS_FSTATFS,
     SYS_SETITIMER,
     SYS_GETITIMER,
     SYS_NEWSTAT,
     SYS_NEWLSTAT,
     SYS_NEWFSTAT,
     SYS_UNAME,
     SYS_WAIT4,
     SYS_SYSINFO,
     SYS_FSYNC,
     SYS_NEWUNAME,
     SYS_MPROTECT,
     SYS_SIGPROCMASK,
     SYS_GET_KERNEL_SYMS,
     SYS_GETPGID,
     SYS_FCHDIR,
     SYS_SYSFS,
     SYS_PERSONALITY,
     SYS_LLSEEK,
     SYS_GETDENTS,
     SYS_SELECT,
     SYS_FLOCK,
     SYS_MSYNC,
     SYS_READV,
     SYS_WRITEV,
     SYS_GETSID,
     SYS_FDATASYNC,
     SYS_MLOCK,
     SYS_MUNLOCK,
     SYS_MLOCKALL,
     SYS_MUNLOCKALL,
     SYS_SCHED_SETPARAM,
     SYS_SCHED_GETPARAM,
     SYS_SCHED_GETSCHEDULER,
     SYS_SCHED_YELD,
     SYS_SCHED_GET_PRIORITY_MAX,
     SYS_SCHED_GET_PRIORITY_MIN,
     SYS_SCHED_RR_GET_INTERVAL,
     SYS_NANOSLEEP,
     SYS_MREMAP,
     SYS_GETRESUID,
     SYS_QUERY_MODULE,
     SYS_POLL,
     SYS_GETRESGID,
     SYS_PRCTL,
     SYS_RT_SIGACTION,
     SYS_RT_SIGPROCMASK,
     SYS_RT_SIGPENDING,
     SYS_RT_SIGTIMEDWAIT,
     SYS_RT_SIGQUEUEINFO,
     SYS_RT_SIGSUSPEND,
     SYS_PREAD,
     SYS_PWRITE,
     SYS_GETCWD,
     SYS_CAPGET,
     SYS_CAPSET,
     SYS_SIGALTSTACK,
     SYS_SENDFILE,
     188, /* getpmsg */
     189, /* putpmsg */		 
     SYS_GETRLIMIT,
     SYS_MMAP2,
     SYS_TRUNCATE64,
     SYS_FTRUNCATE64,
     SYS_STAT64,
     SYS_LSTAT64,
     SYS_FSTAT64,
     SYS_GETUID,
     SYS_GETGID,
     SYS_GETEUID,
     SYS_GETEGID,
     SYS_GETGROUPS,
     SYS_GETRESUID,
     SYS_GETRESGID,
     SYS_MINCORE,
     SYS_MADVISE,
     SYS_GETDENTS64,
     SYS_FCNTL64,
     SYS_GETTID,
     SYS_READAHEAD,
     SYS_GETXATTR,
     SYS_LGETXATTR,
     SYS_FGETXATTR,
     SYS_LISTXATTR,
     SYS_LLISTXATTR,
     SYS_FLISTXATTR,
     SYS_SENDFILE64,
     SYS_SET_THREAD_AREA,
     SYS_GET_THREAD_AREA,
     250, /* alloc_hugepages */	
     251, /* free_hugepages */
     SYS_EXIT_GROUP,
     SYS_SET_TID_ADDRESS,
     
     /* You need privileges to switch UIDs in the first place... there's 
       little malice in voluntarily giving some of them up... */
     
     SYS_SETUID16,
     SYS_SETGID16,
     SYS_SETREUID16,
     SYS_SETREGID16,
     SYS_SETGROUPS16,
     SYS_SETFSUID16,
     SYS_SETFSGID16,
     SYS_SETRESUID16,
     SYS_SETRESGID16,
     SYS_SETREUID,
     SYS_SETREGID,
     SYS_SETGROUPS,
     SYS_SETRESUID,
     SYS_SETRESGID,
     SYS_SETUID,
     SYS_SETFSUID,
     SYS_SETFSGID,
     SYS_SETGID
};

#endif /* ! _HAVE_CONFIG_H */
