#ifndef __snd_sandbox__
#define __snd_sandbox__
#include <dlfcn.h>
#include <fcntl.h>
#include <linux/bpf_common.h>
#include <linux/capability.h> /* Definition of CAP_* and
                                        _LINUX_CAPABILITY_* constants */
#include <errno.h>
#include <linux/audit.h>   /* Definition of AUDIT_* constants */
#include <linux/filter.h>  /* Definition of struct sock_fprog */
#include <linux/seccomp.h> /* Definition of SECCOMP_* constants */
#include <net/if.h>        // For struct ifreq
#include <sched.h>
#include <seccomp.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h> /* Definition of PTRACE_* constants */
#include <sys/stat.h>
#include <sys/syscall.h> /* Definition of SYS_* constants */
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#endif
