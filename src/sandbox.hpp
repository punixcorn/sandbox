#include "includes.h"

extern "C" inline void print(const char *message) {
    printf("[SND] %s\n", message);
}

extern "C" inline void printerror(const char *message) {
    printf("[SND] <ERR> %s\n", message);
}

extern "C" inline int set_uid_gid_mappings(int uid, int gid) {
    FILE *ufs = fopen("/proc/self/uid_map", "w");
    if (ufs == NULL) {
        perror("Error opening /proc/self/uid_map");
        return 1;
    }
    fprintf(ufs, "0 %d 1\n", uid);
    fclose(ufs);

    FILE *denyfs = fopen("/proc/self/setgroups", "w");
    if (denyfs == NULL) {
        perror("Error opening /proc/self/setgroups");
        return 1;
    }
    fprintf(denyfs, "deny\n");
    fclose(denyfs);

    FILE *gfs = fopen("/proc/self/gid_map", "w");
    if (gfs == NULL) {
        perror("Error opening /proc/self/gid_map");
        return 1;
    }
    fprintf(gfs, "0 %d 1\n", gid);
    fclose(gfs);
    print("set uid and gid mappings completed");
    return 0;
}

extern "C" inline int setup_other_mountpoints() {
    if (mkdir("/tmp/bin", 0755) == -1) {
        printerror("mkdir /tmp/bin failed");
        return 1;
    }
    if (mkdir("/tmp/lib", 0755) == -1) {
        printerror("mkdir /tmp/lib failed");
        return 1;
    }
    if (mkdir("/tmp/usr", 0755) == -1) {
        printerror("mkdir /tmp/usr failed");
        return 1;
    }

    if (mount("/bin", "/tmp/bin", NULL, MS_REC | MS_BIND, NULL) != 0) {
        printerror("failed to mount /bin");
        return 1;
    } else {
        print("mounted /bin");
    }
    if (mount("/lib", "/tmp/lib", NULL, MS_REC | MS_BIND, NULL) != 0) {
        printerror("failed to mount /lib");
        return 1;
    } else {
        print("mounted /lib");
    }
    if (mount("/usr", "/tmp/usr", NULL, MS_REC | MS_BIND, NULL) != 0) {
        printerror("failed to mount /usr");
        return 1;
    } else {
        print("mounted /usr");
    }

    if (mount(NULL, "/tmp/bin", NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL) !=
        0) {
        printerror("failed to remount /bin as read-only");
        return 1;
    }
    if (mount(NULL, "/tmp/lib", NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL) !=
        0) {
        printerror("failed to remount /lib as read-only");
        return 1;
    }
    if (mount(NULL, "/tmp/usr", NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL) !=
        0) {
        printerror("failed to remount /usr as read-only");
        return 1;
    }
    print("setup other mountpoints completed");

    return 0;
}

extern "C" inline int mount_proc() {
    // if (mkdir("/proc", 0700) == -1) {
    //   printerror("mkdir /proc failed");
    //   return 1;
    // }

    const char *src = "proc";
    const char *trgt = "/proc";
    const char *type = "proc";
    const unsigned long mntflags = 0;
    const char *opts = NULL; /* 65534 is the uid of nobody */

    int result = mount(src, trgt, type, mntflags, opts);

    if (result == 0) {
        printf("Mount created at %s...\n", trgt);
        umount(trgt);
    } else {
        printf(
            "Error : Failed to mount %s\n"
            "Reason: %s [%d]\n",
            src, strerror(errno), errno);
        return -1;
    }

    return 0;
}

extern "C" inline int setup_fs() {
    if (mount("tmpfs", "/tmp", "tmpfs", 0, NULL) != 0) {
        printerror("failed to mount /tmp");
        return 1;
    } else {
        print("mounted /tmp");
    }

    if (mkdir("/tmp/lib64", 0755) == -1) {
        printerror("mkdir \"lib64\"failed");
        return 1;
    } else {
        print("created /tmp/lib64");
    }

    if (mount("/lib64", "/tmp/lib64", NULL, MS_REC | MS_BIND, NULL) != 0) {
        printerror("failed to mount /lib64");
        return 1;
    } else {
        print("mounted /lib64");
    }

    if (mkdir("/tmp/etc", 0755) == -1) {
        perror("mkdir \"etc\"failed");
        return 1;
    } else {
        print("created /tmp/etc");
    }

    if (mount("/etc", "/tmp/etc", NULL, MS_REC | MS_BIND, NULL) != 0) {
        printerror("failed to mount /etc");
        return 1;
    } else {
        print("mounted /etc");
    }

    if (setup_other_mountpoints() != 0) {
        printerror("failed to setup other mountpoints");
        _exit(1);
    };

    if (mkdir("/tmp/oldroot", 0755) == -1) {
        perror("mkdir \"oldroot\"failed");
        return 1;
    } else {
        print("created /tmp/oldroot");
    }

    if (syscall(SYS_pivot_root, "/tmp", "/tmp/oldroot") != 0) {
        printerror("failed to pivot root");
        return 1;
    } else {
        print("pivot root");
    }

    if (chdir("/") != 0) {
        printerror("failed to change dir to /");
        return 1;
    } else {
        print("changed dir to /");
    }

    if (umount2("/oldroot", MNT_DETACH) != 0) {
        printerror("failed to umount /oldroot");
    } else {
        print("umounted /oldroot");
    }

    if (rmdir("/oldroot") != 0) {
        printerror("failed to remove /oldroot");
        return 1;
    } else {
        print("removed /oldroot");
    }

    print("setup fs completed");
    return 0;
}

extern "C" inline int setup_proc() {
    if (mkdir("/proc", 0755) == -1) {
        perror("mkdir \"proc\"failed");
        return 1;
    } else {
        print("created /proc");
    }
    if (mount("proc", "/proc", "proc",
              MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_BIND | MS_REC,
              "mode=0755,uid=0") != 0) {
        printerror("failed to mount /proc");
        return 1;
    }
    print("mounted /proc");
    return 0;
}

extern "C" inline int setup_interface() {
    if (unshare(CLONE_NEWNET) != 0) {
        return 1;
    };
    print("setup interface completed");
    return 0;
}

extern "C" inline int setup_loopback_interface() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("failed to create socket");
        return 1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ);

    // Bring up the loopback interface
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        printerror("failed to get interface flags");
        close(sock);
        return 1;
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        printerror("failed to set interface flags");
        close(sock);
        return 1;
    }

    close(sock);
    print("loopback interface brought up");
    return 0;
}

extern "C" inline int set_sandbox_hostname(const char *hostname) {
    if (sethostname(hostname, strlen(hostname)) != 0) {
        printerror("failed to set hostname");
        return 1;
    }
    print("hostname set");
    return 0;
}

extern "C" inline void setup_syscall_filtering() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    // set arch
    seccomp_arch_add(ctx, SCMP_ARCH_X86_64);
#define allow_libseccomp(ctx, syscall) \
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscall, 0);

    // compares first arg to 0 if true allow
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SYS_exit_group, 1,
                     SCMP_A0(SCMP_CMP_EQ, 0));
    allow_libseccomp(ctx, SYS_access);
    allow_libseccomp(ctx, SYS_brk);

    // load
    seccomp_load(ctx);
    seccomp_release(ctx);
}

extern "C" inline int setup_cgroups() { return 0; }

extern "C" inline void set_capabilities() {
    struct __user_cap_header_struct cap_header = {_LINUX_CAPABILITY_VERSION_3,
                                                  0};
    struct __user_cap_data_struct cap_data[2];
    // Initialize the capability header
    memset(&cap_header, 0, sizeof(cap_header));
    cap_header.version = _LINUX_CAPABILITY_VERSION_3;
    cap_header.pid = 0;  // Target the current process

    // Initialize capability data
    memset(cap_data, 0, sizeof(cap_data));
    cap_data[0].effective = (1 << CAP_SYS_ADMIN);  // Set CAP_SYS_ADMIN
    cap_data[0].permitted = (1 << CAP_SYS_ADMIN);
    cap_data[0].inheritable = 0;
    if (syscall(SYS_capset, &cap_header, cap_data) == -1) {
        perror("capget");
        return;
    }

    if (cap_data[0].effective & (1 << CAP_SYS_ADMIN)) {
        printf("CAP_SYS_ADMIN is set\n");
    } else {
        printf("CAP_SYS_ADMIN is missing\n");
    }
}
