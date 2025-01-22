#include <sched.h>
#include <sys/mount.h>

#include "sandbox.hpp"

// TO ADD :
// other namespaces to look at
// cgroups, IPC, TIME, UTS , SElinux

typedef int (*main_t)(int argc, char **argv, char **envp);
typedef int (*libc_start_main_t)(int (*main)(int, char **, char **), int argc,
                                 char **argv, void (*init)(void),
                                 void (*fini)(void), void (*rtld_fini)(void),
                                 void(*stack_end));

static libc_start_main_t real_libc_start_main = nullptr;
static main_t actual_main = nullptr;

// Our custom main function
extern "C" int sandbox(int argc, char **argv, char **envp) {
    printf("\n++PRELOADED SANDBOX ENV++\n");
    uid_t uid = geteuid();
    uid_t gid = geteuid();

    unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWPID);

    if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL) != 0) {
        printerror("failed to mount /");
        return 1;
    } else {
        print("mounted /");
    };

    if (set_uid_gid_mappings(uid, gid) != 0) {
        printerror("failed to set uid and gid mappings");
    }

    if (set_sandbox_hostname("sandbox") != 0) {
        printerror("failed to set sandbox hostname");
    }

    // handle child
    pid_t pid = fork();
    if (pid == 0) {
        // set PATH
        const char *default_path =
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
        std::cout << "[SND] pid " << pid << std::endl;

        if (setenv("PATH", default_path, 1) != 0) {
            perror("failed to set PATH");
            return 1;
        }
        unsetenv("LD_PRELOAD");

        if (setup_fs() != 0) {
            printerror("failed to setup fs");
            _exit(1);
        };

        printf("[SND] euid %d egid %d\n", geteuid(), getegid());
        printf("[SND] uid %d gid %d\n", getuid(), getgid());

        set_capabilities();
        std::filesystem::create_directories("/proc");
        if (mount("proc", "/proc", "proc", MS_REC | MS_BIND, NULL) != 0) {
            fprintf(stderr,
                    "[SND] <ERR> Failed to mount /proc: %s (errno: %d)\n",
                    strerror(errno), errno);
            return 1;
        } else {
            print("mounted /proc");
        }

        // if (setup_cgroups() != 0) {}
        // mount_proc();
        print("INIT PID CREATED");

        if (setup_interface() != 0) {
            printerror("failed to setup interface");
            //_exit(1);
        };

        if (setup_loopback_interface() != 0) {
            printerror("failed to setup loopback interface");
            //_exit(1);
        };

        setup_syscall_filtering();
        print("syscall filtering setup");

        int result = actual_main(argc, argv, envp);
        _exit(result);
    }

    int status = -1;
    waitpid(pid, &status, 0);
    return status;
}

extern "C" int __libc_start_main(int (*main)(int, char **, char **), int argc,
                                 char **argv, void (*init)(void),
                                 void (*fini)(void), void (*rtld_fini)(void),
                                 void(*stack_end)) {
    real_libc_start_main =
        (libc_start_main_t)dlsym(RTLD_NEXT, "__libc_start_main");
    actual_main = (main_t)main;
    return real_libc_start_main(sandbox, argc, argv, init, fini, rtld_fini,
                                stack_end);
}
