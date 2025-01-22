#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/capability.h> /* Definition of CAP_* and
                                        _LINUX_CAPABILITY_* constants */

#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h> /* Definition of SYS_* constants */
#include <sys/types.h>
#include <sysexits.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>

int printNetworkInterfaces(void) {
    struct ifaddrs *ptr_ifaddrs = nullptr;

    auto result = getifaddrs(&ptr_ifaddrs);
    if (result != 0) {
        std::cout << "`getifaddrs()` failed: " << strerror(errno) << std::endl;

        return EX_OSERR;
    }

    for (struct ifaddrs *ptr_entry = ptr_ifaddrs; ptr_entry != nullptr;
         ptr_entry = ptr_entry->ifa_next) {
        std::string ipaddress_human_readable_form;
        std::string netmask_human_readable_form;

        std::string interface_name = std::string(ptr_entry->ifa_name);
        sa_family_t address_family = ptr_entry->ifa_addr->sa_family;
        if (address_family == AF_INET) {
            // IPv4

            // Be aware that the `ifa_addr`, `ifa_netmask` and `ifa_data` fields
            // might contain nullptr. Dereferencing nullptr causes "Undefined
            // behavior" problems. So it is need to check these fields before
            // dereferencing.
            if (ptr_entry->ifa_addr != nullptr) {
                char buffer[INET_ADDRSTRLEN] = {
                    0,
                };
                inet_ntop(
                    address_family,
                    &((struct sockaddr_in *)(ptr_entry->ifa_addr))->sin_addr,
                    buffer, INET_ADDRSTRLEN);

                ipaddress_human_readable_form = std::string(buffer);
            }

            if (ptr_entry->ifa_netmask != nullptr) {
                char buffer[INET_ADDRSTRLEN] = {
                    0,
                };
                inet_ntop(
                    address_family,
                    &((struct sockaddr_in *)(ptr_entry->ifa_netmask))->sin_addr,
                    buffer, INET_ADDRSTRLEN);

                netmask_human_readable_form = std::string(buffer);
            }

            std::cout << interface_name
                      << ": IP address = " << ipaddress_human_readable_form
                      << ", netmask = " << netmask_human_readable_form
                      << std::endl;
        } else if (address_family == AF_INET6) {
            // IPv6
            uint32_t scope_id = 0;
            if (ptr_entry->ifa_addr != nullptr) {
                char buffer[INET6_ADDRSTRLEN] = {
                    0,
                };
                inet_ntop(
                    address_family,
                    &((struct sockaddr_in6 *)(ptr_entry->ifa_addr))->sin6_addr,
                    buffer, INET6_ADDRSTRLEN);

                ipaddress_human_readable_form = std::string(buffer);
                scope_id = ((struct sockaddr_in6 *)(ptr_entry->ifa_addr))
                               ->sin6_scope_id;
            }

            if (ptr_entry->ifa_netmask != nullptr) {
                char buffer[INET6_ADDRSTRLEN] = {
                    0,
                };
                inet_ntop(address_family,
                          &((struct sockaddr_in6 *)(ptr_entry->ifa_netmask))
                               ->sin6_addr,
                          buffer, INET6_ADDRSTRLEN);

                netmask_human_readable_form = std::string(buffer);
            }

            std::cout << interface_name
                      << ": IP address = " << ipaddress_human_readable_form
                      << ", netmask = " << netmask_human_readable_form
                      << ", Scope-ID = " << scope_id << std::endl;
        } else {
            // AF_UNIX, AF_UNSPEC, AF_PACKET etc.
            // If ignored, delete this section.
        }
    }

    freeifaddrs(ptr_ifaddrs);
    return EX_OK;
}

int printrootdir(const char *path = "/") {
    DIR *dir = opendir(path);  // Open the directory

    if (dir == nullptr) {
        std::cerr << "Failed to open directory " << path << ": "
                  << strerror(errno) << std::endl;
        return EXIT_FAILURE;
    }

    struct dirent *entry;
    std::cout << "\nListing contents of directory: " << path << std::endl;

    // Read and print each directory entry
    while ((entry = readdir(dir)) != nullptr) {
        if (strncmp(entry->d_name, ".", 1) == 0 ||
            strncmp(entry->d_name, "..", 2) == 0)
            continue;
        std::cout << entry->d_name << ", ";  // Print directory entry name
    }
    std::cout << "\n";
    std::cout << "\n";
    closedir(dir);  // Close the directory
    return EXIT_SUCCESS;
};

// Function to print PID, EUID, and EGID
void printProcessInfo() {
    pid_t pid = getpid();
    uid_t euid = getuid();
    gid_t egid = getgid();

    std::cout << "Process Information:" << std::endl;
    std::cout << "PID: " << pid << std::endl;
    std::cout << "EUID: " << euid << std::endl;
    std::cout << "EGID: " << egid << std::endl;
    std::cout << std::endl;
}

void open_shell() {}
int print_processes_running() {
    const char *path = "/proc";  // Path to the /proc directory
    DIR *dir = opendir(path);    // Open the /proc directory

    if (dir == nullptr) {
        std::cerr << "Failed to open directory " << path << ": "
                  << strerror(errno) << std::endl;
        return EXIT_FAILURE;
    }

    struct dirent *entry;

    std::cout << "List of all running processes (PID and process name):"
              << std::endl;

    // Loop through all entries in the /proc directory
    while ((entry = readdir(dir)) != nullptr) {
        // Only consider directories that contain numbers (representing PIDs)
        if (entry->d_type == DT_DIR &&
            std::all_of(entry->d_name, entry->d_name + strlen(entry->d_name),
                        ::isdigit)) {
            std::string pid = entry->d_name;

            // Open the "comm" file, which contains the name of the process
            std::ifstream commFile("/proc/" + pid + "/comm");
            if (commFile.is_open()) {
                std::string processName;
                std::getline(commFile, processName);  // Read the process name
                commFile.close();
                std::cout << "PID: " << pid
                          << " - Process Name: " << processName << std::endl;
            }
        }
    }

    closedir(dir);  // Close the /proc directory
    return EXIT_SUCCESS;
}

static void pause_() {
    int c = 0;
    while ((c = getchar()) != EOF) {
        break;
    }
}

// Function to retrieve the capabilities using capget syscall
int get_capabilities() {
    struct __user_cap_header_struct header;
    struct __user_cap_data_struct data[2];

    header.version = _LINUX_CAPABILITY_VERSION_3;
    header.pid = 0;

    if (syscall(SYS_capget, &header, data) == -1) {
        perror("capget failed");
        return -1;  // Return -1 on failure
    }

    printf("Capabilities for the current process:\n");
    printf("Effective Capabilities:\n");
    printf("  Capable of: 0x%lx\n", data[0].effective);
    printf("  Permitted: 0x%lx\n", data[0].permitted);
    printf("  Inherited: 0x%lx\n", data[0].inheritable);

    return 0;  // Return 0 on success
}

int main() {
    std::cout << "\n======main=====\n";
    printProcessInfo();
    printNetworkInterfaces();
    printrootdir();
    print_processes_running();
    get_capabilities();
    system("sh");
    return 0;
}
