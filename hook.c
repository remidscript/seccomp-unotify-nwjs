#define _GNU_SOURCE

#include<stdlib.h>
#include<stdio.h>
#include<stdint.h>
#include<stdbool.h>
#include<string.h>
#include<err.h>
#include<fcntl.h>
#include<stddef.h>
#include<stdcountof.h>
#include<errno.h>
#include<dirent.h>
#include<libgen.h>
#include<ctype.h>


#include<unistd.h>
#include<linux/limits.h>
#include<linux/seccomp.h>
#include<linux/filter.h>
#include<linux/audit.h>

#include<sys/syscall.h>
#include<sys/types.h>
#include<sys/prctl.h>
#include<sys/ioctl.h>
#include<sys/signal.h>
#include<sys/socket.h>

static int seccomp(unsigned int operation, unsigned int flags, void *args){ return syscall(SYS_seccomp, operation, flags, args); }
static bool cookieIsValid(int notifyFd, uint64_t id){ return ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0; }
static void sigchldHandler(int sig)
{
    char msg[] = "Child terminated.\n";
    write(STDOUT_FILENO, msg, sizeof(msg) - 1);
    _exit(EXIT_SUCCESS);
}
static void closeSocketPair(int sockPair[2])
{
    if (close(sockPair[0]) == -1) err(EXIT_FAILURE, "closeSocketPair-close-0");
    if (close(sockPair[1]) == -1) err(EXIT_FAILURE, "closeSocketPair-close-1");
    printf("sockPair closed.\n");
}
static int sendFd(int sockFd, int fd)
{
    char controlBuf[CMSG_SPACE(sizeof(int))] = {0};
    struct msghdr msg = {
        .msg_iov = &(struct iovec){
            .iov_base = "12345",
            .iov_len = 6
        },
        .msg_iovlen = 1,
        .msg_control = controlBuf,
        .msg_controllen = sizeof(controlBuf)
    };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    *cmsg = (struct cmsghdr){
        .cmsg_level = SOL_SOCKET,
        .cmsg_type = SCM_RIGHTS,
        .cmsg_len = CMSG_LEN(sizeof(fd))
    };
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
    return sendmsg(sockFd, &msg, 0); // -1 means error
}
static int recvFd(int sockFd)
{
    char controlBuf[CMSG_SPACE(sizeof(int))] = {0};
    char bufferChar[1];
    struct msghdr msg = {
        .msg_iov = &(struct iovec){
            .iov_base = bufferChar,
            .iov_len = 1
        },
        .msg_iovlen = 1,
        .msg_control = controlBuf,
        .msg_controllen = sizeof(controlBuf)
    };
    ssize_t recvLen = recvmsg(sockFd, &msg, MSG_WAITALL);
    if(recvLen == -1) {
        perror("recvmsg");
        return -1;
    }

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    int fd = *(int*)CMSG_DATA(cmsg);
    return fd;
}




void get_process_name_by_comm(int pid, char *buffer, size_t len)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    
    FILE *f = fopen(path, "r");
    if (f) {
        if (fgets(buffer, len, f) != NULL) {
            // Strip the trailing newline character
            buffer[strcspn(buffer, "\n")] = '\0';
        } else {
            strncpy(buffer, "Unknown", len);
        }
        fclose(f);
    } else {
        strncpy(buffer, "Process not found", len);
    }
}



#define X32_SYSCALL_BIT 0x40000000
#define X86_64_CHECK_ARCH_AND_LOAD_SYSCALL_NR \
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))), \
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 2), \
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))), \
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1), \
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)
static int installNotifyFilter(void){
    struct sock_filter filter[] = {
        X86_64_CHECK_ARCH_AND_LOAD_SYSCALL_NR,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat, 1, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_access, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = countof(filter),
        .filter = filter,
    };
    int notifyFd = seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (notifyFd == -1)
        err(EXIT_FAILURE, "seccomp-install-notify-filter");
    return notifyFd;
}

// #define HASH_TABLE_SLOTS 32
// int hashFunction(char* name)
// {
//     int sum = 0;
//     size_t len = strlen(name);
//     for (size_t i = 0; i < len; i++){
//         sum *= (int)name[i];
//         sum += len;
//     }
//     // printf("HASH RESULT: %d,   FROM: %s\n", sum % HASH_TABLE_SLOTS,name);
//     return sum % HASH_TABLE_SLOTS;
// }

static char *caseInsensitivePath(char fullPath[PATH_MAX])
{
    char dirPath[PATH_MAX];
    memcpy(dirPath, fullPath, sizeof(dirPath));
    char *dirName = dirname(dirPath); 

    char basePath[PATH_MAX];
    memcpy(basePath, fullPath, sizeof(basePath));
    char *baseName = basename(basePath);
    
    char lowerBaseName[NAME_MAX];
    size_t base_len = strlen(baseName);
    for (int i=0; i<base_len; i++)
        lowerBaseName[i] = tolower((unsigned char)baseName[i]);
    lowerBaseName[base_len] = '\0';


    DIR *d = opendir(dirName);
    if (!d)
        return NULL;

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL)
    {
        size_t len = strlen(entry->d_name);
        char lowerName[NAME_MAX];
        for (int i=0; i<len; i++)
            lowerName[i] = tolower((unsigned char)entry->d_name[i]);
        lowerName[len] = '\0';

        if (strcasecmp(lowerName, lowerBaseName) == 0)
        {
            char *corrected = malloc(PATH_MAX);
            snprintf(corrected, PATH_MAX, "%s/%s", dirName, entry->d_name);
            closedir(d);
            printf("\tCORRECTED: %s\n", corrected);

            return corrected;
            // return openat(AT_FDCWD, corrected, flags, mode);
        }
    }
    closedir(d);
    return NULL;
}

// Many arguments need more data from target process so use PID for /proc/ operations. (pathName here is a pointer inside target process memory for example.)
static char *customPath(pid_t pid, int dirFd, const uintptr_t pathNamePtr)
{
    char procMemPath[PATH_MAX];
    snprintf(procMemPath, sizeof(procMemPath), "/proc/%d/mem", pid);

    int procMemFd = open(procMemPath, O_RDONLY | O_CLOEXEC);
    if (procMemFd == -1){
        char proc_name[256];
        get_process_name_by_comm(pid, proc_name, sizeof(proc_name));
        perror("openProcMemPath");
        printf("[%s] openProcMemPath\n", proc_name);
        return NULL;
    }
    
    char path[PATH_MAX];
    ssize_t n = pread(procMemFd, path, sizeof(path), pathNamePtr);
    close(procMemFd);
    if (n<=0){
        perror("preadProcMemFd");
        return NULL;
    }
    path[sizeof(path)-1] = '\0';

    char *fullPath = malloc(PATH_MAX);
    if (path[0] == '/'){
        snprintf(fullPath, PATH_MAX, "%s", path);
    }
    else if (dirFd == AT_FDCWD){
        char procCwdPath[PATH_MAX];
        snprintf(procCwdPath, sizeof(procCwdPath), "/proc/%d/cwd", pid);
        char cwd[PATH_MAX];
        ssize_t n = readlink(procCwdPath, cwd, sizeof(cwd)-1);
        if (n == -1){
            perror("cwdReading");
            return NULL;
        }
        cwd[n] = '\0';
        snprintf(fullPath, PATH_MAX, "%s/%s", cwd, path);
    }
    else{
        char procFdPath[PATH_MAX];
        snprintf(procFdPath, sizeof(procFdPath), "/proc/%d/fd/%d", pid, dirFd);
        char dir[PATH_MAX];
        ssize_t n = readlink(procFdPath, dir, sizeof(dir)-1);
        if (n == -1){
            perror("dirReading");
            return NULL;
        }
        dir[n] = '\0';
        snprintf(fullPath, PATH_MAX, "%s/%s", dir, path);
    }
    

    return fullPath;
}

void handleNotifications(int notifyFd)
{
    struct seccomp_notif_sizes sizes;
    seccomp(SECCOMP_GET_NOTIF_SIZES, 0, &sizes);
    struct seccomp_notif *req = malloc(sizes.seccomp_notif);
    struct seccomp_notif_resp *resp = malloc(sizes.seccomp_notif_resp);
    for (;;){
        memset(req, 0, sizes.seccomp_notif);
        if (ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_RECV, req) == -1) {
            if (errno == EINTR)
                continue;
            else if (errno == ENOENT) // Target exited
                continue;
            err(EXIT_FAILURE, "ioctl-SECCOMP_IOCTL_NOTIF_RECV");
        }
        // printf("Got notification (ID %#llx) for PID %d\n", req->id, req->pid);
        *resp = (struct seccomp_notif_resp){
            .id = req->id,
            .flags = 0,
            .val = 0,
            .error = 0
        };
        char proc_name[256];
        get_process_name_by_comm(req->pid, proc_name, sizeof(proc_name));
        if (strcmp(proc_name, "nw")==0){
            switch(req->data.nr){
                case SYS_openat:{
                    int fd = -1;
                    char *path = customPath(req->pid, req->data.args[0], (uintptr_t)req->data.args[1]);
                    // printf("[%s]Openat = %s\n", proc_name, path);
                    if (strncmp(path, "/proc", 5) == 0 || strncmp(path, "/opt", 4) == 0 || strncmp(path, "/dev", 4) == 0){
                        // printf("SKIP\n");
                        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                        break;
                    }

                    fd = openat(AT_FDCWD, path, req->data.args[2], req->data.args[3]);
                    
                    if (fd<0){
                        char *newPath = caseInsensitivePath(path);
                        fd = openat(AT_FDCWD, newPath, req->data.args[2], req->data.args[3]);
                        free(newPath);
                    }
                    free(path);

                    if (fd>=0){
                        struct seccomp_notif_addfd addFd = {
                            .id = resp->id,
                            .srcfd = fd,
                            .flags = 0,
                            .newfd_flags = 0
                        };
                        int remoteFd = ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_ADDFD, &addFd);
                        // if (remoteFd == -1)
                        //     perror("SECCOMP_IOCTL_NOTIF_ADDFD");
                        close(fd);
                        resp->error = 0;
                        resp->val = remoteFd;
                    }
                    else 
                    {
                        resp->val = -1;
                        resp->error = -errno;
                    }
                    break;
                }
                case SYS_access: {
                    char *path = customPath(req->pid, AT_FDCWD, (uintptr_t)req->data.args[0]);
                    // printf("[%s]Access = %s\n", proc_name, path);
                    int mode = (int)req->data.args[1];
                    if (strncmp(path, "/proc", 5) == 0 || strncmp(path, "/opt", 4) == 0 || strncmp(path, "/dev", 4) == 0){
                        // printf("SKIP\n");
                        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                        break;
                    }

                    int rc = access(path, mode);

                    if (rc != 0 && errno == ENOENT) {
                        char *corrected = caseInsensitivePath(path);
                        printf("[%s]AccessCorrect = %s\n", proc_name, corrected);
                        if (corrected)
                            rc = access(corrected, mode);
                        free(corrected);
                    }
                    // resp->val = -1;
                    // resp->error = -ENOENT;
                    resp->val   = (rc == 0) ? 0 : -1;
                    resp->error = (rc == 0) ? 0 : -errno;
                    if (errno == ENOENT)
                        printf("NOT FOUND!\n");

                    free(path);
                    break;
                }
            }
        }
        else
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        if (ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_SEND, resp) == -1) {
            if (errno == ENOENT)
                printf("\tResponse failed with ENOENT; perhaps target process's syscall was interrupted by a signal?\n");
            else
                perror("ioctl-SECCOMP_IOCTL_NOTIF_SEND");
        }
    }
}
void supervisor(int sockPair[2])
{
    int notifyFd = recvFd(sockPair[1]);
    if (notifyFd == -1) err(EXIT_FAILURE, "recvfd");
    closeSocketPair(sockPair);

    handleNotifications(notifyFd);
}

int main(int argc, char *argv[])
{
    int sockPair[2];
    setbuf(stdout, NULL);

    if (argc < 2) {
        fprintf(stderr, "Pathname to the game directory required as the first argument.\n");
        exit(EXIT_FAILURE);
    }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockPair) == -1)
        err(EXIT_FAILURE, "Socket pair failed");
    
    pid_t pid = fork(); // Mitosis onwards

    if (pid == -1) err(EXIT_FAILURE, "Forking process failed");
    else if (pid == 0){ // The child
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
            err(EXIT_FAILURE, "process-control-no-new-privileges");
        if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0))
            err(EXIT_FAILURE, "process-control-set-dumpable");;
        int notifyFd = installNotifyFilter();
        if (sendFd(sockPair[0], notifyFd) == -1)
            err(EXIT_FAILURE, "sendfd");
        execvp("nw", &argv[0]); // Assuming nw is installed in user's PATH being NW.js binary.
        if (close(notifyFd) == -1)
            err(EXIT_FAILURE, "close-target-notify-fd");
        printf("Child finished job.\n");
    }
    else { // The parent
        struct sigaction sa = {.sa_handler = sigchldHandler, .sa_flags = 0};
        sigemptyset(&sa.sa_mask);
        if (sigaction(SIGCHLD, &sa, NULL) == -1)
            err(EXIT_SUCCESS, "sigaction");
        supervisor(sockPair);
    }
    closeSocketPair(sockPair);
    exit(EXIT_SUCCESS);
}