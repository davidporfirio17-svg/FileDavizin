#import <Foundation/Foundation.h>
#include <stdint.h>
#include <stdbool.h>

NS_ASSUME_NONNULL_BEGIN

/// Initialize the container engine — performs initial symlink sandbox escape.
/// Returns the number of base paths that are accessible after init.
int FDContainerEngineInit(void);

/// Discover the data container path for a given bundle ID.
NSString * _Nullable FDDiscoverContainerPath(NSString *bundleID);

/// Grant sandbox read/write access to a filesystem path.
/// Returns a handle >= 0 on success, < 0 on failure.
int64_t FDGrantAccess(const char *path);

/// Release a previously obtained sandbox access grant.
void FDReleaseAccess(int64_t handle);

/// Enumerate installed app containers.
/// Returns an array of dictionaries with keys "identifier" and "path".
NSArray<NSDictionary<NSString *, NSString *> *> *FDEnumerateApps(NSUInteger limit);

/// Test whether the engine can write to a directory.
BOOL FDCanWrite(const char *dirPath);

/// Get the diagnostic string from the last operation.
const char * _Nonnull FDLastDiagnostic(void);

/// Run full diagnostic and return a detailed report string.
/// This tests every subsystem and logs results via NSLog.
NSString *FDRunFullDiagnostic(void);

NS_ASSUME_NONNULL_END
