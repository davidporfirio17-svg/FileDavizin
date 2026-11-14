#import "FDExceptionCatcher.h"

BOOL FDTryObjC(void (NS_NOESCAPE ^block)(void),
               NSException * _Nullable * _Nullable outException) {
    @try {
        block();
        return YES;
    } @catch (NSException *e) {
        NSLog(@"[FD] ObjC exception caught: %@ — %@", e.name, e.reason);
        if (outException) *outException = e;
        return NO;
    }
}
