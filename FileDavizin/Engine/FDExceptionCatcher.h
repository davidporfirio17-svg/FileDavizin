#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

BOOL FDTryObjC(void (NS_NOESCAPE ^block)(void),
               NSException * _Nullable * _Nullable outException);

NS_ASSUME_NONNULL_END
