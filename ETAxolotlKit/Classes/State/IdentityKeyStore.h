//
//  IdentityKeyStore.h
//  AxolotlKit
//
//  Created by Frederic Jacobs on 12/10/14.
//  Copyright (c) 2014 Frederic Jacobs. All rights reserved.
//

#import <Foundation/Foundation.h>
@class ECKeyPair;

@protocol IdentityKeyStore <NSObject>

- (ECKeyPair*)identityKeyPair;
- (int64_t)localRegistrationId;
- (BOOL)saveRemoteIdentity:(NSData*)identityKey recipientId:(NSString*)recipientId;
- (BOOL)isTrustedIdentityKey:(NSData*)identityKey recipientId:(NSString*)recipientId;

@end
