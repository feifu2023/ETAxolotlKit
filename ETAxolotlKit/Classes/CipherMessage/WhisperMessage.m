//
//  WhisperMessage.m
//  AxolotlKit
//
//  Created by Frederic Jacobs on 23/07/14.
//  Copyright (c) 2014 Frederic Jacobs. All rights reserved.
//

#import "AxolotlExceptions.h"
#import "Constants.h"
#import "WhisperMessage.h"
#import "NSData+keyVersionByte.h"
#import "SerializationUtilities.h"
#import <AxolotlKit/AxolotlKit-Swift.h>

#define VERSION_LENGTH 1

@implementation WhisperMessage

- (instancetype)initWithVersion:(int)version macKey:(NSData*)macKey senderRatchetKey:(NSData*)senderRatchetKey counter:(int)counter previousCounter:(int)previousCounter cipherText:(NSData*)cipherText senderIdentityKey:(NSData*)senderIdentityKey receiverIdentityKey:(NSData*)receiverIdentityKey{
    
    if (self = [super init]) {
        
        Byte versionByte = [SerializationUtilities intsToByteHigh:version low:CURRENT_VERSION];
        NSMutableData *serialized = [NSMutableData dataWithBytes:&versionByte length:1];
        
        SPKProtoTSProtoWhisperMessageBuilder *messageBuilder = [SPKProtoTSProtoWhisperMessage builderWithRatchetKey:senderRatchetKey
                                                                                                            counter:counter
                                                                                                         ciphertext:cipherText];
        [messageBuilder setPreviousCounter:previousCounter];
        
        NSError *error;
        NSData *_Nullable messageData = [messageBuilder buildSerializedDataAndReturnError:&error];
        if (!messageData || error) {
            NSLog(@"Could not serialize proto: %@.", error);
            @throw [NSException exceptionWithName:InvalidMessageException reason:@"Could not serialize proto!" userInfo:@{}];
        }
        [serialized appendData:messageData];
        
        NSData *mac = [SerializationUtilities macWithVersion:version
                                                 identityKey:[senderIdentityKey prependKeyType]
                                         receiverIdentityKey:[receiverIdentityKey prependKeyType]
                                                      macKey:macKey
                                                  serialized:serialized];
        
        [serialized appendData:mac];
        
        _version = version;
        _senderRatchetKey = senderRatchetKey;
        _previousCounter = previousCounter;
        _counter = counter;
        _cipherText = cipherText;
        _serialized = [serialized copy];
    }
    
    return self;
}

- (instancetype)initWithData:(NSData*)serialized{
    
    if (self = [super init]) {
        
        if (serialized.length <= (VERSION_LENGTH + MAC_LENGTH)) {
            @throw [NSException exceptionWithName:InvalidMessageException reason:@"Message size is too short to have content" userInfo:@{}];
        }
        
        Byte version;
        [serialized getBytes:&version length:VERSION_LENGTH];
        
        NSData *messageAndMac = [serialized subdataWithRange:NSMakeRange(VERSION_LENGTH, serialized.length - VERSION_LENGTH)];
        
        NSData *messageData = [messageAndMac subdataWithRange:NSMakeRange(0, messageAndMac.length - MAC_LENGTH)];
        
        if ([SerializationUtilities highBitsToIntFromByte:version] < MINIMUM_SUPPORTED_VERSION) {
//            @throw [NSException exceptionWithName:LegacyMessageException reason:@"Message was sent with an unsupported version of the TextSecure protocol." userInfo:@{}];
        }
        
        if ([SerializationUtilities highBitsToIntFromByte:version] > CURRENT_VERSION) {
//            @throw [NSException exceptionWithName:InvalidMessageException reason:@"Unknown Version" userInfo:@{@"Version": [NSNumber numberWithChar:[SerializationUtilities highBitsToIntFromByte:version]]}];
        }
        
        NSError *error;
        SPKProtoTSProtoWhisperMessage *_Nullable whisperMessage =
        [SPKProtoTSProtoWhisperMessage parseData:messageData error:&error];
        if (!whisperMessage || error) {
//            @throw [NSException exceptionWithName:InvalidMessageException reason:@"Incomplete Message" userInfo:@{}];
        }
        
        _serialized = serialized;
        _senderRatchetKey = [whisperMessage.ratchetKey removeKeyType];
        _version = [SerializationUtilities highBitsToIntFromByte:version];
        _counter = whisperMessage.counter;
        _previousCounter = whisperMessage.previousCounter;
        _cipherText = whisperMessage.ciphertext;
    }
    
    return self;
}

- (void)verifyMacWithVersion:(int)messageVersion senderIdentityKey:(NSData *)senderIdentityKey receiverIdentityKey:(NSData*)receiverIdentityKey macKey:(NSData *)macKey{
    
    NSData *data     = [self.serialized subdataWithRange:NSMakeRange(0, self.serialized.length - MAC_LENGTH)];
    NSData *theirMac = [self.serialized subdataWithRange:NSMakeRange(self.serialized.length - MAC_LENGTH, MAC_LENGTH)];
    NSData *ourMac   = [SerializationUtilities macWithVersion:messageVersion
                                                  identityKey:[senderIdentityKey prependKeyType]
                                          receiverIdentityKey:[receiverIdentityKey prependKeyType]
                                                       macKey:macKey
                                                   serialized:data];
    
    if (![theirMac isEqualToData:ourMac]) {
        NSLog(@"Bad Mac!");
//        @throw [NSException exceptionWithName:InvalidMessageException reason:@"Bad Mac!" userInfo:@{}];
    }
}


- (CipherMessageType)cipherMessageType {
    return CipherMessageType_Whisper;
}

#pragma mark - Logging

+ (NSString *)logTag
{
    return [NSString stringWithFormat:@"[%@]", self.class];
}

- (NSString *)logTag
{
    return self.class.logTag;
}

@end
