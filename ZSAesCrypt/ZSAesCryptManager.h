//
//  ZSAesCryptManager.h
//  ZSAesCrypt
//
//  Created by hzs on 15/5/23.
//  Copyright (c) 2015年 powfulhong. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ZSAesCryptManager : NSObject

/* Encryption */
+ (NSString *)encrypt:(NSString *)msg;
+ (NSString *)encrypt:(NSString *)msg key:(NSString *)key;

/* decryption */
+ (NSString *)decrypt:(NSString *)msg;
+ (NSString *)decrypt:(NSString *)msg key:(NSString *)key;

@end