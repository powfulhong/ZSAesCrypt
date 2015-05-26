//
//  ZSAesCryptManager.m
//  ZSAesCrypt
//
//  Created by hzs on 15/5/23.
//  Copyright (c) 2015年 powfulhong. All rights reserved.
//

#import "ZSAesCryptManager.h"
#import "openssl/aes.h"

#define KEY @"d$frk^zti#pwtlz$"

int aes_decrypt(char *in, char *key, char *out, uint32_t length)
{
    if(!in || !key || !out) {
        return 0;
    }
    
    unsigned char iv[AES_BLOCK_SIZE];
    AES_KEY aes;
    
    memset(iv, '0', AES_BLOCK_SIZE);
    
    if (AES_set_decrypt_key((unsigned char*)key, 128, &aes) < 0) {
        return 0;
    }
    
    /* decrypt by block */
    int block_num = length / AES_BLOCK_SIZE;
    for (int i = 0; i < block_num; ++i) {
        AES_cbc_encrypt((unsigned char *)(in + i * AES_BLOCK_SIZE), (unsigned char*)(out + i * AES_BLOCK_SIZE), AES_BLOCK_SIZE, &aes, iv, AES_DECRYPT);
    }
    
    return 1;
}

/* size must be 16 byte align. */
char *decrypt_string(char *data, uint32_t size, char *password)
{
    if (!data || !password) {
        return nil;
    }
    
    char key[AES_BLOCK_SIZE];
    size_t pwd_len = 0;
    
    char *out = (char *)malloc(size + 1);
    if (!out) {
        return NULL;
    }
    
    memset(out, '\0', size + 1);
    
    pwd_len = strlen(password);
    for(int i = 0; i < AES_BLOCK_SIZE; i++) {
    /*
        if (i < pwd_len) {
            key[i] = 32 + password[i];
        } else {
            key[i] = 32 + i;
        }
     */
        key[i] = 32 + (i < pwd_len ? password[i] : i);
    }
    
    if(!aes_decrypt(data, key, out, size)) {
        if (out != NULL) {
            free(out);
        }
        
        return NULL;
    }
    
    return out;
}

int aes_encrypt(char *in, char *key, char *out, uint32_t length)
{
    if(!in || !key || !out) {
        return 0;
    }
    
    unsigned char iv[AES_BLOCK_SIZE];
    AES_KEY aes;
    
    memset(iv, '0', AES_BLOCK_SIZE);
    
    if(AES_set_encrypt_key((unsigned char*)key, 128, &aes) < 0)    {
        return 0;
    }
    
    int block_num = length / AES_BLOCK_SIZE;
    for (int i = 0; i < block_num; ++i) {
        AES_cbc_encrypt((unsigned char*)(in + i * AES_BLOCK_SIZE), (unsigned char*)(out + i * AES_BLOCK_SIZE), AES_BLOCK_SIZE, &aes, iv, AES_ENCRYPT);
    }
    
    return 1;
}

/* Remember to free the return buffer. */
int encrypt_string(char *in, char *password, char **out, uint32_t in_len)
{
    if (!in || !password) {
        return -1;
    }
    
    char key[AES_BLOCK_SIZE];
    size_t pwd_len = 0;
    uint32_t eny_size; /* must be 16 byte align */
    
    eny_size = (in_len / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
    
    pwd_len = strlen(password);

    for(int i = 0; i < AES_BLOCK_SIZE; i++) {
    /*
        if (i < pwd_len) {
            key[i] = 32 + password[i];
        } else {
            key[i] = 32 + i;
        }
     */
        key[i] = 32 + (i < pwd_len ? password[i] : i);
    }
    
    /* 填充明文 */
    char *in_padding = malloc(sizeof(char) * eny_size);
    memcpy(in_padding, in, in_len);
    int pad = AES_BLOCK_SIZE - in_len % AES_BLOCK_SIZE;
    for (int i = in_len; i < eny_size; ++i) {
        in_padding[i] = pad;
    }
    
    *out = (char *)malloc(sizeof(char) * eny_size);
    if(!aes_encrypt(in_padding, key, *out, eny_size)) {
        if (*out != NULL) {
            free(*out);
        }
        free(in_padding);
        return -1;
    }
    
    free(in_padding);
    
    return eny_size;
}

/* 十六进制转为十进制 */
char* getDecimalismByhex(NSString *hex)
{
    NSDictionary *hexDic = @{@"0" : @"0", @"1" : @"1", @"2" : @"2", @"3" : @"3", @"4" : @"4", @"5" : @"5", @"6" : @"6",
                             @"7" : @"7", @"8" : @"8", @"9" : @"9", @"a" : @"10", @"A" : @"10", @"b" : @"11",
                             @"B" : @"11", @"c" : @"12", @"C" : @"12", @"d" : @"13", @"D" : @"13", @"e" : @"14",
                             @"E" : @"14", @"f" : @"15", @"F" : @"15"};
    
    char *decimalism = malloc(sizeof(uint8_t) * [hex length] / 2);
    
    for (int i = 0; i < [hex length]; i = i + 2) {
        unichar x = [hex characterAtIndex:i];
        unichar y = [hex characterAtIndex:i + 1];
        
        decimalism[i / 2] = [[hexDic objectForKey:[NSString stringWithFormat:@"%c", x]] integerValue] * 16 + [[hexDic objectForKey:[NSString stringWithFormat:@"%c", y]] integerValue];
    }
    
    return decimalism;
    
}

/* 十进制转为十六进制 */
NSString * getHexByDecimalism(unsigned char *in, int len)
{
    NSDictionary *hexDic = @{@"0" : @"0", @"1" : @"1", @"2" : @"2", @"3" : @"3", @"4" : @"4", @"5" : @"5", @"6" : @"6",
                             @"7" : @"7", @"8" : @"8", @"9" : @"9", @"10" : @"a", @"11" : @"b", @"12" : @"c", @"13" : @"d", @"14" : @"e", @"15" : @"f"};
    NSMutableString *ret = [NSMutableString stringWithString:@""];
    for (int i = 0; i < len; ++i) {
        [ret appendFormat:@"%@%@", [hexDic objectForKey:[NSString stringWithFormat:@"%d", in[i] / 16]], [hexDic objectForKey:[NSString stringWithFormat:@"%d", in[i] % 16]]];
    }
    
    return ret;
}

@implementation ZSAesCryptManager

+ (NSString *)encrypt:(NSString *)msg
{
    return [ZSAesCryptManager encrypt:msg key:KEY];
}

+ (NSString *)encrypt:(NSString *)msg key:(NSString *)key
{
    if (msg == nil || key == nil) {
        return nil;
    }

    char *out;
    char *msg_encrypt = (char *)[msg UTF8String];
    int eny_size = encrypt_string(msg_encrypt, (char *)[key UTF8String], &out, (int)strlen(msg_encrypt));
    
    if (eny_size == -1 || out == NULL) {
        return nil;
    }
    
    NSString *encrypt_msg = getHexByDecimalism((unsigned char *)out, eny_size);
    free(out);
    
    return encrypt_msg;
}

+ (NSString *)decrypt:(NSString *)msg
{
    return [ZSAesCryptManager decrypt:msg key:KEY];
}

+ (NSString *)decrypt:(NSString *)msg key:(NSString *)key
{
    if (msg == nil || key == nil) {
        return nil;
    }
    
    char *encrypt_decimalism_msg = getDecimalismByhex(msg);
    uint32_t eny_size = (uint32_t)[msg length] / 2;
    
    char *decrypt_char_msg = decrypt_string(encrypt_decimalism_msg, eny_size, (char *)[key UTF8String]);
    
    free(encrypt_decimalism_msg);
    if (decrypt_char_msg == NULL) {
        return nil;
    }
    
    /* 补齐字符长度，根据补齐规则，最后一个字符即为补齐的字符的长度 */
    int padding_len = (int)decrypt_char_msg[eny_size - 1];
    /* 包含补齐字符的明文 */
    NSString *total_decrypt_msg = [NSString stringWithCString:decrypt_char_msg encoding:NSUTF8StringEncoding];
    /* 去除补齐字符的明文 */
    NSString *decrypt_msg = [total_decrypt_msg substringToIndex:[total_decrypt_msg length] - padding_len];
    
    free(decrypt_char_msg);
    
    return decrypt_msg;
}

@end
