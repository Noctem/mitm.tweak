#import <Foundation/Foundation.h>
#import <Security/SecureTransport.h>
#import <Security/Security.h>
#include <CFNetwork/CFNetwork.h>
#include <CFNetwork/CFProxySupport.h>

#import "substrate.h"

static void SSKLog(NSString *format, ...)
{
    NSString *newFormat = [[NSString alloc] initWithFormat:@"=== SSL Kill Switch 2: %@", format];
    va_list args;
    va_start(args, format);
    NSLogv(newFormat, args);
    va_end(args);
}

/**
 * Remove cert pinning
 **/
%hook NIATrustedCertificatesAuthenticator

-(void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler {
    NSLog(@"[mitm] NIATrustedCertificatesAuthenticator.didReceiveChallenge");
    NSURLCredential *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
    completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
}

%end

%hook PGPTrustedCertificatesAuthenticator

-(void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler {
    NSLog(@"[mitm] PGPTrustedCertificatesAuthenticator.didReceiveChallenge");
    NSURLCredential *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
    completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
}

%end

%hook NSURLConnectionDelegate

- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    NSLog(@"[mitm] NSURLConnectionDelegate connection:willSendRequestForAuthenticationChallenge:");
    if([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
    {
        [challenge.sender useCredential:[NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust] forAuthenticationChallenge:challenge];
    }
}

- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace{
    NSLog(@"[mitm] NSURLConnectionDelegate connection:canAuthenticateAgainstProtectionSpace:");
    if([[protectionSpace authenticationMethod] isEqualToString:NSURLAuthenticationMethodServerTrust])
    {
        return YES;
    }

    return NO;
}

- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    NSLog(@"[mitm] NSURLConnectionDelegate connection:didReceiveAuthenticationChallenge");
    if([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
    {
        [challenge.sender useCredential:[NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust] forAuthenticationChallenge:challenge];
    }
}

%end

//////////////////////

%hook NSURLConnection

- (id)initWithRequest:(NSURLRequest *)request delegate:(id < NSURLConnectionDelegate >)delegate {
    NSLog(@"[mitm] NSURLConnection.initWithRequest %@", request);

    id origResult;
    origResult = %orig(request, delegate);

    return origResult;
}

- (id)initWithRequest:(NSURLRequest *)request delegate:(id < NSURLConnectionDelegate >)delegate startImmediately:(BOOL)startImmediately {
    NSLog(@"[mitm] NSURLConnection.initWithRequest %@", request);

    id origResult;
    origResult = %orig(request, delegate, startImmediately);

    return origResult;
}

%end

//////////////////////

%hook UnityWWWConnectionDelegate

- (id)initWithURL:(NSURL*)url udata:(void*)udata {
    NSLog(@"[mitm] UnityWWWConnectionDelegate.initWithURL %@", url);
    return %orig(url, udata);
}

%end

//////////////////////

%hook UnityWWWConnectionSelfSignedCertDelegate 

- (void)connection:(NSURLConnection*)connection didReceiveResponse:(NSURLResponse*)response {
    NSLog(@"[mitm] UnityWWWConnectionSelfSignedCertDelegate.didReceiveResponse");
    %orig(connection, response);
}

- (BOOL)connection:(NSURLConnection*)connection handleAuthenticationChallenge:(NSURLAuthenticationChallenge*)challenge
{
    NSLog(@"[mitm] UnityWWWConnectionSelfSignedCertDelegate.handleAuthenticationChallenge");
    return %orig(connection, challenge);
}

%end

//////////////////////

/**
 * Hook network calls
 **/

%hook __NSURLSessionLocal

- (id)dataTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler
{
    NSString* host = [request URL].host;

    NSLog(@"[mitm] __NSURLSessionLocal.dataTaskWithRequest %@", host);
    return %orig(request, completionHandler);
}

%end

////////////////////

//////////////////////

%hook USURLLoader


- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    NSLog(@"[mitm] USURLLoader connection:willSendRequestForAuthenticationChallenge:");
    if([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
    {
        [challenge.sender useCredential:[NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust] forAuthenticationChallenge:challenge];
    }
}

- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace{
    NSLog(@"[mitm] USURLLoader connection:canAuthenticateAgainstProtectionSpace:");
    if([[protectionSpace authenticationMethod] isEqualToString:NSURLAuthenticationMethodServerTrust])
    {
        return YES;
    }

    return NO;
}

- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    NSLog(@"[mitm] USURLLoader connection:didReceiveAuthenticationChallenge");
    if([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
    {
        [challenge.sender useCredential:[NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust] forAuthenticationChallenge:challenge];
    }
}


%end

//////////////////////

%hook CRNSURLConnectionDelegateProxy

- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    NSLog(@"[mitm] USURLLoader connection:willSendRequestForAuthenticationChallenge:");
    if([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
    {
        [challenge.sender useCredential:[NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust] forAuthenticationChallenge:challenge];
    }
}

- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace{
    NSLog(@"[mitm] USURLLoader connection:canAuthenticateAgainstProtectionSpace:");
    if([[protectionSpace authenticationMethod] isEqualToString:NSURLAuthenticationMethodServerTrust])
    {
        return YES;
    }

    return NO;
}

- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    NSLog(@"[mitm] USURLLoader connection:didReceiveAuthenticationChallenge");
    if([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
    {
        [challenge.sender useCredential:[NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust] forAuthenticationChallenge:challenge];
    }
}


%end

//////////////////////

%hook NSOutputStream

+ (id)outputStreamWithURL:(NSURL *)url append:(BOOL)shouldAppend {
    NSLog(@"[mitm] outputStreamWithURL %@", url);
    return %orig;
}


- (id)initWithURL:(NSURL *)url append:(BOOL)shouldAppend {
    NSLog(@"[mitm] initWithURL %@", url);
    return %orig;
}

%end

//////////////////////

%hook NSDictionary

-(BOOL) writeToURL:(NSURL *)aURL atomically:(BOOL)flag {
    NSLog(@"[mitm] NSDictionary.writeToURL %@", aURL);
    return %orig;
}
%end

//////////////////////

%hook NSData

-(BOOL) writeToURL:(NSURL *)aURL options:(NSDataWritingOptions)mask error:(NSError **)errorPtr {
    NSLog(@"[mitm] NSData.writeToURL %@", aURL);
    return %orig;
}
%end


static OSStatus (*original_SSLSetSessionOption)(SSLContextRef context,
                                                SSLSessionOption option,
                                                Boolean value);

static OSStatus replaced_SSLSetSessionOption(SSLContextRef context,
                                             SSLSessionOption option,
                                             Boolean value)
{
    // Remove the ability to modify the value of the kSSLSessionOptionBreakOnServerAuth option
    if (option == kSSLSessionOptionBreakOnServerAuth)
    {
        return noErr;
    }
    return original_SSLSetSessionOption(context, option, value);
}


static SSLContextRef (*original_SSLCreateContext)(CFAllocatorRef alloc,
                                                  SSLProtocolSide protocolSide,
                                                  SSLConnectionType connectionType);

static SSLContextRef replaced_SSLCreateContext(CFAllocatorRef alloc,
                                               SSLProtocolSide protocolSide,
                                               SSLConnectionType connectionType)
{
    SSLContextRef sslContext = original_SSLCreateContext(alloc, protocolSide, connectionType);

    // Immediately set the kSSLSessionOptionBreakOnServerAuth option in order to disable cert validation
    original_SSLSetSessionOption(sslContext, kSSLSessionOptionBreakOnServerAuth, true);
    return sslContext;
}


static OSStatus (*original_SSLHandshake)(SSLContextRef context);

static OSStatus replaced_SSLHandshake(SSLContextRef context)
{

    OSStatus result = original_SSLHandshake(context);

    // Hijack the flow when breaking on server authentication
    if (result == errSSLServerAuthCompleted)
    {
        // Do not check the cert and call SSLHandshake() again
        return original_SSLHandshake(context);
    }

    return result;
}



static OSStatus(*original_SecTrustEvaluate)(SecTrustRef trust, SecTrustResultType *result);

OSStatus new_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result)
{
    NSLog(@"[mitm] SecTrustEvaluate");
    *result = kSecTrustResultProceed;
    return errSecSuccess;
}

static OSStatus (*orig_SSLSetSessionOption)(SSLContextRef context, SSLSessionOption option, Boolean value);

static OSStatus new_SSLSetSessionOption(SSLContextRef context, SSLSessionOption option, Boolean value) {
    // Remove the ability to modify the value of the kSSLSessionOptionBreakOnServerAuth option
    NSLog(@"[mitm] SSLSetSessionOption");
    if (option == kSSLSessionOptionBreakOnServerAuth)
        return noErr;
    else
        return orig_SSLSetSessionOption(context, option, value);
}


__attribute__((constructor)) static void init(int argc, const char **argv)
{
    // Substrate-based hooking; only hook if the preference file says so
    SSKLog(@"Subtrate hook enabled.");

    // SecureTransport hooks - works up to iOS 9
    MSHookFunction((void *) SSLHandshake,(void *)  replaced_SSLHandshake, (void **) &original_SSLHandshake);
    MSHookFunction((void *) SSLSetSessionOption,(void *)  replaced_SSLSetSessionOption, (void **) &original_SSLSetSessionOption);
    MSHookFunction((void *) SSLCreateContext,(void *)  replaced_SSLCreateContext, (void **) &original_SSLCreateContext);

    MSHookFunction((void *) SecTrustEvaluate,(void *)  new_SecTrustEvaluate, (void **) &original_SecTrustEvaluate);
    MSHookFunction((void *) SSLSetSessionOption,(void *)  new_SSLSetSessionOption, (void **) &orig_SSLSetSessionOption);
}
