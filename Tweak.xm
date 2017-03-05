#import <Foundation/Foundation.h>
#import <QuartzCore/QuartzCore.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <fishhook.h>
#import <arpa/inet.h>
#import <netdb.h>

static NSString *mitmDirectory;

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

/**
 * Low level cert pinning bypass
 */
static OSStatus(*original_SecTrustEvaluate)(SecTrustRef trust, SecTrustResultType *result);

OSStatus new_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result);
OSStatus new_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result)
{
	NSLog(@"[mitm] SecTrustEvaluate");
	*result = kSecTrustResultProceed;
	return errSecSuccess;
}

static CFDictionaryRef (*orig_SecTrustGetExceptionForCertificateAtIndex)(SecTrustRef trust, CFIndex ix);

static CFDictionaryRef new_SecTrustGetExceptionForCertificateAtIndex(SecTrustRef trust, CFIndex ix);
static CFDictionaryRef new_SecTrustGetExceptionForCertificateAtIndex(SecTrustRef trust, CFIndex ix) {
	NSLog(@"[mitm] SecTrustGetExceptionForCertificateAtIndex");
	return NULL;
}

/**
 * Another cert pinning bypass
 */
static OSStatus (*orig_SSLSetSessionOption)(SSLContextRef context, SSLSessionOption option, Boolean value);
static OSStatus new_SSLSetSessionOption(SSLContextRef context, SSLSessionOption option, Boolean value);
static OSStatus new_SSLSetSessionOption(SSLContextRef context, SSLSessionOption option, Boolean value) {
    // Remove the ability to modify the value of the kSSLSessionOptionBreakOnServerAuth option
	NSLog(@"[mitm] SSLSetSessionOption");
    if (option == kSSLSessionOptionBreakOnServerAuth)
        return noErr;
    else
        return orig_SSLSetSessionOption(context, option, value);
}


static SSLContextRef (*orig_SSLCreateContext) (CFAllocatorRef alloc, SSLProtocolSide protocolSide, SSLConnectionType connectionType);

static SSLContextRef new_SSLCreateContext(CFAllocatorRef alloc, SSLProtocolSide protocolSide, SSLConnectionType connectionType);
static SSLContextRef new_SSLCreateContext(CFAllocatorRef alloc, SSLProtocolSide protocolSide, SSLConnectionType connectionType) {
	NSLog(@"[mitm] SSLCreateContext");
    SSLContextRef sslContext = orig_SSLCreateContext(alloc, protocolSide, connectionType);
    // Immediately set the kSSLSessionOptionBreakOnServerAuth option in order to disable cert validation
    orig_SSLSetSessionOption(sslContext, kSSLSessionOptionBreakOnServerAuth, true);
    return sslContext;
}

static OSStatus (*orig_SSLHandshake)(SSLContextRef context);

static OSStatus new_SSLHandshake(SSLContextRef context);
static OSStatus new_SSLHandshake(SSLContextRef context) {
	NSLog(@"[mitm] SSLHandshake");
    OSStatus result = orig_SSLHandshake(context);
    if (result == errSSLServerAuthCompleted) 
	{
        return orig_SSLHandshake(context);
    }
    else
	{
        return result;
	}
}

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

/**
 * Hook network calls
 **/

%hook __NSCFURLSession

- (id)dataTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler
{
    NSString* host = [request URL].host;
    
	NSLog(@"[mitm] __NSCFURLSession.dataTaskWithRequest %@", host);
    if ([host containsString:@"pgorelease.nianticlabs.com"])
    {
		NSData* body = request.HTTPBody;

		long long timestamp = (long long)([[NSDate date] timeIntervalSince1970] * 1000.0);
		NSString *fileName = [NSString stringWithFormat:@"%lld.req.raw.bin", timestamp];
		NSLog(@"[mitm] Save to file: %@", fileName);

		NSString *fileWithPath = [NSString stringWithFormat:@"%@/%@", mitmDirectory, fileName];

		[body writeToFile:fileWithPath atomically:NO];

        void (^hacked)(NSData *data, NSURLResponse *response, NSError *error) = ^void(NSData *data, NSURLResponse *response, NSError *error)
        {
			NSString *resFileName = [NSString stringWithFormat:@"%lld.res.raw.bin", timestamp];
			NSString *resFileWithPath = [NSString stringWithFormat:@"%@/%@", mitmDirectory, resFileName];
			[data writeToFile:resFileWithPath atomically:NO];
			
            // Invoke the original handler
            completionHandler(data, response, error);
        };
        
        // Call the hacked handler
        return %orig(request, hacked);
	}
    
    return %orig(request, completionHandler);
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

//////////////////////

static struct hostent *(*original_gethostbyname)(const char *host);

struct hostent *new_gethostbyname(const char *host);
struct hostent *new_gethostbyname(const char *host)
{
	hostent *result = original_gethostbyname(host);
	NSLog(@"[mitm] gethostbyname %s -> %@", host, result);
	return result;
}

//////////////////////

static int (*original_getaddrinfo)(const char *hostname, const char *servname, const struct addrinfo *hints, struct addrinfo **reslist);

int new_getaddrinfo(const char *hostname, const char *servname, const struct addrinfo *hints, struct addrinfo **reslist);
int new_getaddrinfo(const char *hostname, const char *servname, const struct addrinfo *hints, struct addrinfo **reslist) {
	NSLog(@"[mitm] getaddrinfo %s - %s", hostname, servname);
	int ret;
	if (false && strncmp(hostname, "sso.pokemon.com", 15) == 0) {
		NSLog(@"[mitm] redirect to local");
		ret = original_getaddrinfo("zero46.mymitm.tk", NULL, NULL, reslist);
	} else {
		ret = original_getaddrinfo(hostname, servname, hints, reslist);
	}
	struct addrinfo *res;
	for (res = *reslist; res; res = res->ai_next) {
		NSLog(@"[mitm] addr %s", res->ai_canonname);
	}
	return ret;
}

//////////////////////

static OSStatus (*original_SSLWrite)(SSLContextRef context, const void *data, size_t dataLength, size_t *processed);

OSStatus new_SSLWrite(SSLContextRef context, const void *data, size_t dataLength, size_t *processed);
OSStatus new_SSLWrite(SSLContextRef context, const void *data, size_t dataLength, size_t *processed){
	NSLog(@"[mitm] SSLWrite");
	OSStatus ret = original_SSLWrite(context, data, dataLength, processed);
	return ret;
}

static OSStatus (*original_SSLSetIOFuncs)(SSLContextRef context, SSLReadFunc readFunc, SSLWriteFunc writeFunc);

OSStatus new_SSLSetIOFuncs(SSLContextRef context, SSLReadFunc readFunc, SSLWriteFunc writeFunc);
OSStatus new_SSLSetIOFuncs(SSLContextRef context, SSLReadFunc readFunc, SSLWriteFunc writeFunc) {
	NSLog(@"[mitm] SSLSetIOFuncs");
	OSStatus ret = original_SSLSetIOFuncs(context, readFunc, writeFunc);
	return ret;
}


typedef CFTypeRef CFHTTPConnectionRef;
static CFHTTPConnectionRef (*orig_CFHTTPConnectionCreate)(CFAllocatorRef alloc, CFStringRef host, SInt32 port, UInt32 connectionType, CFDictionaryRef streamProperties);
CFHTTPConnectionRef new_CFHTTPConnectionCreate(CFAllocatorRef alloc, CFStringRef host, SInt32 port, UInt32 connectionType, CFDictionaryRef streamProperties);
CFHTTPConnectionRef new_CFHTTPConnectionCreate(CFAllocatorRef alloc, CFStringRef host, SInt32 port, UInt32 connectionType, CFDictionaryRef streamProperties) {
	NSLog(@"[mitm] CFHTTPConnectionCreate - %@", host);
	return orig_CFHTTPConnectionCreate(alloc, host, port, connectionType, streamProperties);
}

static CFStringRef (*orig__CFNetworkUserAgentString)(void);
CFStringRef new__CFNetworkUserAgentString(void);
CFStringRef new__CFNetworkUserAgentString(void) {
	CFStringRef useragent = orig__CFNetworkUserAgentString();
	NSLog(@"[mitm] _CFNetworkUserAgentString - %@", useragent);
	return useragent;
}


//////////////////////

static void (*orig_CFStreamCreatePairWithSocketToHost)(CFAllocatorRef alloc, CFStringRef host, UInt32 port, CFReadStreamRef *readStream, CFWriteStreamRef *writeStream);

void new_CFStreamCreatePairWithSocketToHost(CFAllocatorRef alloc, CFStringRef host, UInt32 port, CFReadStreamRef *readStream, CFWriteStreamRef *writeStream);
void new_CFStreamCreatePairWithSocketToHost(CFAllocatorRef alloc, CFStringRef host, UInt32 port, CFReadStreamRef *readStream, CFWriteStreamRef *writeStream) {
    NSLog(@"[mitm] CFStreamCreatePairWithSocketToHost: %s:%d", (char *)host, (unsigned int)port);
    orig_CFStreamCreatePairWithSocketToHost(alloc, host, port, readStream, writeStream);
}

static void (*orig_CFStreamCreatePairWithSocketToCFHost)(CFAllocatorRef alloc, CFHostRef host, SInt32 port, CFReadStreamRef  _Nullable *readStream, CFWriteStreamRef  _Nullable *writeStream);

void new_CFStreamCreatePairWithSocketToCFHost(CFAllocatorRef alloc, CFHostRef host, SInt32 port, CFReadStreamRef  _Nullable *readStream, CFWriteStreamRef  _Nullable *writeStream);
void new_CFStreamCreatePairWithSocketToCFHost(CFAllocatorRef alloc, CFHostRef host, SInt32 port, CFReadStreamRef  _Nullable *readStream, CFWriteStreamRef  _Nullable *writeStream) {
	NSLog(@"[mitm] CFStreamCreatePairWithSocketToCFHost: %@:%d", host, (unsigned int)port);
	orig_CFStreamCreatePairWithSocketToCFHost(alloc, host, port, readStream, writeStream);
}

//////////////////////

static void (*orig_CFHTTPMessageSetBody)(CFHTTPMessageRef message, CFDataRef bodyData);

void new_CFHTTPMessageSetBody(CFHTTPMessageRef message, CFDataRef bodyData);
void new_CFHTTPMessageSetBody(CFHTTPMessageRef message, CFDataRef bodyData) {
	NSLog(@"[mitm] CFHTTPMessageSetBody %@ - %@", message, bodyData);
	orig_CFHTTPMessageSetBody(message, bodyData);
}

//////////////////////

static CFHTTPMessageRef (*orig_CFHTTPMessageCreateRequest)(CFAllocatorRef alloc, CFStringRef requestMethod, CFURLRef url, CFStringRef httpVersion);

CFHTTPMessageRef new_CFHTTPMessageCreateRequest(CFAllocatorRef alloc, CFStringRef requestMethod, CFURLRef url, CFStringRef httpVersion);
CFHTTPMessageRef new_CFHTTPMessageCreateRequest(CFAllocatorRef alloc, CFStringRef requestMethod, CFURLRef url, CFStringRef httpVersion) {
	NSLog(@"[mitm] CFHTTPMessageCreateRequest %@", url);
	return orig_CFHTTPMessageCreateRequest(alloc, requestMethod, url, httpVersion);
}

static CFURLRef (*orig_CFURLCreateWithString)(CFAllocatorRef allocator, CFStringRef URLString, CFURLRef baseURL);
CFURLRef new_CFURLCreateWithString(CFAllocatorRef allocator, CFStringRef URLString, CFURLRef baseURL);
CFURLRef new_CFURLCreateWithString(CFAllocatorRef allocator, CFStringRef URLString, CFURLRef baseURL) {
	NSLog(@"[mitm] CFURLCreateWithString %@ - %@", URLString, baseURL);
	return orig_CFURLCreateWithString(allocator, URLString, baseURL);
}

//////////////////////

void TryToDumpCerts() {
	NSError *error = nil;
	NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
	NSString *appfolder = [[[paths objectAtIndex:0] stringByDeletingLastPathComponent] stringByAppendingPathComponent:@".config"];

	NSLog(@"[mitm] app folder = %@", appfolder);

	NSArray * directoryContents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:appfolder error:&error];
	for (NSString *folder in directoryContents) {
		NSLog(@"[mitm] %@", folder);
	}
}

//////////////////////

%ctor {
	NSLog(@"[mitm] Pokemon Go Tweak Initializing...");

	// various system hook
	rebind_symbols((struct rebinding[]){
		{"SecTrustEvaluate", (void *)new_SecTrustEvaluate, (void **)&original_SecTrustEvaluate},
		{"SecTrustGetExceptionForCertificateAtIndex", (void *)new_SecTrustGetExceptionForCertificateAtIndex, (void **)&orig_SecTrustGetExceptionForCertificateAtIndex},
		{"gethostbyname", (void *)new_gethostbyname, (void **)&original_gethostbyname},
		{"getaddrinfo", (void *)new_getaddrinfo, (void **)&original_getaddrinfo},
		{"SSLWrite", (void *)new_SSLWrite, (void **)&original_SSLWrite},
		{"SSLSetIOFuncs", (void *)new_SSLSetIOFuncs, (void **)&original_SSLSetIOFuncs},
		{"CFStreamCreatePairWithSocketToHost", (void *)new_CFStreamCreatePairWithSocketToHost, (void **)&orig_CFStreamCreatePairWithSocketToHost},
		{"CFStreamCreatePairWithSocketToCFHost", (void *)new_CFStreamCreatePairWithSocketToCFHost, (void **)&orig_CFStreamCreatePairWithSocketToCFHost},
		{"CFHTTPMessageSetBody", (void *)new_CFHTTPMessageSetBody, (void **)&orig_CFHTTPMessageSetBody},
		{"CFHTTPMessageCreateRequest", (void *)new_CFHTTPMessageCreateRequest, (void **)&orig_CFHTTPMessageCreateRequest},
		{"SSLHandshake", (void *)new_SSLHandshake, (void **)&orig_SSLHandshake},
		{"SSLCreateContext", (void *)new_SSLCreateContext, (void **)&orig_SSLCreateContext},
		{"SSLSetSessionOption", (void *)new_SSLSetSessionOption, (void **)&orig_SSLSetSessionOption},
		{"CFHTTPConnectionCreate", (void *)new_CFHTTPConnectionCreate, (void **)orig_CFHTTPConnectionCreate},
		{"_CFNetworkUserAgentString", (void *)new__CFNetworkUserAgentString, (void **)orig__CFNetworkUserAgentString}
	}, 15);

	//

	// TryToDumpCerts();

	// todo: actually handle error :)
	NSError *error = nil;

	NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
	NSString *documents = [paths objectAtIndex:0];

	NSLog(@"[mitm] Clean old directories");
	NSCalendar *cal = [NSCalendar currentCalendar];    
	NSDate *someDaysAgo = [cal dateByAddingUnit:NSCalendarUnitDay 
											value:-3
											toDate:[NSDate date] 
											options:0];

	NSArray * directoryContents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:documents error:&error];
	for (NSString *folder in directoryContents) {
		if ([folder hasPrefix:@"mitm."]) {
			long long timestamp = [[folder substringFromIndex:5] longLongValue];
			NSDate *mitmdate = [NSDate dateWithTimeIntervalSince1970:(long long)(timestamp/1000)];

			if ([mitmdate compare:someDaysAgo] == NSOrderedAscending) {
				NSString *oldFolder = [documents stringByAppendingPathComponent:folder];
				NSLog(@"[mitm] Session too old, deleting %@", oldFolder);
				[[NSFileManager defaultManager] removeItemAtPath:oldFolder error:nil];
			}
		}
	}

	long long timestamp = (long long)([[NSDate date] timeIntervalSince1970] * 1000.0);
	NSString *dirname = [NSString stringWithFormat:@"/mitm.%lld", timestamp];

	NSLog(@"[mitm] Initializing log writer(s) to %@", dirname);
	
	mitmDirectory = [documents stringByAppendingPathComponent:dirname];
	if (![[NSFileManager defaultManager] fileExistsAtPath:mitmDirectory]) {
		[[NSFileManager defaultManager] createDirectoryAtPath:mitmDirectory
			withIntermediateDirectories:NO
			attributes:nil
			error:&error];
	}

	NSLog(@"[mitm] Init OK.");
}