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
    NSURLCredential *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
    completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
}

%end

/*
	Define the new SecTrustEvaluate function
*/
OSStatus new_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result);
OSStatus new_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result)
{
	NSLog(@"[mitm] SecTrustEvaluate");
	*result = kSecTrustResultProceed;
	return errSecSuccess;
}

/*
	Function signature for original SecTrustEvaluate
*/
static OSStatus(*original_SecTrustEvaluate)(SecTrustRef trust, SecTrustResultType *result);

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
    
	NSLog(@"dataTaskWithRequest %@", host);
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
	id origResult = %orig(url, shouldAppend);
	NSLog(@"[mitm] outputStreamWithURL %@", url);
	return origResult;
}


- (id)initWithURL:(NSURL *)url append:(BOOL)shouldAppend {
	id origResult = %orig(url, shouldAppend);
	NSLog(@"[mitm] initWithURL %@", url);
	return origResult;
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
	NSLog(@"[mitm] getaddrinfo %s", hostname);
	int ret = original_getaddrinfo(hostname, servname, hints, reslist);
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

//////////////////////

%ctor {
	NSLog(@"[mitm] Pokemon Go Tweak Initializing...");

	// various system hook
	rebind_symbols((struct rebinding[]){
		{"SecTrustEvaluate", (void *)new_SecTrustEvaluate, (void **)&original_SecTrustEvaluate},
		{"gethostbyname", (void *)new_gethostbyname, (void **)&original_gethostbyname},
		{"getaddrinfo", (void *)new_getaddrinfo, (void **)&original_getaddrinfo},
		{"SSLWrite", (void *)new_SSLWrite, (void **)&original_SSLWrite},
		{"SSLSetIOFuncs", (void *)new_SSLSetIOFuncs, (void **)&original_SSLSetIOFuncs}
	}, 5);

	// todo: actually handle error :)
	NSError *error = nil;

	NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
	NSString *documents = [paths objectAtIndex:0];

	NSLog(@"[mitm] Clean old directories");
	NSCalendar *cal = [NSCalendar currentCalendar];    
	NSDate *sevenDaysAgo = [cal dateByAddingUnit:NSCalendarUnitDay 
											value:-7
											toDate:[NSDate date] 
											options:0];

	NSArray * directoryContents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:documents error:&error];
	for (NSString *folder in directoryContents) {
		if ([folder hasPrefix:@"mitm."]) {
			long long timestamp = [[folder substringFromIndex:5] longLongValue];
			NSDate *mitmdate = [NSDate dateWithTimeIntervalSince1970:(long long)(timestamp/1000)];

			if ([mitmdate compare:sevenDaysAgo] == NSOrderedAscending) {
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