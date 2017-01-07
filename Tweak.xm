#import <QuartzCore/QuartzCore.h>

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

//////////////////////

/**
 * Hook network calls
 **/

%hook __NSCFURLSession

- (id)dataTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler
{
    NSString* host = [request URL].host;
    
    // Validate request
    if ([host containsString:@"pgorelease.nianticlabs.com"])
    {
		NSData* body = request.HTTPBody;		

		NSString *fileName = [NSString stringWithFormat:@"%lu.req.raw.bin", (long)CACurrentMediaTime()];
		NSLog(@"[mitm] Save to file: %@", fileName);

		NSString *fileWithPath = [NSString stringWithFormat:@"%@/%@", mitmDirectory, fileName];

		[body writeToFile:fileWithPath atomically:NO];

        void (^hacked)(NSData *data, NSURLResponse *response, NSError *error) = ^void(NSData *data, NSURLResponse *response, NSError *error)
        {

            // Invoke the original handler
            completionHandler(data, response, error);
        };
        
        // Call the hacked handler
        return %orig(request, hacked);
    }
    
    return %orig(request, completionHandler);
}

%end

%ctor {
	NSLog(@"[mitm] Pokemon Go Tweak Initializing...");

	NSError *error = nil;

	NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
	NSString *documents = [paths objectAtIndex:0];
	NSLog(@"[mitm] Initializing log writer(s) to %@", documents);
	
	mitmDirectory = [documents stringByAppendingPathComponent:@"/mitm/"];
	if (![[NSFileManager defaultManager] fileExistsAtPath:mitmDirectory]) {
		[[NSFileManager defaultManager] createDirectoryAtPath:mitmDirectory
			withIntermediateDirectories:NO
			attributes:nil
			error:&error];
	}

}