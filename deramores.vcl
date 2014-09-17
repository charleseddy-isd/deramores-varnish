include "backends/default.backend";

include "acls/trusted.acl";

include "subs/clean-ga-querystring.sub";
include "subs/x-forwarded-ip.sub";
include "subs/clean-req-url.sub";
include "subs/normalize-gzip.sub";
include "subs/purge-request.sub";
include "subs/rfc-request.sub";
include "subs/deny-trace.sub";
include "subs/whitelist-cookies.sub";

sub vcl_recv {
  call deny_trace;

  call x_forwarded_for;
  call clean_ga_querystring;
  call clean_req_url;


  if (req.http.SSL_OFFLOADED) {
    set req.http.connection = "close";
    return(pipe);
  }

  call purge_request;

  call rfc_request;

  # Cache only GET or HEAD requests. This makes sure POST requests are always passed.
  if (req.request != "GET" && req.request != "HEAD") {
    /* We only deal with GET and HEAD by default */
    return (pass);
  }

  # don't cache product images - too many, too big and should only be accessed once by CDN
  if (req.url ~ "^/media/catalog/product/") {
    return (pass);
  }

  call normalize_gzip;

  # Rules for static files
  if (req.url ~ "\.(jpeg|jpg|png|gif|ico|swf|js|css|gz|rar|txt|bzip|pdf)(\?.*|)$") {
    set req.http.staticmarker = "1";
    unset req.http.Cookie;

    return (lookup);
  }

  # Don't cache pages for Magento Admin
  # FIXME: change this rule if you use custom url in admin
  if (req.url ~ "^/(index.php/)?(drladmin|admin|wp)") {
    set req.http.connection = "close";
    return(pipe);
  }

  # Don't cache checkout/customer pages, product compare
  if (req.url ~ "^/(index.php/)?(checkout|customer|catalog/product_compare|wishlist|downloadsignup|api)") {
    return(pass);
  }

  # Unique identifier which tells Varnish to use cache or not
  if (req.http.cookie ~ "(nocache_stable|nocache|NEWMESSAGE)") {
    return (pass);
  }

  call whitelist_cookies;

  set req.http.magicmarker = "1"; # Instruct varnish to remove cache headers received from backend
  return(lookup);
}

sub vcl_pipe {
#     # Note that only the first request to the backend will have
#     # X-Forwarded-For set.  If you use X-Forwarded-For and want to
#     # have it set for all requests, make sure to have:
#     # set req.http.connection = "close";
#     # here.  It is not set by default as it might break some broken web
#     # applications, like IIS with NTLM authentication.
  set req.http.connection = "close";
  return (pipe);
}

sub vcl_hash {
  hash_data(req.url);
  if (req.http.host) {
    hash_data(req.http.host);
  } else {
    hash_data(server.ip);
  }
  if (req.http.cookie ~ "store=") {
    set req.http.X-Store = regsub(req.http.cookie, ".*store=([^;]+);.*", "\1");
    hash_data(req.http.X-Store);
    remove req.http.X-Store;
  }
  return (hash);
}

# Called after a cache lookup if the req. document was found in the cache.
sub vcl_hit {
  if (req.request == "PURGE") {
    ban_url(req.url);
    error 200 "Purged";
  }

  if (!(obj.ttl > 0s)) {
    return (pass);
  }
  return (deliver);
}

# Called after a cache lookup and odc was not found in cache.
sub vcl_miss {
  if (req.request == "PURGE"){
    error 200 "Not in cache";
  }
  return (fetch);
}


# Called after document was retreived from backend
# @var req      Request object.
# @var beresp   Backend response (contains HTTP headers from backend)
sub vcl_fetch {
  set req.grace = 30s;

  unset beresp.http.X-Page-Speed;
  unset beresp.http.X-Mod-Pagespeed;

  # Current response should not be cached
  if(beresp.http.Set-Cookie ~ "nocache=1") {
      return (deliver);
  }

  # Flag set when we want to delete cache headers received from backend
  if (req.http.magicmarker){
    unset beresp.http.magicmarker;
    unset beresp.http.Cache-Control;
    unset beresp.http.Expires;
    unset beresp.http.Pragma;
    unset beresp.http.Cache;
    unset beresp.http.Server;
    unset beresp.http.Set-Cookie;
    unset beresp.http.Age;

    # default ttl for pages
    set beresp.ttl = 1d;
  }
  if (req.http.staticmarker) {
    set beresp.ttl = 30d; # static file cache expires in 30 days
    unset beresp.http.staticmarker;
    unset beresp.http.ETag; # Removes Etag in case we have multiple frontends
  }

  return (deliver);
}

# Called after a cached document is delivered to the client.

sub vcl_deliver {
  if (obj.hits > 0) {
    set resp.http.X-Cache = "HIT ("+obj.hits+")";
  } else {
    set resp.http.X-Cache = "MISS";
    #  set resp.http.X-Cache-Hash = obj.http.hash;
  }
  return (deliver);
}
