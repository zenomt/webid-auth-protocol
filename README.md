WebID HTTP Authorization Protocol
=================================

Introduction
------------
This memo proposes a protocol to obtain HTTP bearer-type authorization tokens
that can establish that the agent requesting a resource is acting directly
on behalf of, and is authorized by, a [WebID][] URI (WebID). The protocol
includes methods for both [WebID-OIDC][] and [WebID-TLS][] authenticated
identities, including a means to authenticate WebID-OIDC identities using
[Self-Issued OpenID Providers][OIDC-SelfIssued].

This protocol is intended to be used by [Solid][] applications, in particular
browser-based applications, but is generally applicable to any HTTP access
scenario where the accessing agent is to be identified as acting on direct
behalf of (and access to be granted or denied) a WebID and optionally the
agent's application identifier.

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**", "**SHALL
NOT**", "**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**", "**NOT RECOMMENDED**",
"**MAY**", and "**OPTIONAL**" in this document are to be interpreted as
described in BCP 14 \[[RFC2119][]\] \[[RFC8174][]\] when, and only when, they
appear in all capitals, as shown here.

The Problems
------------

### WebID-OIDC

When demonstrating control of a WebID with WebID-OIDC, a Relying Party (RP)
obtains an Identity Token (`id_token`) as a direct client of the OIDC Provider
(OP).  This is the *first party* scenario, for example where the user logs
directly in to her POD or to an online application. In this scenario, the
user, when attempting to log in or to access a restricted resource on the RP,
is directed by the RP to select her OP, log in there, and the OP will then
return a signed `id_token` to the RP, which can be verified and the user
considered logged in (for example, by the RP setting a cookie in the user's
browser).

In some cases (and what is expected to eventually be the common case), the
RP will be an in-browser Javascript-based application, and this application
will attempt to access resources on other servers (the user's or other PODs,
other web servers, etc) on behalf of the user. If any of those remote resources
are restricted, today the user must log in directly to the remote server(s)
as RPs with her OP. This can be tedious (or unmanageable) for the user if the
number of servers to be contacted is large (for example, in a "social news
feed" type application that retrieves and collates social media postings from
all of the user's friends). The OP selection step is typically HTML and
Javascript based in a browser page, and doesn't lend itself to use by automatic
or robotic agents.  Furthermore, having a full directly-logged-in status with
the RP (with the status maintained for example in a browser cookie) may not
be desirable, as Cross-Site Request Forgery attacks, among others, may grant
an attacker or even another legitimate application more privilege than is
desirable in this situation.

At this time, browser-based applications can only be identified to resource
servers via the `Origin` HTTP header (except for the special case below).
This may be insufficient when multiple applications are hosted in the same
origin (for example, github.com).

The OP can return an `access_token` to the agent along with the `id_token`.
Only in the special case where the resource server to be accessed by a user
is *also* that user's OP, the `access_token` can identify its bearer to the
OP-plus-resource-server as the local user, and identify the agent to which
it was issued.

### WebID-TLS

Notwithstanding the logistical problem of securely loading a WebID-TLS
certificate into multiple browsers, and the browser user experience problems
of managing certificates, and granting (and especially revoking, changing,
or logging out) the use of a certificate to communicate with a particular
origin server in today's web browsers, TLS itself and commonly deployed web
servers provide no way to conditionally use a client-side certificate for
only some requests to the same origin. Whether to send a client certificate
to the server is determined during the initial TLS handshake (after a target
hostname is sent by the client but before the target path is sent), and is
thereafter fixed for the duration of the TLS connection. While this can be
renegotiated at a later time in TLS 1.2, renegotiation is currently
[not allowed in HTTP/2][http2-norenego], and there is no standard way for an
application web server to indicate to an upstream TLS reverse proxy (such as
[nginx][]) to renegotiate or restart the session (with just that client)
requesting a client certificate.

Commonly deployed web servers (such as nginx) can be configured to request a
client certificate for specific named (virtual) hosts. The client certificate
will be requested on all connections to that host. If this host/origin is the
host for the desired resources, then either a client certificate will be
required to be sent for all requests (even ones that shouldn't require
authorization), or, if the initial certificate request is denied by the user,
there will be no opportunity later to demand the client certificate for only
the restricted resources.

A possible workaround is to use a server at a subdomain configured to require
a client certificate. The user can be directed to follow a link to a page on
this subdomain host, and if the certificate is presented, verified, and
properly linked to a WebID, this page can set a browser cookie in the
superdomain. The user can be redirected back to the original domain, and new
requests will include the cookie. This scenario shares the first-party
cookie-based issues described above for WebID-OIDC first-party logins.

The Protocol
------------
*WebID HTTP Authorization Protocol* comprises the following components:

  - A supplemental behavior for WebID-OIDC OPs to include the `redirect_uri`
    in the `aud`ience of the `id_token` in certain circumstances;

  - Three new parameters to the `WWW-Authenticate` response header for
    the `Bearer` method, and supplemental semantics;

  - An API endpoint for exchanging an OIDC `id_token` for an access token;

  - Supplemental methods for verifying the `id_token`;

  - An API endpoint for obtaining an access token when using WebID-TLS;

  - An operational semantics.

Syntax
------

### Include `redirect_uri` in OIDC `id_token`

In order to enable reasonable discrimination of applications at a finer
granularity than Origin, a WebID-OIDC OP **SHOULD** include in the list of
`aud`iences the `redirect_uri` to which the `id_token` or `code` was sent,
if and only if the `webid` scope (or other scopes whose semantics define this
behavior) was requested by the client.

A client conforming to this protocol **SHOULD** request the `webid` additional
scope from the OP in order to allow third party servers to make access control
decisions at a finer granularity than Origin.

#### Discussion
The `redirect_uri` can be used as an application identifier.  Some RPs might
consider an unrecognized `aud` entry as an untrusted audience and reject the
`id_token`. Therefore the `redirect_uri` will not be included unless the
client has signaled a desire for its presence with an appropriate scope.

This protocol includes a redirect workflow that can prove a `redirect_uri`
directly to the server with the same assurance as from an OIDC `id_token`'s
`aud` claim.  However, using a redirect-based workflow is inconvenient in a
browser-based application, and will often involve methods such as invisible
frames that obfuscate the program's operation (vs direct HTTP transactions),
and add additional round-trip times and delays to the transaction. Additional
delays to application response can worsen the user's experience.

### `WWW-Authenticate` Parameters for `Bearer` Method

A resource server, to challenge an unauthorized request using this protocol,
will employ a combination of the following parameters in a `WWW-Authenticate`
header returned in an HTTP `401` response to a request:

  - `scope`: For challenges according to this protocol, the `scope`
    parameter **SHALL** include at least the `openid` and `webid` scopes;

  - `nonce`: This parameter conveys an opaque challenge string to be used as
    described below;

  - `token_endpoint`: The URI of the WebID-OIDC token exchange endpoint, if
    available;

  - `webid_tls_endpoint`: The URI of the WebID-TLS token endpoint, if available.

### `token_endpoint` API Parameters

In order to avoid leaving a signed `id_token` and other sensitive parameters
in web server logs, the agent **SHOULD** access this API by HTTP `POST` method,
but `GET` **MUST** also be supported by the server. The API takes the following
parameters, either in the request body as Content-Type
`application/x-www-form-urlencoded` format for `POST`, or as URI query
parameters for `GET`:

  - `id_token`: Required: A WebID-OIDC `id_token` as described below;

  - `nonce`: Required: The nonce from the `WWW-Authenticate` challenge;

  - `agent_nonce`: Required: An arbitrary string chosen by the agent, used
    as described below;

  - `uri`: Required: The [absolute URI][], including scheme, authority
    (host and optional port), path, and query, but not including fragment
    identifier, corresponding to the original request that resulted in the
    HTTP `401` response. This parameter **MUST NOT** include a fragment
    identifier;

  - `redirect_uri`: Optional: If present, the response will be made in the
    form of an HTTP `302` redirect to this URI; otherwise the response will
    be made in the response body as a JSON object;

  - `state`: Optional: If present, opaque application state to be echoed
    back in a redirect response. Only useful if a `redirect_uri` is specified.

A successful response **SHALL** comprise the following parameters:

  - `access_token`: An opaque string comprising a `Bearer` access token that
    can be used for requests in the same [protection space][] as the original
    request;

  - `expires_in`: A numeric number of seconds from the `Date` of this response
    at which the `access_token` will no longer be valid;

  - `state`: A string, the `state` from the request, echoed unmodified. Only
    included in the response if the request included a `state`.

Unrecognized parameters **SHOULD** be ignored.

TBD: error response.

If no `redirect_uri` was included, the response body is a JSON object in
Content-Type `application/json` format whose keys are the response parameters.

If a `redirect_uri` was included, the response is an HTTP `302` redirect with
the `Location` being the `redirect_uri`, followed by a fragment indicator
`#`, and the response parameters in `application/x-www-form-urlencoded` form.
Only the fragment form is allowed to avoid the `access_token` accidentally
appearing in web server logs.

Note: If a `redirect_uri` is included in the request, it overrides any redirect
URI that may appear in the `aud` of the `id_token` for the purpose of application
identification and access control decisions.

Note: If a `redirect_uri` is not included in the request and the `id_token`
has no discernable redirect URI in its `aud` list, then the `Origin` from the
original request is the best granularity available for access control decisions.

### `webid_tls_endpoint` API Parameters

The `webid_tls_endpoint` API **MUST** support HTTP `POST` and `GET` methods.
The API takes the following parameters, either in the request body as Content-Type
`application/x-www-form-urlencoded` format for `POST`, or as URI query
parameters for `GET`:

  - `nonce`: Required: The nonce from the `WWW-Authenticate` challenge;

  - `uri`: Required: The [absolute URI][], including scheme, authority
    (host and optional port), path, and query, but not including fragment
    identifier, corresponding to the original request that resulted in the
    HTTP `401` response. This parameter **MUST NOT** include a fragment
    identifier;

  - `redirect_uri`: Optional: If present, the response will be made in the
    form of an HTTP `302` redirect to this URI; otherwise the response will
    be made in the response body as a JSON object.

  - `state`: Optional: If present, opaque application state to be echoed
    back in a redirect response. Only useful if a `redirect_uri` is specified.

A TLS client certificate is **REQUIRED** when communicating with this API
endpoint. That means the API endpoint will probably be at a different origin
from the original URI.

A successful response is made in the same manner as one for the `token_endpoint`.

TBD: error response.

Note: If a `redirect_uri` is not included in the request, then the `Origin`
from the original request is the best granularity available for access control
decisions.

Operation
---------
An agent (for example, an in-browser application working on behalf of a user)
attempts an HTTP request to a resource server for an access-restricted URI
without presenting any special credentials.

	GET /some/restricted/resource HTTP/2
	Host: www.example.com
	Origin: https://other.example.com

The resource server does not allow this request without authorization.  It
generates an unguessable, opaque nonce that the server **SHOULD** be able to
later recognize as having generated. The server responds with an HTTP `401`
Unauthorized message, and includes the [protection space][] (`realm`), this
nonce, the appropriate scopes, and the `token_endpoint` and `webid_tls_endpoint`
URIs as appropriate, in the `WWW-Authenticate` header with the `Bearer` method.
The server **MAY** also include an HTML response body to allow the user to
perform a first-party login using another method, such as by selecting her
OIDC Provider, for cases where the resource was navigated to directly in the
browser.

	HTTP/2 401 Unauthorized
	WWW-Authenticate: Bearer realm="/auth/",
	    scope="openid webid",
	    nonce="j16C4SOLQWFor3VYUtZWnrUr5AG5uwDF7q9RFsDk",
	    token_endpoint="/auth/webid-token",
	    webid_tls_endpoint="https://webid-tls.example.com/auth/webid-tls"
	Access-Control-Allow-Origin: https://other.example.com
	Access-Control-Expose-Headers: WWW-Authenticate
	Date: Tue, 30 Apr 2019 20:22:45 GMT
	Content-type: text/html
	
	<html>Human first-party login page...</html>

The agent recognizes the response as compatible with this protocol by recognizing
the method as `Bearer`, scope `webid`, and the presence of the `nonce` and
either of the `token_endpoint` or `webid_tls_endpoint` parameters.

### WebID-OIDC Operation

The agent determines to use the WebID-OIDC method.

It is assumed that the agent already has a first-person session with the
user's OP, and can request additional `id_token`s through a normal OIDC
authorization workflow.

The agent generates a cryptographically strong `agent_nonce`. `uri` is
the absolute URI for the original request, as detailed in Syntax.

The agent calculates

	proof_nonce = Base64URL ( HMAC-SHA512-256 ( k = nonce, m = agent_nonce + ":" + uri ) )
	
	("peZAlYnd3ESp-KYkkmsllGfpWLcslTMr3dGymDX2rWc" with the example values used)

The agent requests a new `id_token` from the OP, passing `proof_nonce` in to
be the `id_token`'s nonce, and requesting at least scopes `openid` and `webid`.

The OP returns to the agent a new, signed `id_token`, whose `nonce` claim is
the `proof_nonce`. The OP includes the `redirect_uri` in the `aud` claim, if
supported.

The agent sends a request to the `token_endpoint` URI, and includes the new
`id_token`, the `nonce` from the `401` response, the `agent_nonce`, the `uri`
for the original request, and if using the redirect response mode, a
`redirect_uri` and a `state`.

	POST /auth/webid-token HTTP/2
	Host: www.example.com
	Origin: https://other.example.com
	Content-type: application/x-www-form-urlencoded
	
	id_token=ey...
	&nonce=j16C4SOLQWFor3VYUtZWnrUr5AG5uwDF7q9RFsDk
	&agent_nonce=1QSoZJq-laL3pukTmOqfDS5hbngkBM5pGF6cmgNp
	&uri=https://www.example.com/some/restricted/resource

(Line breaks in the request body are for readability and would not be present
in real life)

The server verifies this request:

  1. Verifies the `nonce` (for example, confirming it was really issued by this
     server, not too far in the past, hasn't been redeemed yet, and was issued
     for a request for `uri`);

  2. Verifies that `uri` is an absolute URI for this server and the protection
     space for which this endpoint is responsible;

  3. Parses `id_token`, extracting the WebID, `iss`uer, `aud`ience, and `nonce` as
     the `proof_nonce`;

  4. Verifies `proof_nonce`, as extracted from the `id_token`, has the expected
     value by comparing it to the server's own calculated value (based on the
     `nonce`, `agent_nonce`, and `uri`);

  5. Loads and parses the WebID document to extract the OIDC Issuer (if
     listed) and public keys (if listed) for the WebID;

  6. Verifies the `id_token` signature. If the `id_token` is
     [self issued][OIDC-SelfIssued], the public key **MUST** be listed in the
     WebID.  Otherwise, [OIDC Discovery][], based on the `iss` claim, is used
     to find the public key, and the `iss` **MUST** be the authorized OIDC
     issuer.

  7. Determines the application identifier, which is the `redirect_uri` of
     the request if it was given, or of a likely redirect URI extracted from
     the `aud` claim (for example, "the audience that looks like a URI"), or
     the `Origin` header from the original request (if saved with the `nonce`),
     or the `Origin` header of this request, or Unknown.

If the request is verified, the server issues an `access_token` valid for
this protection space and for a limited time. The `access_token` **SHOULD**
be translatable by a server for this protection space into at least the WebID
and the application identifier.

	HTTP/2 200
	Content-type: application/json; charset=utf-8
	Cache-control: no-cache, no-store
	Access-Control-Allow-Origin: https://other.example.com
	Date: Tue, 30 Apr 2019 20:22:46 GMT
	
	{
		"access_token": "gZDES1DqHf1i3zydSqfnsgGhkMgc4gcbpnCHSCcQ",
		"expires_in": 1800
	}

The agent can now use this `access_token` as a Bearer token in the `Authorization`
header for requests in the same protection space.

	GET /some/restricted/resource HTTP/2
	Host: www.example.com
	Origin: https://other.example.com
	Authorization: Bearer gZDES1DqHf1i3zydSqfnsgGhkMgc4gcbpnCHSCcQ

The server translates the bearer token into a WebID, and application identifier
if available, and can use those data and any others at its disposal to make
a determination whether to grant access to the requested resource.

### WebID-TLS Operation

The agent determines to use the WebID-TLS mode.

The agent sends, using its WebID-TLS client certificate, to the `webid_tls_endpoint`
URI. The origin for this URI will probably be different from the original
request URI, in order for the server to request a client certificate in the
TLS handshake.  It is assumed that the original server that responded with
`401` and this API server are coupled such that this API server is able to
verify the `nonce` and return a bearer token that is meaningful in the original
server's protection space.

	POST /auth/webid-tls HTTP/2
	Host: webid-tls.example.com
	Origin: https://other.example.com
	Content-type: application/x-www-form-urlencoded
	
	nonce=j16C4SOLQWFor3VYUtZWnrUr5AG5uwDF7q9RFsDk
	&uri=https://www.example.com/some/restricted/resource
	&redirect_uri=https://other.example.com/app/getbearer
	&state=EehJc1e8dDGz2iazKHy-1VJyWgMmnovRsbeEuqfZ

The server verifies the request:

  1. Verifies the `nonce` (for example, confirming that it was really issued
     by the original server, not too far in the past, and hasn't been redeemed
     yet);

  2. Verifies that `uri` is an absolute URI and is in the protection space
     for which this endpoint is responsible, and if possible that `uri`
     corresponds with the `nonce`;

  3. Verifies, [in the normal way][WebID-TLS], the WebID by extracting
     the public key from the client certificate used in the TLS connection,
     loading the WebID document according to the SubjectAlternativeName field,
     and looking for a matching public key in the WebID;

  4. Determines the application identifier, which is the `redirect_uri` of
     the request if it was given, or the `Origin` header from the original
     request (if recorded with the `nonce`), or the `Origin` header of this
     request if it is not the origin of the original request URI, or Unknown.

If the request is verified, the server issues an `access_token` valid for the
original server's protection space and for a limited time. The `access_token`
**SHOULD** be translatable by any server for the orginal protection space
into at least the WebID and the application identifier.

	HTTP/2 302
	Location: https://other.example.com/app/getbearer#access_token=gZDES1DqHf1i3zydSqfnsgGhkMgc4gcbpnCHSCcQ&expires_in=1800&state=EehJc1e8dDGz2iazKHy-1VJyWgMmnovRsbeEuqfZ
	Date: Tue, 30 Apr 2019 20:22:46 GMT

The agent can now use this `access_token` as a Bearer token in the `Authorization`
header for requests in the same protection space at the original request URI's
origin.

	GET /some/restricted/resource HTTP/2
	Host: www.example.com
	Origin: https://other.example.com
	Authorization: Bearer gZDES1DqHf1i3zydSqfnsgGhkMgc4gcbpnCHSCcQ

Security Considerations
-----------------------
Having a bearer token issued from this protocol doesn't guarantee access to
the requested resource. Access control facilities in the resource server can
use the identity associated with the bearer token and other considerations
to determine access rights.

### Redirect Workflow Considerations

Care **SHOULD** be taken so that the `Location` header in response to the
above API endpoints is not exposed to browser scripts in redirect-type
responses. The redirect-type response flow in a browser application is intended
to only allow a browser application to obtain the returned parameters if the
redirect was actually followed, indicating the `redirect_uri` is part of the
application. If the `Location` header can be read directly by the browser
script from an `XMLHTTPRequest` or `Fetch` response, any browser application can
impersonate any other browser application to the above API endpoints.

The `redirect_uri` (either as part of this API flow or extracted from an
`id_token`) is not truly secure, but is only a strong indicator that the
`redirect_uri` was used in a browser-based application. Non-browser applications
(such as native applications, servers, robots, or any other agent) are not
subject to the [Same-Origin policy][same-origin] or
[Cross-Origin Resource Sharing (CORS)][CORS] restrictions, and have full
access to all request and response headers of all HTTP transactions (including
ones to OIDC Providers), and therefore can impersonate any `redirect_uri`
(and therefore any application identifier) whether it is associated with the
application or not.

The presence and use of a `redirect_uri` with the above APIs (either directly
or in an `id_token`) indicates only that the authenticated WebID asserts that
the URI identifies an application she has consented to use. It does not
guarantee that any particular URI was actually followed. The WebID making
this assertion is the only party that should assign a trustability to any
`redirect_uri`.  This distinction **SHOULD** be considered when making access
control decisions.

### Nonce Considerations

Nonces issued by servers in the `WWW-Authenticate` response header **SHOULD**
have the following properties:

  - Be cryptographically strong, of sufficient length, and unguessable;

  - Be recognizable when returned as having been issued for this protection
    space (for example, by recording in a database, or including a cryptographic
    signature);

  - Be valid for a limited (short) time;

  - Be redeemable at most once;

  - Be coupled to the original request URI in a recognizable way;

  - Record the `Origin` header from the original request.

### Discussion of `proof_nonce` Construction for WebID-OIDC `token_endpoint` Workflow

The construction of the `proof_nonce`, combining a value chosen by the resource
server (`nonce`), a value chosen by the agent (`agent_nonce`), and the original
full request URI, serves to thwart Man-In-The-Middle (MITM) attacks.

Consider a server "Real" with a desirable, but restricted, resource; and a
server "Rogue" that wants to access the resource on Real. Consider a user
"User" who has permission to access the resource at Real, and who might come
to access Rogue for some reason (clickbait, or perhaps Rogue provides some
seemingly useful service as well).

Rogue could attempt to access the resource, and be challenged with a `nonce`.
Rogue could then challenge User for some resource and use the same nonce
value.  If User merely had her OP sign a new `id_token` with that nonce and
presented it to Rogue, Rogue could pass that token on to Real, impersonating
User to access the resource.

The original full request URI, especially including the host name, is
incorporated into the `proof_nonce` to couple the signed `id_token` to the
original URI, and to allow Real to verify that the original request URI belongs
to it and not to a MITM.

The `agent_nonce` is incorporated into the `proof_nonce` to guard against
Rogue crafting either its own nonce or a URI for User to access that could
potentially cause the same inputs to the hash function or a hash collision.

### Man-In-The-Middle With WebID-TLS

Rogue could attempt to access a restricted resource on Real and obtain a
`nonce` and `webid_tls_endpoint` URI. Rogue could then challenge User's access
request for a Rogue resource with the same `nonce` *and* the same
`webid_tls_endpoint` from Real.

User would contact Real's `webid_tls_endpoint` and obtain an `access_token`.
If the call to Real didn't include the original request URI, and instead
relied only on the `nonce` (or metadata associated with it), User could give
this token to Rogue which would then be able to use it to access Real.

To ensure Real and User are talking about the same resource, the `webid_tls_endpoint`
request includes the `uri` just like the `token_endpoint` flow.

### Man-In-The-Middle With HTTP Redirects

User **SHOULD** take care to contain disclosure of the `access_token` to the
protection space for which it was issued.  The HTTP `WWW-Authenticate` `realm`
parameter doesn't describe the extent of the protection space at the origin
in a standard way.  Therefore, the extent of the protection space might not
be known ahead of time, so at the very least, User **MUST NOT** disclose the
`access_token` beyond the origin of the `uri` parameter used to obtain it.

Rogue could use an HTTP `3XX` response to redirect User to access a protected
resource at Real. Depending on the APIs Real's agent uses, the redirect might
be followed automatically or the `Location` might be exposed to the agent to
be followed under manual control.

If the redirect is followed automatically, `uri` will be for Rogue, and Real
will reject the token request.

If the redirect is followed manually by User, `uri` will be for Real, and
User will receive an `access_token`. In this case, User knows the protection
space is for Real and not Rogue (assuming they have different origins, see
below). User **MUST** notice that Real's protection space is different than
Rogue's, and **MUST NOT** send the token to Rogue for future requests.

If Real and Rogue have the same origin, Rogue can obtain an `access_token`
for Real as User, as detailed above. However, if Real and Rogue have the same
origin, [you are having a bad problem][same-origin] and
[you will not go to space today][up goer five].


  [CORS]:             https://www.w3.org/TR/cors/
  [OIDC Discovery]:   https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
  [OIDC-SelfIssued]:  https://openid.net/specs/openid-connect-core-1_0.html#SelfIssued
  [RFC2119]:          https://tools.ietf.org/html/rfc2119
  [RFC8174]:          https://tools.ietf.org/html/rfc8174
  [Solid]:            https://github.com/solid
  [WebID-OIDC]:       https://github.com/solid/webid-oidc-spec
  [WebID-TLS]:        https://github.com/solid/solid-spec/blob/master/authn-webid-tls.md
  [WebID]:            https://www.w3.org/2005/Incubator/webid/spec/identity/
  [absolute URI]:     https://tools.ietf.org/html/rfc3986#section-4.3
  [http2-norenego]:   https://tools.ietf.org/html/rfc7540#section-9.2.1
  [nginx]:            https://nginx.org/
  [protection space]: https://tools.ietf.org/html/rfc7235#section-2.2
  [same-origin]:      https://tools.ietf.org/html/rfc6454#section-3
  [up goer five]:     https://xkcd.com/1133/
