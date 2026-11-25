# HTTP Fingerprinting Checklist

Use this checklist after collecting Caido traffic. It distills the YesWeHack article "Recon series #3: HTTP fingerprinting" and adapts it to API traffic captured in Caido.

Source: https://www.yeswehack.com/learn-bug-bounty/recon-series-http-fingerprinting

## Technique Coverage Matrix

Every fingerprinting report must explicitly cover these techniques from the article:

| Technique | Passive Caido evidence | Active/passive follow-up |
| --- | --- | --- |
| API host discovery | `api_host_candidates`, `host_fingerprints`, API-like hostname labels, API path/content-type/method scores | Expand/narrow HTTPQL across related subdomains |
| HTTP response header analysis | `Server`, `X-Powered-By`, `X-Powered-CMS`, `Via`, `X-*`, CDN/WAF/API gateway headers | Baseline `GET /` only if the initial prompt authorized active testing |
| Banner grabbing and reverse proxy identification | Explicit server/proxy/CDN/WAF headers and status lines in captured responses | Baseline `GET /` only if the initial prompt authorized active testing |
| Inferring server/proxy from header order | `response.header_order` and `aggregate.header_order_guesses` | Compare multiple responses; never treat alone as proof |
| Default error pages | Captured 403/404/405/500/etc. bodies and `aggregate.default_error_signatures` | One random 404 only if the initial prompt authorized active testing |
| Malformed HTTP requests | Captured unusual methods/versions in `request.malformed_request_signal` | Invalid HTTP version and `XGET` probes only if the initial prompt authorized active testing |
| Default files and directory structures | `aggregate.path_and_file_signals`, file extensions, framework directories, API docs paths | HEAD/GET default files only if the initial prompt authorized active testing |
| Cookie parameter analysis | `cookie_names`, `set_cookie_names`, `aggregate.cookie_technologies` | Baseline request only if the initial prompt authorized active testing |
| Passive third-party services | Out of scope for this skill | Do not use Wappalyzer, Shodan, WhatWeb, Nmap, browser/search, or external corroboration |

## Evidence Classes

### Response Header Analysis

Look for direct technology disclosure in:

- `Server`
- `X-Powered-By`
- `X-Powered-CMS`
- `Via`
- Custom technology headers such as `X-Drupal-Cache`, `X-Shopify-Stage`, `X-Varnish`, `X-Amz-Cf-Id`, `CF-Ray`, `X-Cache`
- API gateway/proxy headers such as `X-Amzn-RequestId`, `X-Amz-Apigw-Id`, `X-Envoy-Upstream-Service-Time`, `X-Kong-*`, `X-Served-By`, `CF-Cache-Status`

Treat exact product/version banners as high confidence. Treat generic values such as `nginx`, `Apache`, `cloudflare`, or `awselb` as infrastructure indicators, not proof of the application framework.

### Banner and Reverse Proxy Clues

Banner values can identify web servers, reverse proxies, CDNs, WAFs, and sometimes versions. Record both explicit values and absence of values. A missing `Server` header is still useful when other proxy/CDN headers remain.

### Header Order

Header order is weak evidence but can support other clues. Apache often emits `Date`, then `Server`, then content metadata. Nginx commonly emits `Date`, `Content-Type`, then `Server`. Treat this as low confidence because configuration, versions, and intermediaries can reorder headers.

### Default Error Pages

Captured 404, 403, 500, 405, or framework error responses may reveal default templates. Check response bodies for distinctive title text, HTML structure, comments, stack traces, or JSON error shapes. Common default-page families include Apache, Nginx, IIS, Tomcat, Spring Boot, framework debug pages, API gateway errors, CDN blocks, and WAF denials.

### Malformed HTTP Requests

Malformed requests can trigger banners or default errors, but do not send them unless the initial prompt explicitly authorizes active testing. Examples include invalid HTTP versions or methods. If authorized in the initial prompt, keep probes minimal and in scope.

### Default Files and Directory Structures

In captured traffic, look for requests or responses involving:

- `/favicon.ico`
- `/package.json`
- `/README.txt`, `/readme.txt`
- `/CHANGELOG.txt`, `/changelog.txt`
- `/LICENSE.txt`, `/license.txt`
- Framework-specific directories, API docs, OpenAPI/Swagger files, GraphQL endpoints, versioned paths like `/v1/`

These can confirm versions or frameworks when present. Do not actively request these paths unless active testing was authorized in the initial prompt.

### Cookie Parameters

Cookie names often reveal frameworks or languages:

- `PHPSESSID`: PHP
- `JSESSIONID`: Java/Jakarta servlet stacks
- `ASP.NET_SessionId`: ASP.NET
- `CFTOKEN` / `CFID`: Adobe ColdFusion

Also note framework-specific cookies, load balancer cookies, WAF cookies, and session attributes such as `Secure`, `HttpOnly`, and `SameSite`.

### Passive Corroboration

The article mentions Wappalyzer, Shodan, WhatWeb, and Nmap, but external corroboration is out of scope for this skill. Do not browse, query third-party services, or run external recon tools. Mark this technique as out of scope and rely only on Caido-captured traffic.

## Defensive/Negative Signals

The article's defence section is useful during reporting. Note when version banners are suppressed, default pages are customized, WAF/CDN headers appear to rewrite responses, or sensitive default files are absent/blocked. These are not vulnerabilities by themselves, but they explain why confidence may be lower and what corroborating evidence is needed.

## API-Specific Signals

- Hostname patterns: `api.<domain>`, `*-api.<domain>`, `graphql.<domain>`, `gateway.<domain>`, mobile/app/owner/service subdomains.
- Content types: `application/json`, `application/problem+json`, GraphQL, gRPC/protobuf, XML/SOAP.
- Error schemas: RFC 7807 problem details, Spring Boot `timestamp/status/error/path`, Rails/Django/Express debug styles, API gateway JSON errors.
- Auth headers and challenges: `WWW-Authenticate`, OAuth/OIDC endpoints, JWT-bearing flows, vendor API gateway headers.
- CORS headers: origin reflection, allowed methods/headers, exposed headers.
- Versioned paths and routing conventions: `/api/v1`, `/graphql`, `/rest`, `/rpc`, `/oauth`, `/auth`, `/session`.

## Confidence

- High: explicit product/version header, cookie name with strong framework association, default page with unique wording, response body with framework-specific error shape.
- Medium: repeated custom headers, repeated gateway/CDN headers, consistent API path conventions plus matching content types.
- Low: header order, one-off generic headers, single ambiguous body phrase, technology inferred only from URL naming.
