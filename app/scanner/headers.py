SEC_HEADER_ADVICE = {
"Strict-Transport-Security": "Enable HSTS with a long max-age and includeSubDomains; consider preload.",
"Content-Security-Policy": "Set a restrictive CSP to mitigate XSS; avoid 'unsafe-inline' if possible.",
"X-Frame-Options": "Use 'DENY' or 'SAMEORIGIN' to mitigate clickjacking.",
"X-Content-Type-Options": "Use 'nosniff' to prevent MIME sniffing.",
"Referrer-Policy": "e.g., 'no-referrer' or 'strict-origin-when-cross-origin'.",
"Permissions-Policy": "Disallow unused powerful features (camera, geolocation, etc.).",
}


COMMON_TECH_HINTS = [
("x-powered-by", "X-Powered-By"),
("server", "Server"),
]


CDN_WAF_HINTS = [
("cf-ray", "Cloudflare"),
("cf-cache-status", "Cloudflare"),
("server", "cloudflare"),
("x-amz-cf-id", "AWS CloudFront"),
("via", "cloudfront"),
("akamai-", "Akamai"),
("x-akamai-", "Akamai"),
("fastly-", "Fastly"),
]


CLOUD_HINTS = [
("x-amz-", "AWS"),
("azure-", "Azure"),
("x-ms-", "Azure"),
("gcp", "GCP"),
]


FRAMEWORK_SIGNS = [
("react", ["data-reactroot", "__NEXT_DATA__", "wp-react" ]),
("vue", ["data-v-app", "__VUE_DEVTOOLS_GLOBAL_HOOK__"]),
("angular", ["ng-version", "ng-app"]),
("jquery", ["jquery" ]),
]


COOKIE_KEYS = ["Secure", "HttpOnly", "SameSite"]
