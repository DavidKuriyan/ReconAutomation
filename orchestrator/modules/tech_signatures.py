"""
Technology Signatures Database
Contains regex patterns and rules for identifying web technologies without external APIs.
Supports: headers, meta tags, HTML content, script sources, cookies, css/js paths.
"""

import re

# compiled regex for efficiency
def c(pattern):
    return re.compile(pattern, re.IGNORECASE)

TECHNOLOGIES = {
    # =========================================================================
    # Content Management Systems (CMS)
    # =========================================================================
    "WordPress": {
        "headers": {"X-Powered-By": c(r"WordPress")},
        "meta": {"generator": c(r"WordPress")},
        "html": [c(r"wp-content/"), c(r"wp-includes/"), c(r"wp-json/")],
        "script": [c(r"wp-emoji-release\.min\.js"), c(r"wp-embed\.min\.js")],
        "cookies": {"wordpress_test_cookie": c(r".*"), "wp-settings-": c(r".*")},
        "version_headers": {"X-Powered-By": r"WordPress\s*(\d+\.\d+(?:\.\d+)?)"}
    },
    "Joomla": {
        "headers": {"X-Content-Encoded-By": c(r"Joomla")},
        "meta": {"generator": c(r"Joomla")},
        "html": [c(r"content=\"Joomla!")],
        "cookies": {"joomla_user_state": c(r".*")}
    },
    "Drupal": {
        "headers": {"X-Generator": c(r"Drupal"), "X-Drupal-Cache": c(r".*")},
        "meta": {"generator": c(r"Drupal")},
        "html": [c(r"Drupal\.settings"), c(r"sites/all/themes"), c(r"sites/default/files")],
        "script": [c(r"drupal\.js")],
        "cookies": {"has_js": c(r"1")}
    },
    "Magento": {
        "headers": {"X-Magento-Tags": c(r".*")},
        "html": [c(r"Mage\.Cookies"), c(r"static/_requirejs")],
        "script": [c(r"mage/cookies\.js")],
        "cookies": {"frontend": c(r".*"), "adminhtml": c(r".*")}
    },
    "Shopify": {
        "html": [c(r"cdn\.shopify\.com"), c(r"Shopify\.theme"), c(r"myshopify\.com")],
        "script": [c(r"shopify-")],
        "headers": {"X-Shopify-Stage": c(r".*"), "X-Shopify-Shop-Api-Call-Limit": c(r".*")}
    },
    "Wix": {
        "headers": {"X-Wix-Request-Id": c(r".*")},
        "meta": {"generator": c(r"Wix\.com")},
        "html": [c(r"wix-warmup-data"), c(r"Wix\.com\ Site")],
        "script": [c(r"static\.parastorage\.com")]
    },
    "Squarespace": {
        "meta": {"generator": c(r"Squarespace")},
        "html": [c(r"squarespace\.com"), c(r"static1\.squarespace")],
        "script": [c(r"assets\.squarespace\.com")]
    },
    "TYPO3": {
        "headers": {"X-TYPO3-Parsetime": c(r".*")},
        "meta": {"generator": c(r"TYPO3")},
        "html": [c(r"typo3conf")],
        "cookies": {"fe_typo_user": c(r".*")}
    },

    # =========================================================================
    # Web Servers
    # =========================================================================
    "Nginx": {
        "headers": {"Server": c(r"nginx")},
        "version_headers": {"Server": r"nginx/(\d+\.\d+(?:\.\d+)?)"}
    },
    "Apache": {
        "headers": {"Server": c(r"Apache")},
        "version_headers": {"Server": r"Apache(?:/(\d+\.\d+(?:\.\d+)?))?"}
    },
    "Apache Tomcat": {
        "headers": {"Server": c(r"Tomcat|Apache-Coyote")},
        "version_headers": {"Server": r"Tomcat\s*(\d+\.\d+(?:\.\d+)?)|Apache-Coyote/(\d+\.\d+)"}
    },
    "IIS": {
        "headers": {"Server": c(r"IIS"), "X-Powered-By": c(r"ASP\.NET")},
        "html": [c(r"Microsoft-IIS")],
        "version_headers": {"Server": r"IIS\s*(\d+\.\d+)"}
    },
    "LiteSpeed": {
        "headers": {"Server": c(r"LiteSpeed")},
        "version_headers": {"Server": r"LiteSpeed\s*(\d+\.\d+)"}
    },
    "Caddy": {
        "headers": {"Server": c(r"Caddy")},
        "version_headers": {"Server": r"Caddy/(\d+\.\d+(?:\.\d+)?)"}
    },
    "Traefik": {
        "headers": {"Server": c(r"traefik")}
    },

    # =========================================================================
    # CDN / Reverse Proxy / Edge
    # =========================================================================
    "Cloudflare": {
        "headers": {"Server": c(r"cloudflare"), "CF-RAY": c(r".*")},
        "cookies": {"__cfduid": c(r".*"), "__cf_bm": c(r".*"), "cf_clearance": c(r".*")},
        "html": [c(r"cloudflare"), c(r"__cf_chl_")]
    },
    "Amazon CloudFront": {
        "headers": {"X-Amz-Cf-Id": c(r".*"), "X-Amz-Cf-Pop": c(r".*")},
        "version_headers": {"Server": r"CloudFront"}
    },
    "Amazon AWS": {
        "headers": {"X-Amz-Request-Id": c(r".*"), "X-Amz-Id-2": c(r".*")},
        "html": [c(r"awsglobalaccelerator\.com")]
    },
    "AWS Elastic Load Balancer": {
        "headers": {"X-Request-Id": c(r".*"), "X-Backend-Response": c(r".*")},
        "cookies": {"AWSELB": c(r".*"), "AWSALB": c(r".*")}
    },
    "Fastly": {
        "headers": {"X-Served-By": c(r".*\.fastly\.net"), "X-Cache-Hits": c(r".*"), "Fastly-Debug-Digest": c(r".*")},
        "html": [c(r"fastly\.net")]
    },
    "Akamai": {
        "headers": {"X-Akamai-Transformed": c(r".*"), "X-Akamai-Request-ID": c(r".*")},
        "html": [c(r"akamaihd\.net"), c(r"akamaized\.net")]
    },
    "Varnish": {
        "headers": {"X-Varnish": c(r".*"), "Via": c(r".*varnish"), "X-Cache": c(r".*"), "Age": c(r"\d+")},
        "version_headers": {"Via": r"varnish\s*\(varnish/(\d+\.\d+)"}
    },
    "HAProxy": {
        "headers": {"X-Haproxy-Server-State": c(r".*")}
    },
    "Sucuri": {
        "headers": {"X-Sucuri-ID": c(r".*"), "X-Sucuri-Cache": c(r".*")}
    },

    # =========================================================================
    # Web Application Firewalls (WAF)
    # =========================================================================
    "ModSecurity": {
        "headers": {"X- ModSecurity": c(r".*"), "X-ASLR": c(r".*")},
        "cookies": {"mod_security": c(r".*")}
    },
    "AWS WAF": {
        "headers": {"x-amzn-RequestId": c(r".*"), "x-amzn-ErrorType": c(r".*")}
    },
    "Cloudflare WAF": {
        "headers": {"CF-Chl-Bypass": c(r".*"), "CF-Chl-Client-Ip": c(r".*")}
    },
    "Barracuda WAF": {
        "cookies": {"barra_counter_session": c(r".*")}
    },

    # =========================================================================
    # Programming Languages / Backend Frameworks
    # =========================================================================
    "PHP": {
        "headers": {"X-Powered-By": c(r"PHP")},
        "cookies": {"PHPSESSID": c(r".*")},
        "version_headers": {"X-Powered-By": r"PHP/(\d+\.\d+(?:\.\d+)?)"}
    },
    "ASP.NET": {
        "headers": {"X-Powered-By": c(r"ASP\.NET"), "X-AspNet-Version": c(r".*"), "X-AspNetMvc-Version": c(r".*")},
        "cookies": {"ASP.NET_SessionId": c(r".*"), ".ASPXAUTH": c(r".*")},
        "version_headers": {"X-AspNet-Version": r"(\d+\.\d+\.\d+)"}
    },
    "Java": {
        "cookies": {"JSESSIONID": c(r".*")},
        "headers": {"X-Powered-By": c(r"Java|Servlet|JSP")}
    },
    "Spring Boot": {
        "headers": {"X-Application-Context": c(r".*")},
        "cookies": {"SPRING_SECURITY_REMEMBER_ME": c(r".*")}
    },
    "Ruby on Rails": {
        "headers": {"X-Powered-By": c(r"Phusion Passenger"), "X-Runtime": c(r".*")},
        "html": [c(r"csrf-token"), c(r"csrf-param")],
        "cookies": {"_session_id": c(r".*"), "_rails_session": c(r".*")}
    },
    "Laravel": {
        "headers": {"Set-Cookie": c(r"laravel_session")},
        "cookies": {"laravel_session": c(r".*"), "XSRF-TOKEN": c(r".*")}
    },
    "Django": {
        "html": [c(r"csrfmiddlewaretoken")],
        "cookies": {"csrftoken": c(r".*"), "sessionid": c(r".*")}
    },
    "Flask": {
        "headers": {"Server": c(r"Werkzeug")},
        "cookies": {"session": c(r".*")}
    },
    "Express": {
        "headers": {"X-Powered-By": c(r"Express")},
        "version_headers": {"X-Powered-By": r"Express\s*(\d+\.\d+(?:\.\d+)?)"}
    },
    "Next.js": {
        "headers": {"X-Powered-By": c(r"Next\.js")},
        "html": [c(r"__NEXT_DATA__"), c(r"__NEXT_LOADED_PAGES__")],
        "script": [c(r"_next/static")]
    },
    "Nuxt.js": {
        "html": [c(r"__NUXT__"), c(r"data-n-head")],
        "script": [c(r"_nuxt/")]
    },
    "Gatsby": {
        "html": [c(r"___gatsby"), c(r"data-gatsby")],
        "script": [c(r"webpack-runtime")]
    },
    "Symfony": {
        "headers": {"X-Symfony-Profiler": c(r".*")},
        "cookies": {"SYMFONY_": c(r".*")}
    },
    "CakePHP": {
        "cookies": {"CAKEPHP": c(r".*")},
        "headers": {"X-CakePHP": c(r".*")}
    },
    "CodeIgniter": {
        "cookies": {"ci_session": c(r".*")},
        "headers": {"X-CI-Session": c(r".*")}
    },

    # =========================================================================
    # JavaScript Frameworks / UI Libraries
    # =========================================================================
    "React": {
        "html": [c(r"data-reactid"), c(r"react-root"), c(r"__reactFiber"), c(r"__reactInternalInstance")],
        "script": [c(r"react\.production\.min\.js"), c(r"react-dom"), c(r"react\.development\.js")]
    },
    "Vue.js": {
        "html": [c(r"data-v-"), c(r"vue-app"), c(r"__vue__")],
        "script": [c(r"vue\.min\.js"), c(r"vue\.js"), c(r"vue\.global\.js")]
    },
    "Angular": {
        "html": [c(r"ng-app"), c(r"ng-controller"), c(r"ng-version"), c(r"_nghost-")],
        "script": [c(r"angular\.js"), c(r"angular\.min\.js"), c(r"main\.\w+\.js")]
    },
    "jQuery": {
        "script": [c(r"jquery.*\.js")]
    },
    "Bootstrap": {
        "html": [c(r"bootstrap\.min\.css"), c(r"bootstrap\.css"), c(r"bootstrap\.min\.js")],
        "script": [c(r"bootstrap\.min\.js"), c(r"bootstrap\.js")]
    },
    "Tailwind CSS": {
        "html": [c(r"tailwindcss"), c(r"class=\".*\btailwind\b")],
        "meta": {"generator": c(r"Tailwind")},
        "script": [c(r"tailwind\.css"), c(r"tailwind\.min\.js")]
    },
    "Foundation": {
        "html": [c(r"foundation\.min\.css"), c(r"foundation\.css")],
        "script": [c(r"foundation\.min\.js"), c(r"foundation\.js")]
    },
    "Material UI": {
        "html": [c(r"Mui"), c(r"MuiButton"), c(r"MuiPaper")],
        "script": [c(r"@material-ui"), c(r"@mui/material")]
    },
    "Svelte": {
        "html": [c(r"svelte-\d+"), c(r"__svelte")],
        "script": [c(r"svelte\.min\.js")]
    },
    "Alpine.js": {
        "html": [c(r"x-data"), c(r"x-init"), c(r"x-show"), c(r"x-bind"), c(r"x-on:")],
        "script": [c(r"alpine\.min\.js"), c(r"alpine\.js")]
    },
    "htmx": {
        "html": [c(r"hx-get"), c(r"hx-post"), c(r"hx-trigger"), c(r"hx-target")],
        "script": [c(r"htmx\.min\.js"), c(r"htmx\.js")]
    },
    "Three.js": {
        "script": [c(r"three\.min\.js"), c(r"three\.js")]
    },
    "Chart.js": {
        "script": [c(r"chart\.min\.js"), c(r"chart\.js")]
    },
    "D3.js": {
        "script": [c(r"d3\.min\.js"), c(r"d3\.js"), c(r"d3-cloud")]
    },

    # =========================================================================
    # Analytics / Marketing / Tag Managers
    # =========================================================================
    "Google Analytics": {
        "script": [c(r"google-analytics\.com/analytics\.js"), c(r"googletagmanager\.com"), c(r"gtag")]
    },
    "Google Tag Manager": {
        "script": [c(r"googletagmanager\.com/gtm\.js"), c(r"gtm\.start")]
    },
    "Facebook Pixel": {
        "script": [c(r"connect\.facebook\.net/.*fbevents"), c(r"fbq\(")]
    },
    "Hotjar": {
        "script": [c(r"static\.hotjar\.com")]
    },
    "HubSpot": {
        "script": [c(r"js\.hs-scripts\.com"), c(r"js\.hs-analytics\.net")]
    },
    "Matomo": {
        "html": [c(r"matomo\.php"), c(r"piwik\.php")],
        "script": [c(r"matomo\.js"), c(r"piwik\.js")]
    },
    "LinkedIn Insight": {
        "script": [c(r"linkedin\.com/.*insight")]
    },
    "Microsoft Clarity": {
        "script": [c(r"clarity\.ms")]
    },
    "Segment": {
        "script": [c(r"cdn\.segment\.com")]
    },
    "Amplitude": {
        "script": [c(r"cdn\.amplitude\.com")]
    },
    "Mixpanel": {
        "script": [c(r"cdn\.mixpanel\.com")]
    },

    # =========================================================================
    # E-commerce & Payments
    # =========================================================================
    "WooCommerce": {
        "html": [c(r"woocommerce"), c(r"wc-")],
        "meta": {"generator": c(r"WooCommerce")}
    },
    "Stripe": {
        "script": [c(r"js\.stripe\.com"), c(r"stripe\.js")]
    },
    "PayPal": {
        "script": [c(r"paypalobjects\.com"), c(r"paypal\.com/sdk")]
    },
    "BigCommerce": {
        "html": [c(r"bigcommerce\.com"), c(r"cdn\.bigcommerce\.com")],
        "headers": {"X-BigCommerce-Store-Id": c(r".*")}
    },

    # =========================================================================
    # Email / Marketing Platforms
    # =========================================================================
    "Mailchimp": {
        "script": [c(r"downloads\.mailchimp\.com"), c(r"list-manage\.com")]
    },
    "SendGrid": {
        "headers": {"X-SendGrid": c(r".*")},
        "html": [c(r"sendgrid\.net")]
    },
    "Mailgun": {
        "html": [c(r"mailgun\.org"), c(r"mailgun\.net")]
    },
    "Postmark": {
        "html": [c(r"postmarkapp\.com")]
    },
    "ConvertKit": {
        "script": [c(r"convertkit\.com")]
    },

    # =========================================================================
    # Infrastructure / DevOps
    # =========================================================================
    "Docker": {
        "headers": {"Server": c(r"Docker")},
        "html": [c(r"Docker")]
    },
    "Kubernetes": {
        "headers": {"X-Kubernetes-Pf": c(r".*")},
        "html": [c(r"kubernetes")]
    },
    "Jenkins": {
        "headers": {"X-Jenkins": c(r".*"), "X-Jenkins-Session": c(r".*")},
        "html": [c(r"Jenkins"), c(r"jenkins")]
    },
    "GitLab": {
        "headers": {"X-Gitlab-Event": c(r".*"), "X-Gitlab-Webhook": c(r".*")},
        "html": [c(r"gitlab")]
    },
    "New Relic": {
        "html": [c(r"newrelic"), c(r"nr-data\.net")],
        "script": [c(r"js-agent\.newrelic\.com")]
    },
    "Datadog": {
        "html": [c(r"datadog"), c(r"dd-trace")]
    },
    "Sentry": {
        "script": [c(r"browser\.sentry-cdn\.com"), c(r"@sentry/browser")]
    },
    "Elasticsearch": {
        "headers": {"X-Elastic-Product": c(r".*")},
        "html": [c(r"elasticsearch")]
    },

    # =========================================================================
    # Security / Authentication / Identity
    # =========================================================================
    "reCAPTCHA": {
        "script": [c(r"google\.com/recaptcha"), c(r"g-recaptcha")]
    },
    "hCaptcha": {
        "script": [c(r"hcaptcha\.com")]
    },
    "Auth0": {
        "script": [c(r"auth0\.com")]
    },
    "Okta": {
        "html": [c(r"okta"), c(r"oktacdn")]
    },
    # Let's Encrypt: handled by SSL analysis module (no HTTP-level detection needed)
    "Cloudflare SSL": {
        "headers": {"CF-Validated": c(r".*")}
    },

    # =========================================================================
    # Static Site Generators / Blogging
    # =========================================================================
    "Ghost": {
        "meta": {"generator": c(r"Ghost")},
        "html": [c(r"ghost\.io")],
        "headers": {"X-Ghost-Cache-Status": c(r".*")}
    },
    "Hugo": {
        "meta": {"generator": c(r"Hugo")}
    },
    "Jekyll": {
        "meta": {"generator": c(r"Jekyll")}
    },
    "Hashnode": {
        "headers": {"X-Hashnode": c(r".*")},
        "html": [c(r"hashnode\.dev"), c(r"cdn\.hashnode\.com")],
        "meta": {"generator": c(r"Hashnode")}
    },
    "Medium": {
        "html": [c(r"medium\.com"), c(r"miro\.medium\.com")],
        "headers": {"X-Powered-By": c(r"Medium")}
    },

    # =========================================================================
    # Fonts / Icons / Design Resources
    # =========================================================================
    "Google Fonts": {
        "html": [c(r"fonts\.googleapis\.com"), c(r"fonts\.gstatic\.com")]
    },
    "Font Awesome": {
        "html": [c(r"font-awesome"), c(r"fontawesome")],
        "script": [c(r"font-awesome\.js"), c(r"fontawesome\.js")]
    },
    "Material Icons": {
        "html": [c(r"Material+Icons|material-icons"), c(r"fonts\.googleapis\.com/icon")]
    },

    # =========================================================================
    # CDN / Libraries / Polyfills
    # =========================================================================
    "cdnjs": {
        "script": [c(r"cdnjs\.cloudflare\.com/libs")]
    },
    "jsDelivr": {
        "script": [c(r"cdn\.jsdelivr\.net")]
    },
    "unpkg": {
        "script": [c(r"unpkg\.com")]
    },
    "Polyfill.io": {
        "script": [c(r"polyfill\.io")]
    },
    "Modernizr": {
        "script": [c(r"modernizr.*\.js")]
    },
    "Lodash": {
        "script": [c(r"lodash.*\.js")]
    },
    "Moment.js": {
        "script": [c(r"moment.*\.js")]
    },
    "Day.js": {
        "script": [c(r"dayjs.*\.js")]
    },
    "Axios": {
        "script": [c(r"axios.*\.js")]
    },
    "Socket.io": {
        "script": [c(r"socket\.io")]
    },
    "Swagger": {
        "html": [c(r"swagger"), c(r"swagger-ui")],
        "script": [c(r"swagger")]
    },
    "GraphQL": {
        "html": [c(r"graphql")]
    },
    "Prism.js": {
        "script": [c(r"prism\.js")]
    },

    # =========================================================================
    # Server-Side Technologies
    # =========================================================================
    "Python": {
        "headers": {"Server": c(r"Python|WSGIServer|gunicorn|uWSGI|waitress")}
    },
    "Go": {
        "headers": {"Server": c(r"go-http|Go-http")}
    },
    "Rust": {
        "headers": {"Server": c(r"Rust|Axum|Actix|Rocket")}
    },
    "FastAPI": {
        "headers": {"Server": c(r"uvicorn|FastAPI")}
    },
    "Node.js": {
        "headers": {"X-Powered-By": c(r"Node\.js")}
    },
    "Deno": {
        "headers": {"Server": c(r"Deno")}
    },
    "Gunicorn": {
        "headers": {"Server": c(r"gunicorn")}
    },
    "uWSGI": {
        "headers": {"Server": c(r"uWSGI")}
    },

    # =========================================================================
    # Database Technologies
    # =========================================================================
    "MongoDB": {
        "headers": {"Server": c(r"mongodb")}
    },
    "MySQL": {
        "headers": {"Server": c(r"MySQL")}
    },
    "PostgreSQL": {
        "headers": {"Server": c(r"PostgreSQL")}
    },
    "Redis": {
        "headers": {"Server": c(r"Redis")}
    },
    "Memcached": {
        "headers": {"Server": c(r"Memcached")}
    },
}

# Known favicon hashes (MMH3 hash -> technology name)
FAVICON_HASHES = {
    -1131609981: "WordPress",
    -860844579: "Joomla",
    1167645212: "Drupal",
    -732381078: "Magento",
    1573681645: "Shopify",
    -1427822722: "Squarespace",
    2049301975: "Laravel",
    -1822967509: "Python/Django",
    -892645481: "Ruby on Rails",
    -454504913: "Angular",
    779018800: "React",
    -1095465911: "Gatsby",
    608142905: "Next.js",
    1567336423: "Node.js",
    1208030805: "Apache",
    178717315: "Nginx",
    -1297558336: "IIS",
    1956207960: "Cloudflare",
    1356496209: "Jenkins",
    -1335193475: "GitLab",
    -815544242: "Kubernetes",
    1177208022: "Docker",
    -166066415: "Amazon Web Services",
    1853622013: "Google Cloud",
    -2020900694: "Azure",
}

# Category descriptions for report findings
TECH_CATEGORIES = {
    "CMS": "Content Management System",
    "Web Server": "Web Server",
    "CDN": "Content Delivery Network / Reverse Proxy",
    "WAF": "Web Application Firewall",
    "JavaScript Framework": "Frontend JavaScript Framework",
    "Programming Language": "Programming Language / Runtime",
    "Backend Framework": "Backend Framework",
    "Analytics": "Analytics / Marketing",
    "E-commerce": "E-commerce / Payment",
    "Email": "Email / Marketing Platform",
    "Infrastructure": "Infrastructure / DevOps",
    "Security": "Security / Authentication",
    "Static Site Generator": "Static Site Generator / Blogging",
    "Design": "Design / Fonts / Icons",
    "CDN Library": "CDN / Library Hosting",
    "Database": "Database / Cache",
}

# Map technology names to categories for display
TECH_CATEGORY_MAP = {
    # CMS
    "WordPress": "CMS", "Joomla": "CMS", "Drupal": "CMS", "Magento": "CMS",
    "Shopify": "CMS", "Wix": "CMS", "Squarespace": "CMS", "TYPO3": "CMS",
    "WooCommerce": "E-commerce",
    # Web Servers
    "Nginx": "Web Server", "Apache": "Web Server", "Apache Tomcat": "Web Server",
    "IIS": "Web Server", "LiteSpeed": "Web Server", "Caddy": "Web Server",
    "Traefik": "Web Server",
    # CDN
    "Cloudflare": "CDN", "Amazon CloudFront": "CDN", "Amazon AWS": "CDN",
    "AWS Elastic Load Balancer": "CDN", "Fastly": "CDN", "Akamai": "CDN",
    "Varnish": "CDN", "HAProxy": "CDN", "Sucuri": "CDN",
    # WAF
    "ModSecurity": "WAF", "AWS WAF": "WAF", "Cloudflare WAF": "WAF", "Barracuda WAF": "WAF",
    # Backend Frameworks
    "Laravel": "Backend Framework", "Django": "Backend Framework", "Flask": "Backend Framework",
    "Ruby on Rails": "Backend Framework", "Symfony": "Backend Framework",
    "CakePHP": "Backend Framework", "CodeIgniter": "Backend Framework",
    "Spring Boot": "Backend Framework", "Express": "Backend Framework",
    "Next.js": "Backend Framework", "Nuxt.js": "Backend Framework",
    "Gatsby": "Static Site Generator", "Ghost": "Static Site Generator",
    "Hugo": "Static Site Generator", "Jekyll": "Static Site Generator",
    # JS Frameworks
    "React": "JavaScript Framework", "Vue.js": "JavaScript Framework",
    "Angular": "JavaScript Framework", "jQuery": "JavaScript Framework",
    "Bootstrap": "JavaScript Framework", "Tailwind CSS": "JavaScript Framework",
    "Foundation": "JavaScript Framework", "Material UI": "JavaScript Framework",
    "Svelte": "JavaScript Framework", "Alpine.js": "JavaScript Framework",
    "htmx": "JavaScript Framework", "Three.js": "JavaScript Framework",
    "Chart.js": "JavaScript Framework", "D3.js": "JavaScript Framework",
    # Languages
    "PHP": "Programming Language", "ASP.NET": "Programming Language",
    "Java": "Programming Language", "Python": "Programming Language",
    "Go": "Programming Language", "Rust": "Programming Language",
    "Node.js": "Programming Language", "Deno": "Programming Language",
    # Infrastructure
    "Docker": "Infrastructure", "Kubernetes": "Infrastructure",
    "Jenkins": "Infrastructure", "GitLab": "Infrastructure",
    "New Relic": "Infrastructure", "Datadog": "Infrastructure",
    "Sentry": "Infrastructure", "Elasticsearch": "Database",
    # Security
    "reCAPTCHA": "Security", "hCaptcha": "Security", "Auth0": "Security",
    "Okta": "Security", "Let's Encrypt": "Security", "Cloudflare SSL": "Security",
    # Analytics
    "Google Analytics": "Analytics", "Google Tag Manager": "Analytics",
    "Facebook Pixel": "Analytics", "Hotjar": "Analytics", "HubSpot": "Analytics",
    "Matomo": "Analytics", "LinkedIn Insight": "Analytics",
    "Microsoft Clarity": "Analytics", "Segment": "Analytics",
    "Amplitude": "Analytics", "Mixpanel": "Analytics",
    # Email
    "Mailchimp": "Email", "SendGrid": "Email", "Mailgun": "Email",
    "Postmark": "Email", "ConvertKit": "Email",
    # Design
    "Google Fonts": "Design", "Font Awesome": "Design", "Material Icons": "Design",
    # CDN Libraries
    "cdnjs": "CDN Library", "jsDelivr": "CDN Library", "unpkg": "CDN Library",
    "Polyfill.io": "CDN Library", "Modernizr": "CDN Library", "Lodash": "CDN Library",
    "Moment.js": "CDN Library", "Day.js": "CDN Library", "Axios": "CDN Library",
    "Socket.io": "CDN Library", "Swagger": "CDN Library", "GraphQL": "CDN Library",
    "Prism.js": "CDN Library",
    # Payments / E-commerce
    "Stripe": "E-commerce", "PayPal": "E-commerce", "BigCommerce": "E-commerce",
    # Database
    "MongoDB": "Database", "MySQL": "Database", "PostgreSQL": "Database",
    "Redis": "Database", "Memcached": "Database",
    # Server-side
    "FastAPI": "Backend Framework", "Gunicorn": "Programming Language",
    "uWSGI": "Programming Language",
    # Blogging/Static
    "Hashnode": "Static Site Generator",
    "Medium": "CMS",
}
