"""
Technology Signatures Database
Contains regex patterns and rules for identifying web technologies without external APIs.
"""

import re

# compiled regex for efficiency
def c(pattern):
    return re.compile(pattern, re.IGNORECASE)

TECHNOLOGIES = {
    # -------------------------------------------------------------------------
    # Content Management Systems (CMS)
    # -------------------------------------------------------------------------
    "WordPress": {
        "headers": {"X-Powered-By": c(r"WordPress")},
        "meta": {"generator": c(r"WordPress")},
        "html": [c(r"wp-content/"), c(r"wp-includes/")],
        "script": [c(r"wp-emoji-release\.min\.js"), c(r"wp-embed\.min\.js")],
        "cookies": {"wordpress_test_cookie": c(r".*"), "wp-settings-": c(r".*")}
    },
    "Joomla": {
        "headers": {"X-Content-Encoded-By": c(r"Joomla")},
        "meta": {"generator": c(r"Joomla"), "author": c(r"Joomla")},
        "html": [c(r"content=\"Joomla!")],
        "cookies": {"joomla_user_state": c(r".*")}
    },
    "Drupal": {
        "headers": {"X-Generator": c(r"Drupal"), "X-Drupal-Cache": c(r".*")},
        "meta": {"generator": c(r"Drupal")},
        "html": [c(r"Drupal\.settings"), c(r"sites/all/themes")],
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
        "html": [c(r"cdn\.shopify\.com"), c(r"Shopify\.theme")],
        "script": [c(r"shopify\-")],
        "headers": {"X-Shopify-Stage": c(r".*")}
    },
    "Wix": {
        "headers": {"X-Wix-Request-Id": c(r".*")},
        "meta": {"generator": c(r"Wix\.com")},
        "html": [c(r"wix-warmup-data")],
        "script": [c(r"static\.parastorage\.com")]
    },
    
    # -------------------------------------------------------------------------
    # Web Servers
    # -------------------------------------------------------------------------
    "Nginx": {
        "headers": {"Server": c(r"nginx")}
    },
    "Apache": {
        "headers": {"Server": c(r"Apache")}
    },
    "IIS": {
        "headers": {"Server": c(r"IIS")},
        "html": [c(r"Microsoft-IIS")]
    },
    "LiteSpeed": {
        "headers": {"Server": c(r"LiteSpeed")}
    },
    "Cloudflare": {
        "headers": {"Server": c(r"cloudflare"), "CF-RAY": c(r".*")},
        "cookies": {"__cfduid": c(r".*"), "__cf_bm": c(r".*")}
    },
    "Node.js": {
        "headers": {"X-Powered-By": c(r"Node\.js")}
    },
    
    # -------------------------------------------------------------------------
    # Programming Languages / Frameworks
    # -------------------------------------------------------------------------
    "PHP": {
        "headers": {"X-Powered-By": c(r"PHP")},
        "cookies": {"PHPSESSID": c(r".*")}
    },
    "ASP.NET": {
        "headers": {"X-Powered-By": c(r"ASP\.NET"), "X-AspNet-Version": c(r".*")},
        "cookies": {"ASP.NET_SessionId": c(r".*")}
    },
    "Java": {
        "cookies": {"JSESSIONID": c(r".*")}
    },
    "Ruby on Rails": {
        "headers": {"X-Powered-By": c(r"Phusion Passenger")},
        "html": [c(r"csrf-token"), c(r"csrf-param")]
    },
    "Laravel": {
        "headers": {"Set-Cookie": c(r"laravel_session")},
        "cookies": {"laravel_session": c(r".*"), "XSRF-TOKEN": c(r".*")}
    },
    "Django": {
        "html": [c(r"csrfmiddlewaretoken")],
        "cookies": {"csrftoken": c(r".*")}
    },
    "Flask": {
        "headers": {"Server": c(r"Werkzeug")}
    },
    
    # -------------------------------------------------------------------------
    # JavaScript Frameworks
    # -------------------------------------------------------------------------
    "React": {
        "html": [c(r"data-reactid"), c(r"react-root")],
        "script": [c(r"react\.production\.min\.js"), c(r"react-dom")]
    },
    "Vue.js": {
        "html": [c(r"data-v-"), c(r"vue-app")],
        "script": [c(r"vue\.min\.js"), c(r"vue\.js")]
    },
    "Angular": {
        "html": [c(r"ng-app"), c(r"ng-controller"), c(r"ng\-version")],
        "script": [c(r"angular\.js"), c(r"angular\.min\.js")]
    },
    "jQuery": {
        "script": [c(r"jquery.*\.js")]
    },
    "Bootstrap": {
        "html": [c(r"bootstrap\.min\.css"), c(r"bootstrap\.css")],
        "script": [c(r"bootstrap\.min\.js"), c(r"bootstrap\.js")]
    },
    
    # -------------------------------------------------------------------------
    # Analytics / Marketing
    # -------------------------------------------------------------------------
    "Google Analytics": {
        "script": [c(r"google-analytics\.com\/analytics\.js"), c(r"googletagmanager\.com")]
    },
    "Hotjar": {
        "script": [c(r"static\.hotjar\.com")]
    },
    "HubSpot": {
        "script": [c(r"js\.hs-scripts\.com")]
    },
    
    # -------------------------------------------------------------------------
    # Security / WAF
    # -------------------------------------------------------------------------
    "reCAPTCHA": {
        "script": [c(r"google\.com\/recaptcha")]
    },
    "Let's Encrypt": {
        # Certificate Issuer check would be separate, but headers might leak it
        "headers": {} # handled by SSL scan mainly
    }
}
