APP_NAME = "HTTP Header Scanner"
APP_VERSION = "1.0.0"

COLORS = {
    "background": "#0B1F33",
    "sidebar": "#071827",
    "primary": "#1677FF",
    "primary_hover": "#0D63D8",
    "secondary": "#12395C",
    "card": "#102B45",
    "card_light": "#163B5F",
    "text": "#FFFFFF",
    "text_secondary": "#AFC4D8",
    "success": "#20C997",
    "danger": "#FF5C6C",
    "warning": "#FFB020",
    "border": "#245174",
    "input": "#0D253D",
}

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Forces HTTPS connections.",
        "severity": "High",
    },
    "Content-Security-Policy": {
        "description": "Helps protect against XSS and content injection attacks.",
        "severity": "High",
    },
    "X-Content-Type-Options": {
        "description": "Prevents certain MIME sniffing attacks.",
        "severity": "Medium",
    },
    "X-Frame-Options": {
        "description": "Helps protect against clickjacking.",
        "severity": "Medium",
    },
    "Referrer-Policy": {
        "description": "Controls information sent through the Referer header.",
        "severity": "Low",
    },
    "Permissions-Policy": {
        "description": "Controls browser features and permissions.",
        "severity": "Low",
    },
}