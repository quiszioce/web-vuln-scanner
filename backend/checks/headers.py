import httpx
import truststore
import ssl

# Each header we care about, with a severity if it's missing and a short description
SECURITY_HEADERS = [
    {
        "header": "Content-Security-Policy",
        "severity": "high",
        "description": "Prevents XSS by controlling which resources the browser is allowed to load.",
    },
    {
        "header": "Strict-Transport-Security",
        "severity": "high",
        "description": "Forces HTTPS — prevents downgrade attacks and cookie hijacking.",
    },
    {
        "header": "X-Frame-Options",
        "severity": "medium",
        "description": "Stops the page being embedded in an iframe, preventing clickjacking.",
    },
    {
        "header": "X-Content-Type-Options",
        "severity": "low",
        "description": "Prevents the browser from guessing the content type (MIME sniffing).",
    },
    {
        "header": "Referrer-Policy",
        "severity": "low",
        "description": "Controls how much referrer info is sent with requests.",
    },
    {
        "header": "Permissions-Policy",
        "severity": "low",
        "description": "Restricts access to browser features like camera, microphone, geolocation.",
    },
]


async def check_headers(url: str) -> list[dict]:
    """
    Makes a GET request to the target URL and checks which
    security headers are present or missing in the response.
    """
    results = []

    # truststore makes Python use the Windows certificate store for SSL verification
    ssl_ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    async with httpx.AsyncClient(follow_redirects=True, timeout=10, verify=ssl_ctx) as client:
        response = await client.get(url)

    for item in SECURITY_HEADERS:
        header_name = item["header"]
        present = header_name.lower() in [h.lower() for h in response.headers]

        results.append({
            "check": header_name,
            "status": "pass" if present else "fail",
            "severity": "info" if present else item["severity"],
            "detail": (
                f"Header is present: {response.headers.get(header_name)}"
                if present
                else f"Missing header. {item['description']}"
            ),
        })

    return results
