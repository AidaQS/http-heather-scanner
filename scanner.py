import ssl
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse


USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 "
    "(KHTML, like Gecko) "
    "Chrome/139.0.0.0 Safari/537.36"
)

TIMEOUT = 8


def normalize_url(url):

    url = url.strip()

    if not url:
        raise ValueError("Please enter a URL.")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if not parsed.netloc:
        raise ValueError("The URL is not valid.")

    return url


def scan(url):

    url = normalize_url(url)

    request = Request(
        url,
        method="GET",
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        }
    )

    ssl_context = ssl.create_default_context()

    response = None

    try:

        response = urlopen(
            request,
            timeout=TIMEOUT,
            context=ssl_context
        )

        # Read only a very small amount of data.
        # We do NOT need the complete webpage.
        response.read(1)

        headers = dict(
            response.headers.items()
        )

        return {
            "status": response.status,
            "url": response.geturl(),
            "headers": headers
        }

    except HTTPError as error:

        # HTTP errors are still useful.
        # We want their headers.

        headers = dict(
            error.headers.items()
        )

        return {
            "status": error.code,
            "url": error.geturl(),
            "headers": headers
        }

    except ssl.SSLError as error:

        raise ConnectionError(
            "SSL/TLS connection failed.\n\n"
            f"Details: {error}"
        )

    except URLError as error:

        reason = error.reason

        raise ConnectionError(
            "Could not connect to the server.\n\n"
            f"Reason: {reason}\n\n"
            f"Target: {url}"
        )

    except TimeoutError:

        raise ConnectionError(
            "The server did not respond within "
            f"{TIMEOUT} seconds.\n\n"
            f"Target: {url}"
        )

    except Exception as error:

        raise RuntimeError(
            "Unexpected scanner error.\n\n"
            f"Type: {type(error).__name__}\n"
            f"Details: {error}"
        )

    finally:

        if response is not None:

            try:
                response.close()
            except Exception:
                pass