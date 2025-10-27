import http.client
import requests
import urllib3
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.ssl_ import create_urllib3_context

# Enable debug logging for HTTP connections to see SNI and Host headers
http.client.HTTPConnection.debuglevel = 5
urllib3.add_stderr_logger()


class FrontingAdapter(HTTPAdapter):
    """
    A Transport Adapter that allows specifying a different hostname for SNI
    than the one used in the HTTP Host header.
    """

    def __init__(self, fronted_domain=None, **kwargs):
        self.fronted_domain = fronted_domain
        super(FrontingAdapter, self).__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        # Create a custom SSL context to set the server_hostname for SNI
        context = create_urllib3_context()
        kwargs = {
            'num_pools': connections,
            'maxsize': maxsize,
            'block': block,
            'ssl_context': context,
        }
        if self.fronted_domain:
            # This sets the SNI hostname
            kwargs['server_hostname'] = self.fronted_domain

        self.poolmanager = urllib3.PoolManager(**kwargs)

    def send(self, request, **kwargs):
        # Ensure the Host header is set to the actual target domain
        # This is typically handled by requests based on the request.url,
        # but can be explicitly set if needed for specific scenarios.
        # For domain fronting, the 'Host' header in the HTTP request
        # should be the *actual* domain you want to reach, while the
        # SNI (set by fronted_domain) is the 'cover' domain.

        # The connection pool kwargs might need adjustment for assert_hostname
        # depending on the exact behavior of the CDN.
        connection_pool_kwargs = self.poolmanager.connection_pool_kw
        if self.fronted_domain:
            # If the fronted_domain is used for SNI, we might need to
            # tell urllib3 not to assert the hostname against the IP,
            # or assert it against the fronted_domain.
            # This part can be tricky and depends on the CDN's certificate.
            # For simplicity, we'll let urllib3 handle certificate validation
            # against the SNI domain.
            pass  # No explicit assert_hostname manipulation here for this example

        return super(FrontingAdapter, self).send(request, **kwargs)


# --- Example Usage ---
# The IP address of a CDN endpoint that hosts 'fronted.localhost:8000'
# and can route traffic to 'actual.localhost:8000' based on the Host header.
# Replace with actual IP and domains for a real-world test.
# Note: Many cloud providers now actively block domain fronting. [5]
CDN_IP = "54.230.14.90"  # Example IP, might not be valid or frontable
# The domain visible in SNI (e.g., a CDN domain)
FRONTED_DOMAIN = "fronted.digi.ninja"
# The actual domain you want to reach
ACTUAL_HOST_HEADER = "d1sdh26o090vk5.cloudfront.net"

# Create a session
s = requests.Session()

# Mount the custom adapter to handle HTTPS requests
# The 'fronted_domain' will be used for the SNI field during TLS handshake.
s.mount('https://', FrontingAdapter(fronted_domain=FRONTED_DOMAIN))

try:
    # Make a GET request to the CDN's IP, but specify the actual target
    # in the Host header. The URL's hostname part (CDN_IP) is what the
    # DNS resolution will point to, but the SNI will be FRONTED_DOMAIN
    # and the HTTP Host header will be ACTUAL_HOST_HEADER.
    print(
        f"\nAttempting to front from '{FRONTED_DOMAIN}' to '{ACTUAL_HOST_HEADER}' via IP '{CDN_IP}'...")
    response = s.get(
        f"https://{CDN_IP}/",
        headers={"Host": ACTUAL_HOST_HEADER},
        verify=True,  # Always verify SSL certificates in production
        timeout=10
    )

    print("\n--- Response ---")
    print(f"Status Code: {response.status_code}")
    print(f"Response Headers: {response.headers}")
    print(f"Response Content (first 500 chars): {response.text[:500]}...")

except requests.exceptions.RequestException as e:
    print(f"\nAn error occurred: {e}")
    print(
        "Domain fronting is increasingly difficult as cloud providers block it. [5]")
    print("Ensure the CDN_IP, FRONTED_DOMAIN, and ACTUAL_HOST_HEADER are correctly configured for a frontable service.")
