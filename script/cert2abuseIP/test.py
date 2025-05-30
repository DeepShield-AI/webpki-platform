
import dns.resolver
import dns.reversename

ip = "1.1.1.1"
rev_name = dns.reversename.from_address(ip)
print(rev_name)


resolver = dns.resolver.Resolver()
resolver.nameservers = ['114.114.114.114']
answer = resolver.resolve(rev_name, "PTR")
print(answer)

try:
    # answer = dns.resolver.resolve(rev_name, "PTR")
    for rdata in answer:
        print(rdata)
        print(f"PTR record for {ip}: {rdata.to_text()}")
except dns.resolver.NXDOMAIN:
    print(f"No PTR record found for {ip}")
