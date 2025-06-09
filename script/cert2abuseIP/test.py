
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
        text_data = rdata.to_text()
        if text_data.endswith("."):
            text_data = text_data[:-1]
        print(rdata.to_text()[:-1])
        print(f"PTR record for {ip}: {text_data}")
except dns.resolver.NXDOMAIN:
    print(f"No PTR record found for {ip}")
