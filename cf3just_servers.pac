function FindProxyForURL(url, host) {
  // No proxy for private (RFC 1918) IP addresses (intranet sites)
  if (
    isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
    isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ||
    isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0")
  ) {
    return "DIRECT";
  }

  // No proxy for localhost
  if (isInNet(dnsResolve(host), "127.0.0.0", "255.0.0.0")) {
    return "DIRECT";
  }

 // Bypass list uses proxy server
  if (
    dnsDomainIs(host, "cws.server115.net") ||
    dnsDomainIs(host, "5o-live.server115.net") ||
    dnsDomainIs(host, ".exchange.uk.com") ||
    dnsDomainIs(host, ".justretirement.com/epi") ||
    dnsDomainIs(host, "new.t1.justretirementsolutions.com/epi") ||
    dnsDomainIs(host, "services.oac-mo.net") ||
    dnsDomainIs(host, "mw.markit.com")  ||
    dnsDomainIs(host, ".postcodeanywhere.co.uk") ||
    dnsDomainIs(host, ".hmrc.gov.uk")  ||
    dnsDomainIs(host, ".tax.service.gov.uk")  ||
    dnsDomainIs(host, "dms.markitserv.com")
    ) 
 {
    return "HTTPS saeukgbm27.proxy.cloudflare-gateway.com:443";
 }

  // Default forward direct
  return "DIRECT";
}
