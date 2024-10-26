function FindProxyForURL(url, host) {
	var privateIP = /^(0|10|127|192.168|172.1[6789]|172.2[0-9]|172.3[01]|169.254|192.88.99).[0-9.]+$/;
	var resolved_ip = dnsResolve(host);

	/* Don't send non-FQDN or private IP auths to us */
	if (isPlainHostName(host) || isInNet(resolved_ip, "192.0.2.0","255.255.255.0") || privateIP.test(host))
	return "DIRECT";
	
/* Bypass list uses proxy server */
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
    return "HTTPS saeukgbm27.proxy.cloudflare-gateway.com";
 }

	/* Default Traffic Forwarding. Forward direct to internet via local breakout */
	return "DIRECT";
}
