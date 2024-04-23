function FindProxyForURL(url, host) {
	var privateIP = /^(0|10|127|192.168|172.1[6789]|172.2[0-9]|172.3[01]|169.254|192.88.99).[0-9.]+$/;
	var resolved_ip = dnsResolve(host);

	/* Don't send non-FQDN or private IP auths to us */
	if (isPlainHostName(host) || isInNet(resolved_ip, "192.0.2.0","255.255.255.0") || privateIP.test(host))
	return "DIRECT";
	
/* Don't proxy local domains */
 if (
    dnsDomainIs(host, ".lan.local") ||
    dnsDomainIs(host, ".testlan.testlocal") ||
    dnsDomainIs(host, ".devlan.devlocal") ||
    dnsDomainIs(host, ".justyourmail.com") ||
    dnsDomainIs(host, ".justyourdesktop.com") ||
    dnsDomainIs(host, ".justrs.local") ||
    dnsDomainIs(host, ".justyourmeeting.com") ||
    dnsDomainIs(host, ".justretirementsolutions.com/epi") ||
    dnsDomainIs(host, ".partnershipassurance.int")||
    dnsDomainIs(host, "justyouroffice.justretirement.com") ||
    dnsDomainIs(host, "adfs.justretirement.com") ||
    dnsDomainIs(host, "autodiscover.wearejust.co.uk") ||
    dnsDomainIs(host, "autodiscover.justretirement.com") ||
    dnsDomainIs(host, "autodiscover.hubfs.co.uk") ||
    dnsDomainIs(host, "autodiscover.partnership.co.uk") ||
    dnsDomainIs(host, ".outlook.com") ||
    dnsDomainIs(host, ".office365.com") ||
    dnsDomainIs(host, "definedbenefit.partnership.co.uk")||
    dnsDomainIs(host, "ams.partnership.co.uk")  ||
    dnsDomainIs(host, "equity-release.partnership.co.uk")  ||
    dnsDomainIs(host, "admin-equity-release.partnership.co.uk")  ||
    dnsDomainIs(host, "equityrelease.dev.partnership.co.uk")||
    dnsDomainIs(host, "just-snow.wearejust.co.uk") ||
    dnsDomainIs(host, ".wearejust.co.uk/epi") ||
    dnsDomainIs(host, "provisioningapi.microsoftonline.com") ||
    dnsDomainIs(host, "justretirement-admin.sharepoint.com") ||
    dnsDomainIs(host, "T3711.wework.com")||
    dnsDomainIs(host, "clearpass.justgroupplc.co.uk")||
    dnsDomainIs(host, "dataportal.matrixsolutions.co.uk") ||
    dnsDomainIs(host, "dlws.bloomberg.com")||
    dnsDomainIs(host, "adminoe24.fnzc.co.uk")||
    dnsDomainIs(host, "adminte43.fnzc.co.uk")||
    dnsDomainIs(host, "orbus.wearejust.co.uk")||
    dnsDomainIs(host, "ucupdates-r2.wearejust.co.uk") ||
    dnsDomainIs(host, "lyncdiscoverinternal.wearejust.co.uk") ||
    dnsDomainIs(host, "sipinternal.wearejust.co.uk")  ||
    dnsDomainIs(host, "lyncdiscoverexternal.wearejust.co.uk") ||
    dnsDomainIs(host, "sip.wearejust.co.uk") ||
    dnsDomainIs(host, "sipexternal.wearejust.co.uk") ||
    dnsDomainIs(host, "findev1app01.wearejust.co.uk") ||    
    dnsDomainIs(host, "findev2app01.wearejust.co.uk") ||
    dnsDomainIs(host, "sbc2.justgroupplc.co.uk") ||
    dnsDomainIs(host, ".dell.com") ||
    dnsDomainIs(host, ".hdsjira.com") ||
    dnsDomainIs(host, ".nuget.org") ||
    dnsDomainIs(host, ".npmjs.org") ||
    dnsDomainIs(host, ".postman.com") ||
    dnsDomainIs(host, ".getpostman.com") ||
    dnsDomainIs(host, "identity.getpostman.com") ||
    dnsDomainIs(host, ".visualstudio.com") ||
    dnsDomainIs(host, ".logitech.com") ||
    dnsDomainIs(host, "a3fejkt9utwjk2-ats.iot.us-west-2.amazonaws.com") ||
    dnsDomainIs(host, "cognito-idp.us-west-2.amazonaws.com") ||
    dnsDomainIs(host, "ebs-dba1.wearejust.co.uk") ||    
    dnsDomainIs(host, "ebs-dba2.wearejust.co.uk") ||
    dnsDomainIs(host, "ebs-dev1.wearejust.co.uk") ||    
    dnsDomainIs(host, "ebs-dev2.wearejust.co.uk") ||
    dnsDomainIs(host, "ebs-sys1.wearejust.co.uk") ||
    dnsDomainIs(host, "ebs-uat1.wearejust.co.uk") ||
    dnsDomainIs(host, "ebs-prod.wearejust.co.uk") ||
    dnsDomainIs(host, "ebs-sys2.wearejust.co.uk") ||
    dnsDomainIs(host, "ebs-uat2.wearejust.co.uk") ||
    dnsDomainIs(host, ".portal.hcp.uksouth.azmk8s.io") ||
    dnsDomainIs(host, ".portal.hcp.ukwest.azmk8s.io") ||
    dnsDomainIs(host, ".privatelink.uksouth.azmk8s.io") ||
    dnsDomainIs(host, ".privatelink.ukwest.azmk8s.io") ||
    dnsDomainIs(host, ".openai.azure.com") ||
    dnsDomainIs(host, ".oai.azure.com") ||
    dnsDomainIs(host, ".db.com") ||
    dnsDomainIs(host, ".markitcdn.com") ||
    dnsDomainIs(host, ".markitqa.com") ||
    dnsDomainIs(host, ".enact.co.uk") ||
    dnsDomainIs(host, ".google.com") ||
    dnsDomainIs(host, ".stripe.com") ||
    dnsDomainIs(host, ".blueprismcloud.com")
   )
 {
     return 'DIRECT';
 }
 
/* Do not proxy IPs */
if (
isInNet(host, "46.249.198.196", "255.255.255.255")
)
{
	return 'DIRECT';
}

/* Fortigate explicit proxy POC */
if (
dnsDomainIs(host, "spaghetti.com")
    )
{
    return "PROXY 10.10.62.233:3179";
}

if (
    dnsDomainIs(host, "cws.server115.net") ||
    dnsDomainIs(host, "5o-live.server115.net") ||
    dnsDomainIs(host, ".exchange.uk.com") ||
    dnsDomainIs(host, ".justretirement.com/epi") ||
    dnsDomainIs(host, "new.t1.justretirementsolutions.com/epi") ||
    dnsDomainIs(host, "services.oac-mo.net") ||
    dnsDomainIs(host, ".origoservices.com") ||
    dnsDomainIs(host, "secure.trioptima.com") ||
    dnsDomainIs(host, "mw.markit.com") ||
    (shExpMatch(host, "annuity-messaging.rwy-aviva.co.uk")) ||
    (shExpMatch(host, "b2bbts-oat.canadalife.ie")) ||
    (shExpMatch(host, "jrl.t1.justretirement.com")) ||
    (shExpMatch(host, "ppentry.landg.com")) ||
    (shExpMatch(host, "b2b-sa.e2e.service.scottishwidows.co.uk")) ||
    (shExpMatch(host, "dev.annuity-gears.co.uk")) ||
    (shExpMatch(host, "sftp.lcp.uk.com")) ||
    dnsDomainIs(host, "dms.markitserv.com")
    ) 
 {
    return "PROXY cscproxy.live01.lan.local:3128";
 }

	/* FTP goes directly */
	if (url.substring(0,4) == "ftp:") {
		return "DIRECT";
	}

	/* Updates are directly accessible */
	if (((localHostOrDomainIs(host, "trust.zscaler.com")) ||
        (localHostOrDomainIs(host, ".zscalertwo.net")) ||
		(localHostOrDomainIs(host, "trust.zscaler.net")) ||
		(localHostOrDomainIs(host, "trust.zscalerone.net")) ||
		(localHostOrDomainIs(host, "trust.zscalertwo.net")) ||
		(localHostOrDomainIs(host, "trust.zscloud.net")) ) &&
		(url.substring(0,5) == "http:" || url.substring(0,6) == "https:")){
		return "DIRECT";
	}

	/* Default Traffic Forwarding. Forwarding to CSC on port 80, if not available, send to Zscaler on 10387 */
	/* return "PROXY 10.2.95.61:80; PROXY 165.225.80.40:10387"; */
	return "PROXY 165.225.16.160:10387; PROXY 147.161.141.65:10387";
}
