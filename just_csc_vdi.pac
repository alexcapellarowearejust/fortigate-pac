function FindProxyForURL(url, host) {
	var privateIP = /^(0|10|127|192.168|172.1[6789]|172.2[0-9]|172.3[01]|169.254|192.88.99).[0-9.]+$/;
	var resolved_ip = dnsResolve(host);

	/* Don't send non-FQDN or private IP auths to ZScaler */
	if (isPlainHostName(host) || 
//	    isInNet(resolved_ip, "192.0.2.0","255.255.255.0") || 
	    isInNet(resolved_ip, "10.0.0.0","255.0.0.0") || 
//	    isInNet(resolved_ip, "10.26.0.0","255.255.0.0") || 
	    privateIP.test(host))
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
    dnsDomainIs(host, "dlws.bloomberg.com")||
    dnsDomainIs(host, "adminoe24.fnzc.co.uk")||
    dnsDomainIs(host, "adminte43.fnzc.co.uk")||
    dnsDomainIs(host, "oe24servicemassl.fnzc.co.uk")||
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
    dnsDomainIs(host, ".postman.co") ||
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
    dnsDomainIs(host, "tcr9i.chat.openai.com") ||    
    dnsDomainIs(host, ".chat.openai.com") ||
    dnsDomainIs(host, ".oai.azure.com") ||
    dnsDomainIs(host, ".cdn.openai.com") ||
    dnsDomainIs(host, ".db.com") ||
    dnsDomainIs(host, ".justdpprodsanertpfd001.file.core.windows.net") ||
    dnsDomainIs(host, ".azuredatabricks.net") ||
    dnsDomainIs(host, ".blueprismcloud.com") ||
    dnsDomainIs(host, "amsretirement.co.uk") ||
    dnsDomainIs(host, "gstatic.com/recaptcha") ||
    dnsDomainIs(host, "google.com/recaptcha") ||
    dnsDomainIs(host, "fonts.googleapis.com") ||
    dnsDomainIs(host, "use.fontawesome.com") ||
    dnsDomainIs(host, "login.okta.com") ||
    dnsDomainIs(host, "ok14static.oktacdn.com") ||
    dnsDomainIs(host, "us-rgaext.customdomains.okta.com") ||
    dnsDomainIs(host, "cloudflareportal.com") ||
    dnsDomainIs(host, "cloudflareok.com") ||
    dnsDomainIs(host, "cloudflarecp.com") ||
    dnsDomainIs(host, ".visualstudio.com") ||
    dnsDomainIs(host, ".blob.core.windows.net") ||
    shExpMatch(host, "*.cloudflareclient.com") ||
    dnsDomainIs(host, "a.nel.cloudflare.com")
   )
 {
     return 'DIRECT';
 }
 
/* Do not proxy IPs */
if (
isInNet(host, "46.249.198.196", "255.255.255.255") ||
isInNet(host, "162.159.137.105", "255.255.255.255") ||
isInNet(host, "162.159.138.105", "255.255.255.255") ||
isInNet(host, "162.159.36.1", "255.255.255.255") ||
isInNet(host, "162.159.46.1", "255.255.255.255") ||
isInNet(host, "162.159.193.0", "255.255.255.0") ||
shExpMatch(host, "2606:4700:7::a29f:8969") ||
shExpMatch(host, "2606:4700:7::a29f:8a69") ||
shExpMatch(host, "2606:4700:4700::1111") ||
shExpMatch(host, "2606:4700:4700::1001") ||
shExpMatch(host, "2606:4700:100:*")
)
{
	return 'DIRECT';
}

/* Fortigate explicit proxy POC */
if (
dnsDomainIs(host, "whatismyipaddress.com") ||
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
    dnsDomainIs(host, "whatismyip.com") ||
    dnsDomainIs(host, "www.whatismyip.com") ||
    dnsDomainIs(host, "*.scottishwidowsplatform.com") ||
    dnsDomainIs(host, "bridger.lexisnexis.eu") ||
    dnsDomainIs(host, "canadalifeqptest-api.ctc.uk.com") ||
    dnsDomainIs(host, "testone.testapi.annuityquote.standardlife.co.uk") ||
    dnsDomainIs(host, "dataportal.matrixsolutions.co.uk") ||
    (shExpMatch(host, "annuity-messaging.rwy-aviva.co.uk")) ||
    (shExpMatch(host, "b2bbts-oat.canadalife.ie")) ||
    (shExpMatch(host, "jrl.t1.justretirement.com")) ||
    (shExpMatch(host, "ppentry.landg.com")) ||
    (shExpMatch(host, "b2b-sa.e2e.service.scottishwidows.co.uk")) ||
    (shExpMatch(host, "dev.annuity-gears.co.uk")) ||
    (shExpMatch(host, "sftp.lcp.uk.com")) ||
    (shExpMatch(host, "*.scottishwidowsplatform.com")) ||
    (shExpMatch(host, "bridger.lexisnexis.eu")) ||
    (shExpMatch(host, "canadalifeqptest-api.ctc.uk.com")) ||
    (shExpMatch(host, "testone.testapi.annuityquote.standardlife.co.uk")) ||
    (shExpMatch(host, "dataportal.matrixsolutions.co.uk")) ||
    dnsDomainIs(host, "dms.markitserv.com")
    ) 
 {
    return "HTTPS saeukgbm27.proxy.cloudflare-gateway.com:443";
 }

	/* FTP goes directly */
	if (url.substring(0,4) == "ftp:") {
		return "DIRECT";
	}

	return "HTTPS saeukgbm27.proxy.cloudflare-gateway.com:443";
	
}
