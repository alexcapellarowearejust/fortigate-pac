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
    dnsDomainIs(host, ".fab.dmz") ||
    dnsDomainIs(host, "justyourmail.com") ||
    dnsDomainIs(host, "justyourdesktop.com") ||
    dnsDomainIs(host, ".justrs.local") ||
    dnsDomainIs(host, ".justyourmeeting.com") ||
    dnsDomainIs(host, ".justretirementsolutions.com/epi") ||
    dnsDomainIs(host, "new.justretirementsolutions.com/epi") ||
    dnsDomainIs(host, "justyouroffice.justretirement.com") ||
    dnsDomainIs(host, "adfs.justretirement.com") ||
    dnsDomainIs(host, "autodiscover.wearejust.co.uk") ||
    dnsDomainIs(host, "autodiscover.hubfs.co.uk") ||
    dnsDomainIs(host, "hybrid.partnership.co.uk") ||
    dnsDomainIs(host, "autodiscover.partnership.co.uk") ||
    dnsDomainIs(host, "cascade.partnership.co.uk") ||
    dnsDomainIs(host, "reports.partnership.co.uk") ||
    dnsDomainIs(host, ".partnershipassurance.int")||
    dnsDomainIs(host, "conference.partnership.co.uk")||
    dnsDomainIs(host, "T3711.wework.com")||
    dnsDomainIs(host, "clearpass.justgroupplc.co.uk")||
    dnsDomainIs(host, "dlws.bloomberg.com")||
    dnsDomainIs(host, "equityrelease.dev.partnership.co.uk")||
    dnsDomainIs(host, "adminoe24.fnzc.co.uk")||
	dnsDomainIs(host, "adminte43.fnzc.co.uk")||
    dnsDomainIs(host, "mca.partnership.co.uk")||
    dnsDomainIs(host, "ams.partnership.co.uk")||
    dnsDomainIs(host, "admin-equity-release.partnership.co.uk")||
    dnsDomainIs(host, "equity-release.partnership.co.uk")||
    dnsDomainIs(host, "definedbenefit.partnership.co.uk")||
    dnsDomainIs(host, "orbus.wearejust.co.uk")||
    dnsDomainIs(host, "ucupdates-r2.wearejust.co.uk") ||
    dnsDomainIs(host, "lyncdiscoverinternal.wearejust.co.uk") ||
    dnsDomainIs(host, "sipinternal.wearejust.co.uk")  ||
    dnsDomainIs(host, "lyncdiscoverexternal.wearejust.co.uk") ||
    dnsDomainIs(host, "sip.wearejust.co.uk") ||
    dnsDomainIs(host, "sipexternal.wearejust.co.uk") ||
    dnsDomainIs(host, "just-snow.wearejust.co.uk") ||
    dnsDomainIs(host, "findev1app01.wearejust.co.uk") ||    
    dnsDomainIs(host, "findev2app01.wearejust.co.uk") ||
    dnsDomainIs(host, "sbc2.justgroupplc.co.uk") ||
    dnsDomainIs(host, ".wearejust.co.uk/epi") ||
    dnsDomainIs(host, "wearejust.co.uk/epi") ||
    dnsDomainIs(host, "provisioningapi.microsoftonline.com") ||
    dnsDomainIs(host, "justretirement-admin.sharepoint.com") ||
    dnsDomainIs(host, ".hdsjira.com") ||
    dnsDomainIs(host, ".nuget.org") ||
    dnsDomainIs(host, ".npmjs.org") ||
    dnsDomainIs(host, ".postman.com") ||
    dnsDomainIs(host, ".getpostman.com") ||
    dnsDomainIs(host, "ebs-dba1.wearejust.co.uk") ||    
    dnsDomainIs(host, "ebs-dba2.wearejust.co.uk") ||
    dnsDomainIs(host, "ebs-dev1.wearejust.co.uk") ||    
    dnsDomainIs(host, "ebs-dev2.wearejust.co.uk") ||
    dnsDomainIs(host, "ebs-sys1.wearejust.co.uk") ||
    dnsDomainIs(host, "ebs-uat1.wearejust.co.uk") ||
    dnsDomainIs(host, "ebs-prod.wearejust.co.uk") ||
//  dnsDomainIs(host, ".azuredatabricks.net") ||
    dnsDomainIs(host, ".privatelink.uksouth.azmk8s.io") ||
    dnsDomainIs(host, ".privatelink.ukwest.azmk8s.io")
   )
 {
     return 'DIRECT';
 }
 
if (
isInNet(host, "193.108.18.194", "255.255.255.255") ||
isInNet(host, "195.254.178.204", "255.255.255.255") ||
isInNet(host, "193.108.18.192", "255.255.255.255") ||
isInNet(host, "193.108.18.193", "255.255.255.255")
)
{
    return "PROXY wpad.live01.lan.local:8080";
}

/* Do not proxy IPs */
if (
isInNet(host, "46.249.198.196", "255.255.255.255")
)
{
	return 'DIRECT';
}


if (
    dnsDomainIs(host, "cws.server115.net") ||
    dnsDomainIs(host, "5o-live.server115.net") ||
    dnsDomainIs(host, "ifapreview.exchange.uk.com") ||
    dnsDomainIs(host, ".origoservices.com") ||
    dnsDomainIs(host, ".origo.com") ||
    dnsDomainIs(host, ".vscreen.org") ||
    dnsDomainIs(host, "confirmations.swapswire.com") ||
    dnsDomainIs(host, "expreview.exchange.uk.com") ||
    dnsDomainIs(host, "services.oacplc.com") ||
    dnsDomainIs(host, "brains006.fab.dmz") ||
    dnsDomainIs(host, "wan.partnership.co.uk") ||
    dnsDomainIs(host, "connect.partnership.co.uk") ||
    dnsDomainIs(host, ".justretirement.com/epi") ||
    dnsDomainIs(host, "new.t1.justretirementsolutions.com/epi") ||
    dnsDomainIs(host, "services.oac-mo.net") ||
    dnsDomainIs(host, "mw.markit.com")  ||
    dnsDomainIs(host, "euro.dell.com")  ||
    dnsDomainIs(host, ".dell.com")  ||
    dnsDomainIs(host, "downloads.dell.com")  ||
    dnsDomainIs(host, "ams.partnership.co.uk")  ||
    dnsDomainIs(host, "admin-equity-release.partnership.co.uk")  ||
    dnsDomainIs(host, "activate.doubletake.com")  ||
    dnsDomainIs(host, "ifapreview-services.exchange.uk.com")  ||
    dnsDomainIs(host, "*.scottishwidowsplatform.com") ||
    dnsDomainIs(host, "dataportal.matrixsolutions.co.uk") ||
    (shExpMatch(host, "*.scottishwidowsplatform.com")) ||
    (shExpMatch(host, "dataportal.matrixsolutions.co.uk")) ||
    dnsDomainIs(host, "dms.markitserv.com")
    ) 
 {
    return "PROXY wpad.live01.lan.local:8080";
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

	/* Default Traffic Forwarding. Forwarding to Zen on port 10387, but you can use port 9400 also */
	return "PROXY ${GATEWAY}:10387; PROXY ${SECONDARY_GATEWAY}:10387";
}
