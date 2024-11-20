function FindProxyForURL(url, host) {
	var privateIP = /^(0|10|127|192.168|172.1[6789]|172.2[0-9]|172.3[01]|169.254|192.88.99).[0-9.]+$/;
	var resolved_ip = dnsResolve(host);

	/* Don't send non-FQDN or private IP auths to ZScaler */
	if (isPlainHostName(host) || 
//	    isInNet(resolved_ip, "192.0.2.0","255.255.255.0") || 
	    isInNet(resolved_ip, "10.0.0.0","255.0.0.0") || 
//	    isInNet(resolved_ip, "10.26.0.0","255.255.0.0") || 
	    isInNet(resolved_ip, "52.244.160.207","255.255.255.255") || 
	    isInNet(resolved_ip, "52.238.119.141","255.255.255.255") || 
	    isInNet(resolved_ip, "52.122.0.0","0.1.255.255") || 
	    isInNet(resolved_ip, "52.112.0.0","0.3.255.255") || 
	    isInNet(resolved_ip, "52.129.96.0","0.0.15.255") || 
	    isInNet(resolved_ip, "169.150.104.0","0.0.7.255") || 
	    isInNet(resolved_ip, "167.234.48.0","0.0.15.255") || 
	    isInNet(resolved_ip, "136.245.64.0","0.0.63.255") || 
	    isInNet(resolved_ip, "193.108.18.192","0.0.0.3") ||
        isInNet(host, "13.107.6.152", "0.0.0.1") ||
        isInNet(host, "13.107.18.10", "0.0.0.1") ||
		isInNet(host, "13.107.128.0", "0.0.3.255") ||
        isInNet(host, "23.103.160.0", "0.0.15.255") ||
        isInNet(host, "40.96.0.0", "0.7.255.255") ||
        isInNet(host, "40.104.0.0", "0.1.255.255") ||
        isInNet(host, "52.96.0.0", "0.3.255.255") ||
        isInNet(host, "131.253.33.215", "0.0.0.0") ||
        isInNet(host, "132.245.0.0", "0.0.255.255") ||
        isInNet(host, "150.171.32.0", "0.0.3.255") ||
        isInNet(host, "204.79.197.215", "0.0.0.0") ||
        isInNet(host, "40.92.0.0", "0.1.255.255") ||
        isInNet(host, "40.107.0.0", "0.0.255.255") ||
        isInNet(host, "52.100.0.0", "0.3.255.255") ||
        isInNet(host, "52.238.78.88", "0.0.0.0") ||
        isInNet(host, "104.47.0.0", "0.0.127.255") ||
        isInNet(host, "13.107.136.0", "0.0.3.255") ||
        isInNet(host, "40.108.128.0", "0.0.127.255") ||
        isInNet(host, "52.104.0.0", "0.3.255.255") ||
        isInNet(host, "104.146.128.0", "0.0.127.255") ||
        isInNet(host, "150.171.40.0", "0.0.3.255") ||
        isInNet(host, "52.112.0.0", "0.3.255.255") ||
        isInNet(host, "52.122.0.0", "0.1.255.255") ||
        isInNet(host, "52.238.119.141", "0.0.0.0") ||
        isInNet(host, "52.244.160.207", "0.0.0.0") ||
        isInNet(host, "13.107.6.171", "0.0.0.0") ||
        isInNet(host, "13.107.18.15", "0.0.0.0") ||
        isInNet(host, "13.107.140.6", "0.0.0.0") ||
        isInNet(host, "52.108.0.0", "0.3.255.255") ||
        isInNet(host, "52.244.37.168", "0.0.0.0") ||
        isInNet(host, "20.20.32.0", "0.0.31.255") ||
        isInNet(host, "20.190.128.0", "0.0.63.255") ||
        isInNet(host, "20.231.128.0", "0.0.31.255") ||
        isInNet(host, "40.126.0.0", "0.0.63.255") ||
        isInNet(host, "13.107.6.192", "0.0.0.0") ||
        isInNet(host, "13.107.9.192", "0.0.0.0") ||
        isInNet(host, "2603:1006::", "ffff:ffff:ffff:ff00::") ||
        isInNet(host, "2603:1016::", "ffff:ffff:ffff:fff0::") ||
        isInNet(host, "2603:1026::", "ffff:ffff:ffff:fff0::") ||
        isInNet(host, "2603:1036::", "ffff:ffff:ffff:fff0::") ||
        isInNet(host, "2603:1046::", "ffff:ffff:ffff:fff0::") ||
        isInNet(host, "2603:1056::", "ffff:ffff:ffff:fff0::") ||
        isInNet(host, "2620:1ec:4::152", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") ||
        isInNet(host, "2620:1ec:4::153", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") ||
        isInNet(host, "2620:1ec:c::10", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") ||
        isInNet(host, "2620:1ec:c::11", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") ||
        isInNet(host, "2620:1ec:d::10", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") ||
        isInNet(host, "2620:1ec:d::11", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") ||
        isInNet(host, "2620:1ec:8f0::", "ffff:ffff:ffff:ffc0::") ||
        isInNet(host, "2620:1ec:900::", "ffff:ffff:ffff:ffc0::") ||
        isInNet(host, "2620:1ec:a92::152", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") ||
        isInNet(host, "2620:1ec:a92::153", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") ||
        isInNet(host, "2a01:111:f400::", "ffff:ffff:ffff:ffff:ffff:ffff::") ||
        isInNet(host, "2a01:111:f403::", "ffff:ffff:ffff:ffff:ffff:ffff::") ||
        isInNet(host, "2603:1061:1300::", "ffff:ffff:ffff:ff00::") ||
        isInNet(host, "2603:1063:6000::", "ffff:ffff:ffff:e000::") ||
        isInNet(host, "2620:1ec:8f8::", "ffff:ffff:ffff:ffc0::") ||
        isInNet(host, "2620:1ec:908::", "ffff:ffff:ffff:ffc0::") ||
        isInNet(host, "2a01:111:f402::", "ffff:ffff:ffff:ffff:ffff:ffff::") ||
        isInNet(host, "2603:1063::", "ffff:ffff:ffff:c000::") ||
        isInNet(host, "2603:1027::", "ffff:ffff:ffff:ffff:ffff:ffff::") ||
        isInNet(host, "2603:1037::", "ffff:ffff:ffff:ffff:ffff:ffff::") ||
        isInNet(host, "2603:1047::", "ffff:ffff:ffff:ffff:ffff:ffff::") ||
        isInNet(host, "2603:1057::", "ffff:ffff:ffff:ffff:ffff:ffff::") ||
        isInNet(host, "2603:1063:2000::", "ffff:ffff:ffff:c000::") ||
        isInNet(host, "2620:1ec:6::", "ffff:ffff:ffff:ffff:ffff:ffff::") ||
        isInNet(host, "2620:1ec:40::", "ffff:ffff:ffff:fc00::") ||
        isInNet(host, "2603:1006:1400::", "ffff:ffff:ffff:ff00::") ||
        isInNet(host, "2603:1016:2400::", "ffff:ffff:ffff:ff00::") ||
        isInNet(host, "2603:1026:2400::", "ffff:ffff:ffff:ff00::") ||
        isInNet(host, "2603:1036:2400::", "ffff:ffff:ffff:ff00::") ||
        isInNet(host, "2603:1046:1400::", "ffff:ffff:ffff:ff00::") ||
        isInNet(host, "2603:1056:1400::", "ffff:ffff:ffff:ff00::") ||
        isInNet(host, "2603:1063:2000::", "ffff:ffff:ffff:c000::") ||
        isInNet(host, "2620:1ec:c::15", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") ||
        isInNet(host, "2620:1ec:8fc::6", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") ||
        isInNet(host, "2620:1ec:a92::171", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") ||
        isInNet(host, "2a01:111:f100:2000::a83e:3019", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") ||
        isInNet(host, "2a01:111:f100:2002::8975:2d79", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") ||
        isInNet(host, "2a01:111:f100:2002::8975:2da8", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") ||
        isInNet(host, "2a01:111:f100:7000::6fdd:6cd5", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") ||
        isInNet(host, "2a01:111:f100:a004::bfeb:88cf", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") ||
        isInNet(host, "2603:1006:2000::", "ffff:ffff:ffff:ffff:ffff:ffff::") ||
        isInNet(host, "2603:1007:200::", "ffff:ffff:ffff:ffff:ffff:ffff::") ||
        isInNet(host, "2603:1016:1400::", "ffff:ffff:ffff:ffff:ffff:ffff::") ||
        isInNet(host, "2603:1017::", "ffff:ffff:ffff:ffff:ffff:ffff::") ||
        isInNet(host, "2603:1026:3000::", "ffff:ffff:ffff:ffff:ffff:ffff::") ||
        isInNet(host, "2603:1027:1::", "ffff:ffff:ffff:ffff:ffff:ffff::") ||
        isInNet(host, "2603:1036:3000::", "ffff:ffff:ffff:ffff:ffff:ffff::") ||
        isInNet(host, "2603:1037:1::", "ffff:ffff:ffff:ffff:ffff:ffff::") ||
        isInNet(host, "2603:1046:2000::", "ffff:ffff:ffff:ffff:ffff:ffff) ||
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
    dnsDomainIs(host, ".microsoftonline.com") ||
    dnsDomainIs(host, "definedbenefit.partnership.co.uk")||
    dnsDomainIs(host, "ams.partnership.co.uk")  ||
    dnsDomainIs(host, "equity-release.partnership.co.uk")  ||
    dnsDomainIs(host, "admin-equity-release.partnership.co.uk")  ||
    dnsDomainIs(host, "equityrelease.dev.partnership.co.uk")||
    dnsDomainIs(host, "just-snow.wearejust.co.uk") ||
    dnsDomainIs(host, ".wearejust.co.uk/epi") ||
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
    dnsDomainIs(host, ".blob.core.windows.net") ||
    shExpMatch(host, "*.lync.com") ||
    dnsDomainIs(host, "teams.microsoft.com") ||
    dnsDomainIs(host, ".teams.microsoft.com") ||
    dnsDomainIs(host, ".microsoft.com") ||
    dnsDomainIs(host, "office.com" ||
    dnsDomainIs(host, ".office.com" ||
    dnsDomainIs(host, "office365.com" ||
    dnsDomainIs(host, ".office365.com" ||
    dnsDomainIs(host, "office.net" ||
    dnsDomainIs(host, ".office.net" ||
    dnsDomainIs(host, "onedrive.com" ||
    dnsDomainIs(host, ".onedrive.com" ||
    dnsDomainIs(host, "sharepoint.com" ||
    dnsDomainIs(host, ".sharepoint.com" ||
    dnsDomainIs(host, "optimizely.com" ||
    dnsDomainIs(host, ".optimizely.com" ||
    dnsDomainIs(host, "microsoftonline.com" ||
    dnsDomainIs(host, ".microsoftonline.com" ||
    dnsDomainIs(host, "production.us.trafficmanager.net" ||
    dnsDomainIs(host, ".production.us.trafficmanager.net" ||
    dnsDomainIs(host, "microsoft.com" ||
    dnsDomainIs(host, ".microsoft.com" ||
    dnsDomainIs(host, "live.com" ||
    dnsDomainIs(host, ".live.com" ||
    dnsDomainIs(host, "oneclient.sfx.ms" ||
    dnsDomainIs(host, ".oneclient.sfx.ms" ||
    dnsDomainIs(host, "sharepointonline.com" ||
    dnsDomainIs(host, ".sharepointonline.com" ||
    dnsDomainIs(host, "spoprod-a.akamaihd.net" ||
    dnsDomainIs(host, ".spoprod-a.akamaihd.net" ||
    dnsDomainIs(host, "prod.msocdn.com" ||
    dnsDomainIs(host, ".prod.msocdn.com" ||
    dnsDomainIs(host, "svc.ms" ||
    dnsDomainIs(host, ".svc.ms" ||
    dnsDomainIs(host, "lync.com" ||
    dnsDomainIs(host, ".lync.com" ||
    dnsDomainIs(host, "broadcast.skype.com" ||
    dnsDomainIs(host, ".broadcast.skype.com" ||
    dnsDomainIs(host, "skypeforbusiness.com" ||
    dnsDomainIs(host, ".skypeforbusiness.com" ||
    dnsDomainIs(host, "sfbassets.com" ||
    dnsDomainIs(host, ".sfbassets.com" ||
    dnsDomainIs(host, "skypemaprdsitus.trafficmanager.net" ||
    dnsDomainIs(host, ".skypemaprdsitus.trafficmanager.net" ||
    dnsDomainIs(host, "windows.net" ||
    dnsDomainIs(host, ".windows.net" ||
    dnsDomainIs(host, "msecnd.net" ||
    dnsDomainIs(host, ".msecnd.net" ||
    dnsDomainIs(host, "aspnetcdn.com" ||
    dnsDomainIs(host, ".aspnetcdn.com" ||
    dnsDomainIs(host, "live.net" ||
    dnsDomainIs(host, ".live.net" ||
    dnsDomainIs(host, "aka.ms" ||
    dnsDomainIs(host, ".aka.ms" ||
    dnsDomainIs(host, "azure.net" ||
    dnsDomainIs(host, ".azure.net" ||
    dnsDomainIs(host, "windows.com" ||
    dnsDomainIs(host, ".windows.com" ||
    dnsDomainIs(host, "windows.net" ||
    dnsDomainIs(host, ".windows.net" ||
    dnsDomainIs(host, "msedge.net" ||
    dnsDomainIs(host, ".msedge.net" ||
    dnsDomainIs(host, "mstea.ms" ||
    dnsDomainIs(host, ".mstea.ms" ||
    dnsDomainIs(host, "skypeassets.com" ||
    dnsDomainIs(host, ".skypeassets.com" ||
    dnsDomainIs(host, "azureedge.net" ||
    dnsDomainIs(host, ".azureedge.net" ||
    dnsDomainIs(host, "tenor.com" ||
    dnsDomainIs(host, ".tenor.com" ||
    dnsDomainIs(host, "microsoftstream.com" ||
    dnsDomainIs(host, ".microsoftstream.com" ||
    dnsDomainIs(host, "assets-yammer.com" ||
    dnsDomainIs(host, ".assets-yammer.com" ||
    dnsDomainIs(host, "azureedge.net" ||
    dnsDomainIs(host, ".azureedge.net" ||
    dnsDomainIs(host, "onenote.com" ||
    dnsDomainIs(host, ".onenote.com" ||
    dnsDomainIs(host, "onenote.net" ||
    dnsDomainIs(host, ".onenote.net" ||
    dnsDomainIs(host, "aspnetcdn.com" ||
    dnsDomainIs(host, ".aspnetcdn.com" ||
    dnsDomainIs(host, "optimizely.com" ||
    dnsDomainIs(host, ".optimizely.com" ||
    dnsDomainIs(host, "msappproxy.net" ||
    dnsDomainIs(host, ".msappproxy.net" ||
    dnsDomainIs(host, "msftidentity.com" ||
    dnsDomainIs(host, ".msftidentity.com" ||
    dnsDomainIs(host, "msidentity.com" ||
    dnsDomainIs(host, ".msidentity.com" ||
    dnsDomainIs(host, "windowsazure.com" ||
    dnsDomainIs(host, ".windowsazure.com" ||
    dnsDomainIs(host, "microsoftazuread-sso.com" ||
    dnsDomainIs(host, ".microsoftazuread-sso.com" ||
    dnsDomainIs(host, "microsoftonline-p.net" ||
    dnsDomainIs(host, ".microsoftonline-p.net" ||
    dnsDomainIs(host, "msauth.net" ||
    dnsDomainIs(host, ".msauth.net" ||
    dnsDomainIs(host, "msauthimages.net" ||
    dnsDomainIs(host, ".msauthimages.net" ||
    dnsDomainIs(host, "msftauth.net" ||
    dnsDomainIs(host, ".msftauth.net" ||
    dnsDomainIs(host, "msftauthimages.net" ||
    dnsDomainIs(host, ".msftauthimages.net" ||
    dnsDomainIs(host, "phonefactor.net" ||
    dnsDomainIs(host, ".phonefactor.net" ||
    dnsDomainIs(host, "visualstudio.com" ||
    dnsDomainIs(host, ".visualstudio.com" ||
    dnsDomainIs(host, "cloudapp.net" ||
    dnsDomainIs(host, ".cloudapp.net" ||
    dnsDomainIs(host, "staffhub.ms" ||
    dnsDomainIs(host, ".staffhub.ms" ||
    dnsDomainIs(host, "gfx.ms" ||
    dnsDomainIs(host, ".gfx.ms" ||
    dnsDomainIs(host, "appex.bing.com" ||
    dnsDomainIs(host, ".appex.bing.com" ||
    dnsDomainIs(host, "appex-rf.msn.com" ||
    dnsDomainIs(host, ".appex-rf.msn.com" ||
    dnsDomainIs(host, "getmicrosoftkey.com" ||
    dnsDomainIs(host, ".getmicrosoftkey.com" ||
    dnsDomainIs(host, "atdmt.com" ||
    dnsDomainIs(host, ".atdmt.com" ||
    dnsDomainIs(host, "yammer.com" ||
    dnsDomainIs(host, ".yammer.com" ||
    dnsDomainIs(host, "yammerusercontent.com" ||
    dnsDomainIs(host, ".yammerusercontent.com" ||
    dnsDomainIs(host, "sway-cdn.com" ||
    dnsDomainIs(host, ".sway-cdn.com" ||
    dnsDomainIs(host, "sway-extensions.com" ||
    dnsDomainIs(host, ".sway-extensions.com" ||
    dnsDomainIs(host, "sway.com" ||
    dnsDomainIs(host, ".sway.com" ||
    dnsDomainIs(host, ".cloud.microsoft") ||
    dnsDomainIs(host, ".static.microsoft") ||
    dnsDomainIs(host, ".usercontent.microsoft") ||
    dnsDomainIs(host, "outlook.cloud.microsoft") ||
    dnsDomainIs(host, "outlook.office.com") ||
    dnsDomainIs(host, "outlook.office365.com") ||
    dnsDomainIs(host, "smtp.office365.com") ||
    dnsDomainIs(host, ".protection.outlook.com") ||
    dnsDomainIs(host, ".mail.protection.outlook.com") ||
    dnsDomainIs(host, ".mx.microsoft") ||
    dnsDomainIs(host, ".sharepoint.com") ||
    dnsDomainIs(host, "ssw.live.com") ||
    dnsDomainIs(host, "storage.live.com") ||
    dnsDomainIs(host, ".search.production.apac.trafficmanager.net") ||
    dnsDomainIs(host, ".search.production.emea.trafficmanager.net") ||
    dnsDomainIs(host, ".search.production.us.trafficmanager.net") ||
    dnsDomainIs(host, ".wns.windows.com") ||
    dnsDomainIs(host, "admin.onedrive.com") ||
    dnsDomainIs(host, "officeclient.microsoft.com") ||
    dnsDomainIs(host, "g.live.com") ||
    dnsDomainIs(host, "oneclient.sfx.ms") ||
    dnsDomainIs(host, ".sharepointonline.com") ||
    dnsDomainIs(host, "spoprod-a.akamaihd.net") ||
    dnsDomainIs(host, ".svc.ms") ||
    dnsDomainIs(host, ".lync.com") ||
    dnsDomainIs(host, ".teams.cloud.microsoft") ||
    dnsDomainIs(host, ".teams.microsoft.com") ||
    dnsDomainIs(host, "teams.cloud.microsoft") ||
    dnsDomainIs(host, "teams.microsoft.com") ||
    dnsDomainIs(host, ".keydelivery.mediaservices.windows.net") ||
    dnsDomainIs(host, ".streaming.mediaservices.windows.net") ||
    dnsDomainIs(host, "mlccdn.blob.core.windows.net") ||
    dnsDomainIs(host, "aka.ms") ||
    dnsDomainIs(host, ".users.storage.live.com") ||
    dnsDomainIs(host, "adl.windows.com") ||
    dnsDomainIs(host, ".secure.skypeassets.com") ||
    dnsDomainIs(host, "mlccdnprod.azureedge.net") ||
    dnsDomainIs(host, ".skype.com") ||
    dnsDomainIs(host, "compass-ssl.microsoft.com") ||
    dnsDomainIs(host, ".officeapps.live.com") ||
    dnsDomainIs(host, ".online.office.com") ||
    dnsDomainIs(host, "office.live.com") ||
    dnsDomainIs(host, ".office.net") ||
    dnsDomainIs(host, ".onenote.com") ||
    dnsDomainIs(host, ".microsoft.com") ||
    dnsDomainIs(host, "cdn.onenote.net") ||
    dnsDomainIs(host, "ajax.aspnetcdn.com") ||
    dnsDomainIs(host, "apis.live.net") ||
    dnsDomainIs(host, "officeapps.live.com") ||
    dnsDomainIs(host, "www.onedrive.com") ||
    dnsDomainIs(host, ".auth.microsoft.com") ||
    dnsDomainIs(host, ".msftidentity.com") ||
    dnsDomainIs(host, ".msidentity.com") ||
    dnsDomainIs(host, "account.activedirectory.windowsazure.com") ||
    dnsDomainIs(host, "accounts.accesscontrol.windows.net") ||
    dnsDomainIs(host, "adminwebservice.microsoftonline.com") ||
    dnsDomainIs(host, "api.passwordreset.microsoftonline.com") ||
    dnsDomainIs(host, "autologon.microsoftazuread-sso.com") ||
    dnsDomainIs(host, "becws.microsoftonline.com") ||
    dnsDomainIs(host, "ccs.login.microsoftonline.com") ||
    dnsDomainIs(host, "clientconfig.microsoftonline-p.net") ||
    dnsDomainIs(host, "companymanager.microsoftonline.com") ||
    dnsDomainIs(host, "device.login.microsoftonline.com") ||
    dnsDomainIs(host, "graph.microsoft.com") ||
    dnsDomainIs(host, "graph.windows.net") ||
    dnsDomainIs(host, "login-us.microsoftonline.com") ||
    dnsDomainIs(host, "login.microsoft.com") ||
    dnsDomainIs(host, "login.microsoftonline-p.com") ||
    dnsDomainIs(host, "login.microsoftonline.com") ||
    dnsDomainIs(host, "login.windows.net") ||
    dnsDomainIs(host, "logincert.microsoftonline.com") ||
    dnsDomainIs(host, "loginex.microsoftonline.com") ||
    dnsDomainIs(host, "nexus.microsoftonline-p.com") ||
    dnsDomainIs(host, "passwordreset.microsoftonline.com") ||
    dnsDomainIs(host, "provisioningapi.microsoftonline.com") ||
    dnsDomainIs(host, ".hip.live.com") ||
    dnsDomainIs(host, ".microsoftonline-p.com") ||
    dnsDomainIs(host, ".microsoftonline.com") ||
    dnsDomainIs(host, ".msauth.net") ||
    dnsDomainIs(host, ".msauthimages.net") ||
    dnsDomainIs(host, ".msecnd.net") ||
    dnsDomainIs(host, ".msftauth.net") ||
    dnsDomainIs(host, ".msftauthimages.net") ||
    dnsDomainIs(host, ".phonefactor.net") ||
    dnsDomainIs(host, "enterpriseregistration.windows.net") ||
    dnsDomainIs(host, "policykeyservice.dc.ad.msft.net") ||
    dnsDomainIs(host, ".protection.office.com") ||
    dnsDomainIs(host, ".security.microsoft.com") ||
    dnsDomainIs(host, ".vsassets.io") ||
    dnsDomainIs(host, "compliance.microsoft.com") ||
    dnsDomainIs(host, "defender.microsoft.com") ||
    dnsDomainIs(host, "protection.office.com") ||
    dnsDomainIs(host, "purview.microsoft.com") ||
    dnsDomainIs(host, "security.microsoft.com") ||
    dnsDomainIs(host, ".portal.cloudappsecurity.com") ||
    dnsDomainIs(host, "firstpartyapps.oaspapps.com") ||
    dnsDomainIs(host, "prod.firstpartyapps.oaspapps.com.akadns.net") ||
    dnsDomainIs(host, "telemetryservice.firstpartyapps.oaspapps.com") ||
    dnsDomainIs(host, "wus-firstpartyapps.oaspapps.com") ||
    dnsDomainIs(host, ".aria.microsoft.com") ||
    dnsDomainIs(host, ".events.data.microsoft.com") ||
    dnsDomainIs(host, ".o365weve.com") ||
    dnsDomainIs(host, "amp.azure.net") ||
    dnsDomainIs(host, "appsforoffice.microsoft.com") ||
    dnsDomainIs(host, "assets.onestore.ms") ||
    dnsDomainIs(host, "auth.gfx.ms") ||
    dnsDomainIs(host, "c1.microsoft.com") ||
    dnsDomainIs(host, "dgps.support.microsoft.com") ||
    dnsDomainIs(host, "docs.microsoft.com") ||
    dnsDomainIs(host, "msdn.microsoft.com") ||
    dnsDomainIs(host, "platform.linkedin.com") ||
    dnsDomainIs(host, "prod.msocdn.com") ||
    dnsDomainIs(host, "shellprod.msocdn.com") ||
    dnsDomainIs(host, "support.microsoft.com") ||
    dnsDomainIs(host, "technet.microsoft.com") ||
    dnsDomainIs(host, ".office365.com") ||
    dnsDomainIs(host, ".aadrm.com") ||
    dnsDomainIs(host, ".azurerms.com") ||
    dnsDomainIs(host, ".informationprotection.azure.com") ||
    dnsDomainIs(host, "ecn.dev.virtualearth.net") ||
    dnsDomainIs(host, "informationprotection.hosting.portal.azure.net") ||
    dnsDomainIs(host, "dc.services.visualstudio.com") ||
    dnsDomainIs(host, "mem.gfx.ms") ||
    dnsDomainIs(host, "staffhub.ms") ||
    dnsDomainIs(host, "staffhubweb.azureedge.net") ||
    dnsDomainIs(host, "o15.officeredir.microsoft.com") ||
    dnsDomainIs(host, "officepreviewredir.microsoft.com") ||
    dnsDomainIs(host, "officeredir.microsoft.com") ||
    dnsDomainIs(host, "r.office.microsoft.com") ||
    dnsDomainIs(host, "activation.sls.microsoft.com") ||
    dnsDomainIs(host, "crl.microsoft.com") ||
    dnsDomainIs(host, "office15client.microsoft.com") ||
    dnsDomainIs(host, "officeclient.microsoft.com") ||
    dnsDomainIs(host, "go.microsoft.com") ||
    dnsDomainIs(host, "ajax.aspnetcdn.com") ||
    dnsDomainIs(host, "cdn.odc.officeapps.live.com") ||
    dnsDomainIs(host, "officecdn.microsoft.com") ||
    dnsDomainIs(host, "officecdn.microsoft.com.edgesuite.net") ||
    dnsDomainIs(host, "otelrules.azureedge.net") ||
    dnsDomainIs(host, ".virtualearth.net") ||
    dnsDomainIs(host, "c.bing.net") ||
    dnsDomainIs(host, "ocos-office365-s2s.msedge.net") ||
    dnsDomainIs(host, "tse1.mm.bing.net") ||
    dnsDomainIs(host, "www.bing.com") ||
    dnsDomainIs(host, ".acompli.net") ||
    dnsDomainIs(host, ".outlookmobile.com") ||
    dnsDomainIs(host, "login.windows-ppe.net") ||
    dnsDomainIs(host, "account.live.com") ||
    dnsDomainIs(host, "login.live.com") ||
    dnsDomainIs(host, "www.acompli.com") ||
    dnsDomainIs(host, ".appex-rf.msn.com") ||
    dnsDomainIs(host, ".appex.bing.com") ||
    dnsDomainIs(host, "c.bing.com") ||
    dnsDomainIs(host, "c.live.com") ||
    dnsDomainIs(host, "d.docs.live.net") ||
    dnsDomainIs(host, "docs.live.net") ||
    dnsDomainIs(host, "partnerservices.getmicrosoftkey.com") ||
    dnsDomainIs(host, "signup.live.com") ||
    dnsDomainIs(host, ".yammer.com") ||
    dnsDomainIs(host, ".yammerusercontent.com") ||
    dnsDomainIs(host, ".assets-yammer.com") ||
    dnsDomainIs(host, "www.outlook.com") ||
    dnsDomainIs(host, "eus-www.sway-cdn.com") ||
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
