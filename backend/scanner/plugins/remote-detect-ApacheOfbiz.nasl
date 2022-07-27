###############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-detect-ApacheOfbiz.nasl 9880 2018-05-17 07:12:24Z cfischer $
#
# Apache Open For Business (OFBiz) Detection
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and later,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101019");
  script_version("$Revision: 9880 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-17 09:12:24 +0200 (Thu, 17 May 2018) $");
  script_tag(name:"creation_date", value:"2009-04-18 23:46:40 +0200 (Sat, 18 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Apache Open For Business (OFBiz) Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The remote host is running the Apache OFBiz.

  Apache OFBiz is an Apache Top Level Project. As automation software it comprises a mature suite of enterprise
  applications that integrate and automate many of the business processes of an enterprise.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

port = get_http_port( default:8443 );

foreach module( make_list( '/accounting', '/ap', '/ar', '/assetmaint',
                           '/catalog', '/content', '/facility', '/humanres',
                           '/manufacturing', '/marketing', '/myportal', '/ordermgr',
                           '/partymgr', '/projectmgr', '/sfa', '/scrum', '/workeffort',
                           '/solr', '/birt', '/bi', '/ebay', '/example', '/exampleext',
                           '/hhfacility', '/webpos', '/webtools', '/ofbizsetup',
                           '/ecomseo', '/ecommerce' ) ) {
  # nb: special case
  if( module == "/ecomseo" )
    url = module;
  else
    url = module + "/control/main";

  res = http_get_cache( item:url, port:port );
  if( ! res || res !~ "^HTTP/1\.[01] 200" ) continue;

  # Version 16: <title>OFBiz&#x3a; Accounting Manager: Login</title>
  # Version 13: <title>OFBiz&#58; Order Manager: Login</title>
  # Older version seems to use : instead of &#x3a;
  # <title>OFBiz: Accounting Manager: Login</title>
  ofbizTitle = eregmatch( pattern:"<title>([a-zA-Z: &#0-9;\-]+)</title>", string:res, icase:TRUE );
  if( ( ofbizTitle && 'ofbiz' >< tolower( ofbizTitle[1] ) ) ||
      "neogia_logo.png" >< res || "ofbiz_logo.png" >< res || "ofbiz_logo.gif" >< res ) {

    if( ofbizTitle && 'ofbiz' >< tolower( ofbizTitle[1] ) )
      extra += '\n[' + ofbizTitle[1] +']:' + report_vuln_url( port:port, url:url, url_only:TRUE );
    else
      extra += '\n[Unknown module]:' + report_vuln_url( port:port, url:url, url_only:TRUE );

    installed = TRUE;
    set_kb_item( name:"ApacheOFBiz/" + port + "/modules", value:module );
    if( ! version ) version = "unknown";

    # nb: The version isn't exposed as long as the version is not build from source with a previous "gradlew svnInfo"
    # TODO: According to https://issues.apache.org/jira/browse/OFBIZ-10141 the version will be exposed in version 17.x again
    vers = eregmatch( pattern:'powered by <a href="http://ofbiz.apache.org" target="_blank">[a-zA-Z ]+ ([0-9.]+)', string:res, icase:TRUE );
    if( vers[1] && version == "unknown" ) {
      version = vers[1];
    } else {
      # Special case only seen on https://demo-old.ofbiz.apache.org/ordermgr/control/main
      # Powered by <a href="http://ofbiz.apache.org" target="_blank">Apache OFBiz</a>  - Release-revision : release13.07-r1806272,  built on 2018-05-16 03:11:09
      vers = eregmatch( pattern:'powered by <a href="http://ofbiz.apache.org" target="_blank">.*release([0-9.]+)', string:res, icase:TRUE );
      if( vers[1] && version == "unknown" ) version = vers[1];
    }
  }
}

if( installed ) {

  set_kb_item( name:"ApacheOFBiz/installed", value:TRUE );
  set_kb_item( name:"ApacheOFBiz/" + port + "/version", value:version );
  install = "/";
  extra = '\n\nDetected Modules:\n' + extra;

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apache:open_for_business_project:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:apache:open_for_business_project';

  register_product( cpe:cpe, location:install, port:port );

  log_message( data:build_detection_report( app:"Apache Open For Business (OFBiz)",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:vers[0] ) + extra, # We don't want to add the "Extra information:" text...
                                            port:port );
}

exit( 0 );
