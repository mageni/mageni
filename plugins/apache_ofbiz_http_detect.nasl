# Copyright (C) 2009 Christian Eric Edjenguele <christian.edjenguele@owasp.org>
# New NASL / detection code since 2018 Copyright (C) 2018 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101019");
  script_version("2021-05-12T07:32:54+0000");
  script_tag(name:"last_modification", value:"2021-05-14 09:39:56 +0000 (Fri, 14 May 2021)");
  script_tag(name:"creation_date", value:"2009-04-18 23:46:40 +0200 (Sat, 18 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache OFBiz Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Apache Open For Business (OFBiz).");

  script_xref(name:"URL", value:"https://ofbiz.apache.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:8443 );

# nb: Keep in sync with the list in DDI_Directory_Scanner.nasl
default_modules = make_list(
  "/accounting/control/main",
  "/ap/control/main",
  "/ar/control/main",
  "/assetmaint/control/main",
  "/bi/control/main",
  "/birt/control/main",
  "/catalog/control/main",
  "/cmssite/control/main",
  "/content/control/main",
  "/control/main",
  "/crmsfa/control/main",
  "/ebay/control/main",
  "/ebaystore/control/main",
  "/ecommerce/control/main",
  "/ecomseo", # nb: special case
  "/example/control/main",
  "/exampleext/control/main",
  "/facility/control/main",
  "/financials/control/main",
  "/googlebase/control/main",
  "/hhfacility/control/main",
  "/humanres/control/main",
  "/ldap/control/main",
  "/lucence/control/main",
  "/manufacturing/control/main",
  "/marketing/control/main",
  "/msggateway/control/main",
  "/multiflex/control/main",
  "/myportal/control/main",
  "/ofbizsetup/control/main",
  "/ordermgr/control/main",
  "/passport/control/main",
  "/partymgr/control/main",
  "/pricat/control/main",
  "/projectmgr/control/main",
  "/purchasing/control/main",
  "/scrum/control/main",
  "/sfa/control/main",
  "/sofami/control/main",
  "/solr/control/main",
  "/warehouse/control/main",
  "/webpos/control/main",
  "/webtools/control/main",
  "/workeffort/control/main" );

foreach url( make_list_unique( "/", default_modules, http_cgi_dirs( port:port ) ) ) {

  module_base_path = url;

  # We have four cases which we need to handle here:
  # 1. "/control/main" as the URL -> Use the URL but set "/" as the module_base_path
  # 2. "/something/control/main" in the URL -> Use the URL but strip the /control/main from the module_base_path
  # 3. "/ecomseo or "/" -> No "/control/main" should be appended and the plain URL should be used
  # 4. For everything else the "module_base_path" should be kept but a "/control/main" appended to the URL

  if( url == "/control/main" ) {
    module_base_path = "/";
  } else if( "/control/main" >< url ) {
    module_base_path = str_replace( string:module_base_path, find:"/control/main", replace:"" );
  } else if( "/ecomseo" >< url || url == "/" ) {
    # do nothing
  } else {
    url += "/control/main";
  }

  res = http_get_cache( item:url, port:port );
  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  # Version 16: <title>OFBiz&#x3a; Accounting Manager: Login</title>
  # Version 13: <title>OFBiz&#58; Order Manager: Login</title>
  # Older version seems to use : instead of &#x3a;
  # <title>OFBiz: Accounting Manager: Login</title>
  ofbizTitle = eregmatch( pattern:"<title>([a-zA-Z: &#0-9;\-]+)</title>", string:res, icase:TRUE );
  if( ( ofbizTitle && 'ofbiz' >< tolower( ofbizTitle[1] ) ) ||
      "neogia_logo.png" >< res || "ofbiz_logo.png" >< res || "ofbiz_logo.gif" >< res ||
      "/OfbizUtil.js" >< res || "ofbiz.ico" >< res || ">Apache OFBiz.<" >< res || "OFBiz.Visitor" >< res ) {

    if( ofbizTitle && 'ofbiz' >< tolower( ofbizTitle[1] ) )
      extra += '\n[' + ofbizTitle[1] + ']:' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    else
      extra += '\n[Unknown module]:' + http_report_vuln_url( port:port, url:url, url_only:TRUE );

    installed = TRUE;
    set_kb_item( name:"apache/ofbiz/" + port + "/modules", value:module_base_path );
    if( ! version )
      version = "unknown";

    # nb: The version isn't exposed as long as the version is not build from source with a previous "gradlew svnInfo"
    # TODO: According to https://issues.apache.org/jira/browse/OFBIZ-10141 the version will be exposed in version 17.x again
    vers = eregmatch( pattern:'powered by <a href="http://ofbiz\\.apache\\.org" target="_blank">[a-zA-Z ]+ ([0-9.]+)', string:res, icase:TRUE );
    if( vers[1] && version == "unknown" ) {
      version = vers[1];
    } else {
      # Special cases only seen on https://demo-old.ofbiz.apache.org/ordermgr/control/main so far:
      #
      # Powered by <a href="http://ofbiz.apache.org" target="_blank">Apache OFBiz</a>  - Release-revision : release13.07-r1806272,  built on 2018-05-16 03:11:09
      #
      # or https://demo-stable.ofbiz.apache.org/content/control/main (the text has newlines in newer versions):
      #
      # Powered by <a href="http://ofbiz.apache.org" target="_blank">Apache OFBiz</a>
      #
      # branch : https://svn.apache.org/repos/asf/ofbiz/branches/release16.11
      # revision : [1874358]
      # built on : 2021-03-22 03:13:07
      # with java version&#x3a; : 1.8.0_282 (Private Build 25.282-b08)    </li>
      # and:
      # <a href="http://www.apache.org" target="_blank">The Apache Software Foundation</a>. Powered by
      # <a href="http://ofbiz.apache.org" target="_blank">Apache OFBiz.</a> Release
      # 17.12
      #
      # branch : release17.12
      #
      # revision : 15bb640a83926d96163ef1496b3e162f79ae344c
      #
      # built on : 2021-03-22 03:09:14
      # with java version: : 1.8.0_282 (Private Build 25.282-b08)    </span>

      vers = eregmatch( pattern:'powered by[ \r\n]*<a href="http://ofbiz\\.apache\\.org" target="_blank">.*release[\r\n]*([0-9.]+)', string:res, icase:TRUE );
      if( vers[1] && version == "unknown" )
        version = vers[1];
    }
  }
}

if( installed ) {

  set_kb_item( name:"apache/ofbiz/detected", value:TRUE );

  install = "/";
  extra = '\n\nDetected Modules:\n' + extra;

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apache:ofbiz:" );
  if( ! cpe )
    cpe = "cpe:/a:apache:ofbiz";

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Apache OFBiz", version:version,  install:install,
                                            cpe:cpe, concluded:vers[0] ) + extra, # We don't want to add the "Extra information:" text...
                                            port:port );
}

exit( 0 );
