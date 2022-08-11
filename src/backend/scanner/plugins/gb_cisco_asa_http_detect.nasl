# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105033");
  script_version("2021-07-05T11:21:05+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-07-06 10:39:30 +0000 (Tue, 06 Jul 2021)");
  script_tag(name:"creation_date", value:"2014-05-26 15:00:41 +0200 (Mon, 26 May 2014)");
  script_name("Cisco Adaptive Security Appliance (ASA) SSL VPN Portal Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of the SSL VPN Portal running on a Cisco
  Adaptive Security Appliance (ASA).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:443 );
host = http_host_name( port:port );

url = "/%2bCSCOE%2b/win.js";
finalconclurl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
req = http_get( item:url, port:port );
buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

if( ! buf || "CSCO_WebVPN" >!< buf )
  exit( 0 );

url = "/%2bCSCOE%2b/logon.html";
conclurl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
req = http_get( item:url, port:port );
buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

# nb: Some specific (probably older or different configured) devices hasn't returned anything on the
# URL above. In the browser (maybe due to some cookies set) we're getting redirected (via HTTP/1.0
# 302 Moved Temporarily) to this new URL so we're trying that as well.
if( ! buf || buf !~ "^HTTP/1\.[01] 200" ) {

  url = "/CACHE/sdesktop/install/start.htm";
  req = http_get( item:url, port:port );
  buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

  if( ! buf || buf !~ "^HTTP/1\.[01] 200" || buf !~ "Cisco Secure Desktop" )
    exit( 0 );

  conclurl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
}

finalconclurl += '\n' + conclurl;

uid = rand_str( length:128, charset:"ABCDEF0123456789" );

set_kb_item( name:"cisco/asa/webvpn/detected", value:TRUE );
set_kb_item( name:"cisco/asa/webvpn/http/detected", value:TRUE );

xml = '<?xml version="1.0" encoding="UTF-8"?>\r\n' +
      '<config-auth client="vpn" type="init" aggregate-auth-version="2">\r\n' +
      '<version who="vpn">3.1.05160</version>\r\n' +
      '<device-id device-type="MacBookAir4,1" platform-version="10.9.2" unique-id="' + uid + '">mac-intel</device-id>\r\n' +
      '<mac-address-list>\r\n' +
      '<mac-address>00:00:00:00:00:00</mac-address></mac-address-list>\r\n' +
      '<group-select>VPN</group-select>\r\n' +
      '<group-access>https://' + host + '</group-access>\r\n' +
      '</config-auth>';
len = strlen( xml );

req = 'POST / HTTP/1.1\r\n' +
      'Connection: close\r\n' +
      'Content-Length: ' + len + '\r\n' +
      'X-Transcend-Version: 1\r\n' +
      'Accept: */*\r\n' +
      'Host: ' + host + '\r\n' +
      'X-AnyConnect-Platform: mac-intel\r\n' +
      'Accept-Encoding: identity\r\n' +
      'X-Aggregate-Auth: 1\r\n' +
      'User-Agent: AnyConnect Darwin_i386 3.1.05160\r\n\r\n' +
      xml;
buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

# nb: Newer versions of the ASA VPN Portal doesn't offer the version anymore and requires the user
# to login first to continue.
vers = "unknown";
install = "/";

# <version who="sg">8.4(1)</version>
# or:
# 9.0(2)
version = eregmatch( string:buf, pattern:"<version.*>([^<]+)</version>" );
if( ! isnull( version[1] ) )
  vers = version[1];

app_cpe = build_cpe( value:vers, exp:"^([0-9.()]+)", base:"cpe:/a:cisco:asa:" );
if( ! app_cpe )
  app_cpe = "cpe:/a:cisco:asa";

os_cpe = build_cpe( value:vers, exp:"^([0-9.()]+)", base:"cpe:/o:cisco:adaptive_security_appliance_software:" );
if( ! os_cpe )
  os_cpe = "cpe:/o:cisco:adaptive_security_appliance_software";

os_register_and_report( os:"Cisco Adaptive Security Appliance (ASA)", cpe:os_cpe, banner_type:"Cisco Adaptive Security Appliance (ASA) SSL VPN Portal", banner:version[0], desc:"Cisco Adaptive Security Appliance (ASA) SSL VPN Portal (HTTP)", runs_key:"unixoide" );
register_product( cpe:app_cpe, location:install, port:port, service:"www" );
register_product( cpe:os_cpe, location:install, port:port, service:"www" );

report =  build_detection_report( app:"Cisco Adaptive Security Appliance (ASA) SSL VPN Portal",
                                  version:vers,
                                  install:install,
                                  cpe:app_cpe );
report += '\n\n';
report += build_detection_report( app:"Cisco Adaptive Security Appliance (ASA)",
                                  version:vers,
                                  install:install,
                                  cpe:os_cpe );
report += '\n\n';
if( version[0] )
  report += 'Concluded from version/product identification result (Gathered via a VPN connection request):\n\n' + version[0] + '\n\n';
report += 'Concluded from version/product identification location:\n\n' + finalconclurl;

log_message( port:port, data:report );
exit( 0 );