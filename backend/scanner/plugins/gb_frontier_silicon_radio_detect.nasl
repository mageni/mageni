###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_frontier_silicon_radio_detect.nasl 11629 2018-09-26 17:02:49Z cfischer $
#
# Frontier Silicion Internet Radio Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.108434");
  script_version("$Revision: 11629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-26 19:02:49 +0200 (Wed, 26 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-03-25 17:29:16 +0200 (Sun, 25 Mar 2018)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Frontier Silicion Internet Radio Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script performs HTTP based detection of a Frontier Silicion Internet Radio.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

port = get_http_port( default:80 );

res = http_get_cache( item:"/web/index.html", port:port );

if( res =~ "^HTTP/1\.[01] 200" && '<a class="logo" href="http://www.frontier-silicon.com/"' >< res && "<title>Internet Radio" >< res ) {

  version = "unknown";

  # <title>Internet Radio 2.11</title>
  vers = eregmatch( pattern:"<title>Internet Radio ([0-9.]+)</title>", string:res );
  if( vers[1] ) version = vers[1];

  # nb: There is no PIN on the web interface but its still required in the request below
  fw_url = "/fsapi/GET/netRemote.sys.info.version?pin=1234&_=" + unixtime();
  fw_req = http_get( item:fw_url, port:port );
  fw_res = http_keepalive_send_recv( data:fw_req, port:port, bodyonly:TRUE );

  # <value><c8_array>ir-mmi-FS2026-0500-0084_V2.11.16.EX69632-2A10</c8_array></value>
  full_fw = eregmatch( pattern:"<value><c8_array>([^>]+)</c8_array></value>", string:fw_res );
  if( full_fw[1] ) {
    set_kb_item( name:"frontier-silicon/internet-radio/" + port + "/full_fw", value:full_fw[1] );
    extra += '\nFull firmware version: ' + full_fw[1];
    extra += '\nConcluded: ' + report_vuln_url( port:port, url:fw_url, url_only:TRUE ) + '\n';
  }

  wired_mac_url = "/fsapi/GET/netRemote.sys.net.wired.macAddress?pin=1234&_=" + unixtime();
  wired_mac_req = http_get( item:wired_mac_url, port:port );
  wired_mac_res = http_keepalive_send_recv( data:wired_mac_req, port:port, bodyonly:TRUE );
  wired_mac = eregmatch( pattern:"<value><c8_array>([0-9a-fA-F:]{17})</c8_array></value>", string:wired_mac_res );

  if( wired_mac[1] ) {
    register_host_detail( name:"MAC", value:wired_mac[1], desc:"Get the MAC Address via Frontier Silicion Internet Radio web interface" );
    extra += '\nEthernet MAC Address: ' + wired_mac[1];
    extra += '\nConcluded: ' + report_vuln_url( port:port, url:wired_mac_url, url_only:TRUE ) + '\n';
  }

  wlan_mac_url = "/fsapi/GET/netRemote.sys.net.wlan.macAddress?pin=1234&_=" + unixtime();
  wlan_mac_req = http_get( item:wlan_mac_url, port:port );
  wlan_mac_res = http_keepalive_send_recv( data:wlan_mac_req, port:port, bodyonly:TRUE );
  wlan_mac = eregmatch( pattern:"<value><c8_array>([0-9a-fA-F:]{17})</c8_array></value>", string:wlan_mac_res );

  if( wlan_mac[1] ) {
    register_host_detail( name:"MAC", value:wlan_mac[1], desc:"Get the MAC Address via Frontier Silicion Internet Radio web interface" );
    extra += '\nWLAN MAC Address: ' + wlan_mac[1];
    extra += '\nConcluded: ' + report_vuln_url( port:port, url:wlan_mac_url, url_only:TRUE ) + '\n';
  }

  set_kb_item( name:"frontier-silicon/internet-radio/detected", value:TRUE );

  register_and_report_cpe( app:"Frontier Silicion Internet Radio",
                           ver:version,
                           concluded:vers[0],
                           base:"cpe:/a:frontier_silicon:internet_radio:",
                           expr:"^([0-9.]+)",
                           insloc:"/",
                           regPort:port,
                           regService:"www",
                           extra:extra );
}

exit( 0 );