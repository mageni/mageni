###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lantronix_device_detect_http.nasl 10896 2018-08-10 13:24:05Z cfischer $
#
# Lantronix Devices Detection Detection (HTTP)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108304");
  script_version("$Revision: 10896 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:24:05 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-11-29 12:03:31 +0100 (Wed, 29 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Lantronix Devices Detection Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Lantronix Devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
buf  = http_get_cache( item:"/", port:port );

if( ( buf =~ "^HTTP/1\.[0-1] 403" && "<TITLE>Lantronix - Authentication for " >< buf ) ||
    ( buf =~ "^HTTP/1\.[0-1] 200" &&
      ( '<meta http-equiv="refresh" content="1; URL=secure/ltx_conf.htm">' >< buf ||
        'var sTargetURL = "secure/ltx_conf.htm";' >< buf ||
        "<title>Lantronix WEB-Manager</title>" >< buf ||
        "<title>Lantronix Web Manager</title>" >< buf ||
        '<frame name="navframe" target="mainframe" src="LTX_navi.html" scrolling=no>' >< buf ) ) ) {

  version = "unknown";
  type    = "unknown";
  concl   = "";

  # Server: Lantronix MSS4<BR>
  _type = eregmatch( pattern:"Server: Lantronix ([A-Z0-9-]+)<", string:buf );
  if( _type[1] ) {
    type  = _type[1];
    concl = _type[0];
  }

  # The system infos are located on a separate page
  if( "<title>Lantronix Web Manager</title>" >< buf ) {
    url = "/summary.html";
    buf = http_get_cache( item:url, port:port );
    if( "<b>SERVER CONFIGURATION:</b>" >< buf ) {
      # 		Version V3.6/9(030114)<br>
      vers = eregmatch( pattern:"Version [VB]([0-9\.]+)", string:buf, icase:FALSE );
      if( vers[1] ) {
        version = vers[1];
        if( concl ) concl += '\n';
        concl += vers[0] + " on URL " + report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }
    if( type == "unknown" ) {
      url = "/navigation.html";
      buf = http_get_cache( item:url, port:port );
      if( "<TITLE>Lantronix ThinWeb Manager" >< buf ) {
        # <font face="Arial,Helvetica" color="#660066"><b>EPS2-100</b></font><br><br>
        _type = eregmatch( pattern:"><b>([^<]+)</b></font><br><br>", string:buf, icase:FALSE );
        if( _type[1] ) {
          type = _type[1];
          if( concl ) concl += '\n';
          concl += _type[0] + " on URL " + report_vuln_url( port:port, url:url, url_only:TRUE );
        }
      }
    }
  }

  if( concl )
    set_kb_item( name:"lantronix_device/http/" + port + "/concluded", value:concl );

  set_kb_item( name:"lantronix_device/http/" + port + "/version", value:version );
  set_kb_item( name:"lantronix_device/http/" + port + "/type", value:type );
  set_kb_item( name:"lantronix_device/detected", value:TRUE );
  set_kb_item( name:"lantronix_device/http/detected", value:TRUE );
  set_kb_item( name:"lantronix_device/http/port", value:port );
}

exit( 0 );
