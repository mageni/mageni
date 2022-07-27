##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_codemeter_webadmin_detect.nasl 12708 2018-12-07 15:11:27Z cfischer $
#
# CodeMeter WebAdmin Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801988");
  script_version("$Revision: 12708 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-07 16:11:27 +0100 (Fri, 07 Dec 2018) $");
  script_tag(name:"creation_date", value:"2011-10-04 16:55:13 +0200 (Tue, 04 Oct 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("CodeMeter WebAdmin Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 22350);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the running version CodeMeter WebAdmin
  and sets the result in KB");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

port = get_http_port( default:22350 );
banner = get_http_banner( port:port );

url = "/home.html";
res = http_get_cache( item:url, port:port );

url2 = "/index.html";
res2 = http_get_cache( item:url2, port:port );

if( "<title>CodeMeter | WebAdmin</title>" >!< res &&
    "WIBU-SYSTEMS HTML Served Page" >!< res &&
    "<title>CodeMeter | WebAdmin</title>" >!< res2 &&
    "WIBU-SYSTEMS HTML Served Page" >!< res2 &&
    "Server: WIBU-SYSTEMS HTTP Server" >!< banner ) exit( 0 );

version = "unknown";
install = "/";

# Older versions:
ver = eregmatch( pattern:"WebAdmin Version[^\n]+Version ([0-9.]+)", string:res );
if( ver[1] ) {
  version = ver[1];
  conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
}

# Newer versions:
if( version == "unknown" ) {
  # <p><span class="t-webadmin-version">WebAdmin Version</span>: <span class="bld">6.40</span></p>
  # <p><span class="t-webadmin-version">WebAdmin Version</span>: <span class="bld">6.50</span></p>
  ver = eregmatch( pattern:'>WebAdmin Version[^\n]+>([0-9.]+)<', string:res2 );
  if( ver[1] ) {
    version = ver[1];
    conclUrl = report_vuln_url( port:port, url:url2, url_only:TRUE );
  }
}

set_kb_item( name:"www/"+ port + "/CodeMeter_WebAdmin", value:version );
set_kb_item( name:"CodeMeter_WebAdmin/installed", value:TRUE );

cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:wibu:codemeter_webadmin:" );
if( isnull( cpe ) )
  cpe = 'cpe:/a:wibu:codemeter_webadmin';

register_product( cpe:cpe, location:install, port:port );

log_message( data:build_detection_report( app:"CodeMeter WebAdmin",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concludedUrl:conclUrl,
                                          concluded:ver[0] ),
                                          port:port );

exit( 0 );