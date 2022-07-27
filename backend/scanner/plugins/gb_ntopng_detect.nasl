###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ntopng_detect.nasl 10833 2018-08-08 10:35:26Z cfischer $
#
# ntopng Version Detection
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107109");
  script_version("$Revision: 10833 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-08 12:35:26 +0200 (Wed, 08 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-12-20 06:40:16 +0200 (Tue, 20 Dec 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("ntopng Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 3000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of ntopng.

  The script detects the version of ntopng on the remote host and sets the KB entry.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:3000 );

url = "/lua/about.lua";

req = http_get( item:url, port:port );
res = http_send_recv( port:port, data:req ); # nb: Use http_send_recv as some older versions have issues when sending a keepalive request

if( "<title>Welcome to ntopng</title>" >< res && "<h2>About ntopng</h2>" >< res ) {
  found = TRUE;
  # e.g. <tr><th>Version</th><td>1.0.1 (r6777)</td></tr>
  tmpVer = eregmatch( string:res, pattern:"<th>Version</th><td>([0-9\.]+)( \(r([0-9]+)\))?", icase:TRUE );
  if( ! isnull( tmpVer[3] ) ) extra = "Revision: " + tmpVer[3];
}

if( ! found ) {
  url = "/lua/login.lua?referer=/";

  req = http_get( item:url, port:port );
  res = http_send_recv( port:port, data:req ); # nb: Use http_send_recv as some older versions have issues when sending a keepalive request

  if( "erver: ntopng" >< res || "<title>Welcome to ntopng</title>" >< res || "ntop.org<br> ntopng is released under" >< res ) {
    found = TRUE;
    tmpVer = eregmatch( string:res, pattern:"Server: ntopng ([0-9.]+)", icase:TRUE );
  }
}

if( found ) {

  ntopngVer = "unknown";
  install   = "/";
  set_kb_item( name:"ntopng/installed", value:TRUE );
  concUrl = report_vuln_url( port:port, url:url, url_only:TRUE );

  if( tmpVer[1] ) ntopngVer = tmpVer[1];

  cpe = build_cpe( value:ntopngVer, exp:"^([0-9.]+)", base:"cpe:/a:ntop:ntopng:" );
  if( ! cpe )
    cpe = 'cpe:/a:ntop:ntopng';

  register_product( cpe:cpe, location:install, port:port );
  log_message( data:build_detection_report( app:"ntopng",
                                            version:ntopngVer,
                                            install:install,
                                            cpe:cpe,
                                            concluded:tmpVer[0],
                                            concludedUrl:concUrl,
                                            extra:extra ),
                                            port:port );
}

exit( 0 );
