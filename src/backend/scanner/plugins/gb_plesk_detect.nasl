###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_plesk_detect.nasl 12827 2018-12-18 14:33:16Z cfischer $
#
# Plesk Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103740");
  script_version("$Revision: 12827 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 15:33:16 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2013-06-17 16:27:41 +0200 (Mon, 17 Jun 2013)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Plesk Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Plesk.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:8443 );

url = "/login_up.php3";
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ "^HTTP/1\.[01] 200" && buf =~ "<title>(Parallels Plesk|Plesk Onyx)" ) {

  vers = "unknown";
  install = "/";

  version = eregmatch( pattern:"<title>(Parallels Plesk( Panel)?|Plesk Onyx) ([0-9.]+)</title>", string:buf );
  if( version[3] )
    vers = version[3];

  set_kb_item( name:"plesk/installed", value:TRUE );

  cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:parallels:parallels_plesk_panel:" );
  if( isnull( cpe ) )
    cpe = "cpe:/a:parallels:parallels_plesk_panel";

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Plesk",
                                            version:vers,
                                            install:install,
                                            cpe:cpe,
                                            concluded:version[0] ),
                                            port:port );
}

exit( 0 );