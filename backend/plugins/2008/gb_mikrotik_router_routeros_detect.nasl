###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mikrotik_router_routeros_detect.nasl 7480 2017-10-18 11:44:20Z cfischer $
#
# MikroTik RouterOS Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.312703");
  script_version("$Revision: 7480 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-18 13:44:20 +0200 (Wed, 18 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-03-09 15:28:48 +0530 (Thu, 09 Mar 2017)");
  script_name("MikroTik RouterOS Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl", "telnet.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/www", 10000, "Services/telnet", 23, 2323, "Services/ftp", 21);

  script_tag(name:"summary", value:"Detection of MikroTik RouterOS.

  The script sends a connection request to the server and attempts to
  detect the presence of MikroTik Router.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("telnet_func.inc");
include("ftp_func.inc");

ports = get_kb_list( "Services/ftp" );
if( ! ports ) ports = make_list( 21 );

foreach port( ports ) {

  if( ! get_port_state( port ) ) continue;
  banner = get_ftp_banner( port:port );
  if( " FTP server (MikroTik " >!< banner || " ready" >!<  banner ) continue;

  version = "unknown";
  install = port + "/tcp";
  replace_kb_item( name:"mikrotik/detected", value:TRUE );
  replace_kb_item( name:"mikrotik/ftp/detected", value:TRUE );

  # MikroTik FTP server (MikroTik 6.30.4) ready
  # Example FTP server (MikroTik 6.30.2) ready
  vers = eregmatch( pattern:"FTP server \(MikroTik ([A-Za-z0-9.]+)", string:banner );
  if( vers[1] ) version = vers[1];

  cpe = build_cpe( value:version, exp:"^([A-Za-z0-9.]+)", base:"cpe:/o:mikrotik:routeros:" );
  if( ! cpe )
    cpe = "cpe:/o:mikrotik:routeros";

  register_product( cpe:cpe, location:install, port:port, service:"ftp" );

  log_message( data:build_detection_report( app:"MikroTik RouterOS",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:vers[0] ),
                                            port:port );
}

ports = get_kb_list( "Services/telnet" );
if( ! ports ) ports = make_list( 23, 2323 );

foreach port( ports ) {

  if( ! get_port_state( port ) ) continue;
  banner = get_telnet_banner( port:port );
  if( "MikroTik" >!< banner || "Login:" >!< banner ) continue;

  version = "unknown";
  install = port + "/tcp";
  replace_kb_item( name:"mikrotik/detected", value:TRUE );
  replace_kb_item( name:"mikrotik/telnet/detected", value:TRUE );

  # MikroTik v6.34.6 (bugfix)
  # Login:
  vers = eregmatch( pattern:"MikroTik v([A-Za-z0-9.]+)", string:banner );
  if( vers[1] ) version = vers[1];

  cpe = build_cpe( value:version, exp:"^([A-Za-z0-9.]+)", base:"cpe:/o:mikrotik:routeros:" );
  if( ! cpe )
    cpe = "cpe:/o:mikrotik:routeros";

  register_product( cpe:cpe, location:install, port:port, service:"telnet" );

  log_message( data:build_detection_report( app:"MikroTik RouterOS",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:vers[0] ),
                                            port:port );
}

if( get_kb_item( "Settings/disable_cgi_scanning" ) ) exit( 0 );

port = get_http_port( default:10000 );
res = http_get_cache( port:port, item:"/" );

# <div class="top">mikrotik routeros 6.19 configuration page</div>
# <h1>RouterOS v6.34.6</h1>
if( ( ">RouterOS router configuration page<" >< res && "mikrotik<" >< res && ">Login<" >< res ) ||
    ( ">mikrotik routeros" >< res && "configuration page</div>" >< res ) ) {

  version = "unknown";
  install = port + "/tcp";
  replace_kb_item( name:"mikrotik/detected", value:TRUE );
  replace_kb_item( name:"mikrotik/www/detected", value:TRUE );

  vers = eregmatch( pattern:">RouterOS v([A-Za-z0-9.]+)<", string:res );
  if( ! vers[1] ) vers = eregmatch( pattern:">mikrotik routeros ([A-Za-z0-9.]+) configuration page<", string:res );
  if( vers[1] ) version = vers[1];

  cpe = build_cpe( value:version, exp:"^([A-Za-z0-9.]+)", base:"cpe:/o:mikrotik:routeros:" );
  if( ! cpe )
    cpe = "cpe:/o:mikrotik:routeros";

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"MikroTik RouterOS",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:vers[0] ),
                                            port:port );
}

exit( 0 );
