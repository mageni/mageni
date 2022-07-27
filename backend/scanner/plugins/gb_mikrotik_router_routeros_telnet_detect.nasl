###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mikrotik_router_routeros_telnet_detect.nasl 13624 2019-02-13 10:02:56Z cfischer $
#
# MikroTik RouterOS Detection (Telnet)
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.113070");
  script_version("$Revision: 13624 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-12-14 13:17:18 +0100 (Thu, 14 Dec 2017)");
  script_name("MikroTik RouterOS Detection (Telnet)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23, 2323);
  script_mandatory_keys("telnet/mikrotik/routeros/detected");

  script_tag(name:"summary", value:"Detection of MikroTik RouterOS via Telnet.

  The script sends a connection request to the server and attempts to
  detect the presence of MikroTik Router.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("telnet_func.inc");

port = get_telnet_port( default:23 );
banner = get_telnet_banner( port:port );
if( "MikroTik" >!< banner || "Login:" >!< banner )
  exit( 0 );

version = "unknown";
install = port + "/tcp";
set_kb_item( name: "mikrotik/detected", value: TRUE );
set_kb_item( name: "mikrotik/telnet/detected", value: TRUE );

# MikroTik v6.34.6 (bugfix)
# Login:
vers = eregmatch( pattern: "MikroTik v([A-Za-z0-9.]+)", string: banner );
if( vers[1] ) version = vers[1];

if( version != "unknown" ) {
  set_kb_item( name: "mikrotik/telnet/" + port + "/concluded", value: vers[0] );
}

set_kb_item( name: "mikrotik/telnet/port", value: port );
set_kb_item( name: "mikrotik/telnet/" + port + "/version", value: version );

exit( 0 );