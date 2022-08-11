###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adcon_A840_telemetry_gateway_telnet_detect.nasl 13624 2019-02-13 10:02:56Z cfischer $
#
# Adcon A840 Telemetry Gateway Detection (Telnet)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105488");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13624 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-12-17 16:01:19 +0100 (Thu, 17 Dec 2015)");
  script_name("Adcon A840 Telemetry Gateway Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/adcon/telemetry_gateway_a840/detected");

  exit(0);
}

include("telnet_func.inc");

port = get_telnet_port(default:23);
banner = get_telnet_banner(port:port);
if( ! banner || "Telemetry Gateway A840" >!< banner ) exit( 0 );

set_kb_item( name:'tg_A840/installed', value:TRUE );
set_kb_item( name:'tg_A840/telnet/port', value:port );

version = eregmatch( pattern:'Telemetry Gateway A840 Version ([0-9.]+[^\r\n ]+)', string:banner );

if( ! isnull( version[1] ) )
{
  vers = version[1];
  set_kb_item( name:'tg_A840/telnet/version', value:vers );
}

report = 'Detected Adcon Telemetry Gateway A840.\n';
if( vers ) report += 'Version: ' + vers + '\n';

log_message( port:port, data:report );

exit(0);