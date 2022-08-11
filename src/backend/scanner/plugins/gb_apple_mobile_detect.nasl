###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_mobile_detect.nasl 8078 2017-12-11 14:28:55Z cfischer $
#
# Apple Mobile Device Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.103628");
  script_version("$Revision: 8078 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-11 15:28:55 +0100 (Mon, 11 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-12-27 11:43:24 +0100 (Thu, 27 Dec 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Apple Mobile Device Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "secpod_open_tcp_ports.nasl");
  script_require_ports(62078);
  script_mandatory_keys("TCP/PORTS");

  script_tag(name:"summary", value:"Detection of Apple Mobile Devices.
  The script checks if port 62078/tcp is the only open port. If so, cpe:/o:apple:iphone_os is registered.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

if( ! get_port_state( 62078 ) ) exit( 0 );

ports = get_all_tcp_ports_list();
if( ! ports ) exit( 0 );

open_ports_count = max_index( make_list( ports ) );
if( open_ports_count > 1 ) exit( 0 );

foreach port( ports ) {
  if( port != "62078" ) exit( 0 );
}

register_and_report_os( os:"Apple iOS", cpe:"cpe:/o:apple:iphone_os", desc:"Apple Mobile Device Detection", runs_key:"unixoide" );
log_message( data:"The remote Host seems to be an Apple Device because port 62078 is the only open tcp port." );

exit( 0 );
