# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108894");
  script_version("2020-08-27T13:51:52+0000");
  script_tag(name:"last_modification", value:"2020-08-28 09:48:35 +0000 (Fri, 28 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-27 13:32:10 +0000 (Thu, 27 Aug 2020)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Chargen Service Detection (UDP)");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/udp/chargen", 19);

  script_tag(name:"summary", value:"UDP based detection of a 'chargen' service.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

port = get_port_for_service( default:19, proto:"chargen", ipproto:"udp" );

soc = open_sock_udp( port );
if( ! soc )
  exit( 0 );

# nb: Seems the UDP service requires a different
# approach then the TCP service here:
send( socket:soc, data:'\r\n' );
banner = recv( socket:soc, length:1024 );
close( soc );
if( ! banner )
  exit( 0 );

# nb: See also find_service1.nasl and find_service2.nasl
chargen_found = 0;
foreach chargen_pattern( make_list( '!"#$%&\'()*+,-./', "ABCDEFGHIJ", "abcdefg", "0123456789" ) ) {
  if( chargen_pattern >< banner )
    chargen_found++;
}

if( chargen_found > 2 ) {
  set_kb_item( name:"chargen/udp/detected", value:TRUE );
  set_kb_item( name:"chargen/udp/" + port + "/detected", value:TRUE );
  register_service( port:port, proto:"chargen", message:"A chargen service seems to be running on this port.", ipproto:"udp" );
  log_message( port:port, data:"A chargen service seems to be running on this port.", proto:"udp" );
}

exit( 0 );
