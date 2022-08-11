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
  script_oid("1.3.6.1.4.1.25623.1.0.113756");
  script_version("2020-10-01T08:59:08+0000");
  script_tag(name:"last_modification", value:"2020-10-09 10:01:41 +0000 (Fri, 09 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-01 10:11:11 +0200 (Thu, 01 Oct 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco Smart Install Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports(4786);

  script_tag(name:"summary", value:"Checks whether Cisco Smart Install is present on the target system.");

  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/td/docs/switches/lan/smart_install/configuration/guide/smart_install/concepts.html");

  exit(0);
}

include( "host_details.inc" );
include( "misc_func.inc" );

port = 4786;

if( ! get_port_state( port ) ) exit( 0 );
if( ! soc = open_sock_tcp( port ) ) exit( 0 );

req =  raw_string( 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
                   0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01,
                   0x00
                 );

send( socket: soc, data: req );
recv = recv( socket: soc, length: 20, timeout: 30 );
close( soc );

if( ! recv || strlen( recv ) != 20 ) exit( 0 );

if( hexstr( recv ) =~ "^0000000400000000000000040000000400000001$" )
{
  set_kb_item( name: "cisco/smi/detected", value: TRUE );
  register_service( proto: "cisco_smi", port: port );
  report = "The Cisco Smart Install Protocol was detected on the target system.";
  log_message( data: report, port: port );
}

exit( 0 );
