###############################################################################
# OpenVAS Vulnerability Test
# $Id: dameware_mini_remote_control_disclosure.nasl 12518 2018-11-24 13:51:50Z cfischer $
#
# DameWare Mini Remote Control Information Disclosure
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.11968");
  script_version("$Revision: 12518 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-24 14:51:50 +0100 (Sat, 24 Nov 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("DameWare Mini Remote Control Information Disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Noam Rathaus");
  script_family("General");
  script_dependencies("find_service.nasl", "find_service2.nasl");
  script_require_ports("Services/dameware", 6129);

  script_tag(name:"solution", value:"Filter out incoming traffic to this port to minimize the
  threat.");

  script_tag(name:"summary", value:"The remote host is running DameWare Mini Remote Control.
  This program allows remote attackers to determine the OS type and
  which Service Pack is installed on the server.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

port = get_kb_item( "Services/dameware" );
if( ! port ) port = 6129;
if( ! get_port_state( port ) ) exit( 0 );

soc = open_sock_tcp(port);
if( ! soc ) exit( 0 );

rec = recv( socket:soc, length:8192 );

if( ! ( ( rec[0] == raw_string( 0x30 ) ) && ( rec[1] == raw_string( 0x11 ) ) ) ) {
  close( soc );
  exit( 0 );
}

rec = insstr( rec, raw_string( 0x00 ), 28, 28 );
rec = insstr( rec, raw_string( 0x01 ), 36, 36 );

send( socket:soc, data:rec );

rec = recv( socket:soc, length:8192 );
close( soc );

if( ! ( ( rec[0] == raw_string( 0x10 ) ) && ( rec[1] == raw_string( 0x27 ) ) ) ) {
  exit( 0 );
}

if( ( rec[16] == raw_string( 0x28 ) ) && ( rec[17] == raw_string( 0x0a ) ) ) {
  windows_version = "Windows XP";
}

if( ( rec[16] == raw_string( 0x93 ) ) && ( rec[17] == raw_string( 0x08 ) ) ) {
  windows_version = "Windows 2000";
}

if( ! windows_version ) {
  exit( 0 );
}

service_pack = ""; # nb: To make openvas-nasl-lint happy...
for( i = 24; rec[i] != raw_string( 0x00 ); i++ ) {
  service_pack += rec[i];
}

report = "Using DameWare mini remote control, it was possible to determine that the remote host is running ";
report += windows_version;
report += " - ";
report += service_pack;

security_message( port:port, data:report );

exit( 0 );
