###############################################################################
# OpenVAS Vulnerability Test
#
# ZNC Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100243");
  script_version("2020-06-16T12:39:16+0000");
  script_tag(name:"last_modification", value:"2020-06-17 08:59:13 +0000 (Wed, 17 Jun 2020)");
  script_tag(name:"creation_date", value:"2009-07-26 19:54:54 +0200 (Sun, 26 Jul 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ZNC Detection (IRC)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "find_service2.nasl");
  script_require_ports("Services/irc", 6667, 6697);

  script_tag(name:"summary", value:"Detection of ZNC.

  IRC based detection ZNC.");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

ports = get_ports_for_service( default_port_list:make_list( 6667, 6697 ), proto:"irc" );

foreach port( ports ) {
  soc = open_sock_tcp( port );
  if( ! soc )
    continue;

  req = string( "USER\r\n" );
  send( socket:soc, data:req );

  buf = recv_line( socket:soc, length:64 );
  close( soc );

  if( egrep( pattern:"irc\.znc\.in NOTICE AUTH", string:buf, icase:TRUE ) ||
      ( "irc.znc.in" >< buf && "Password required" >< buf ) ) {
    version = "unknown";

    set_kb_item( name:"znc/detected", value:TRUE );
    set_kb_item( name:"znc/irc/port", value:port );
    set_kb_item( name:"znc/irc/" + port + "/version", value:version );
    set_kb_item( name:"znc/irc/" + port + "/concluded", value:chomp( buf ) );
  }
}

exit( 0 );
