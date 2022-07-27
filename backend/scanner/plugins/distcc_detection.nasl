###############################################################################
# OpenVAS Vulnerability Test
# $Id: distcc_detection.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# DistCC Detection
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.12638");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("DistCC Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 3632);

  script_tag(name:"summary", value:"Tries to detect if the remote host is running a DistCC service.");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

port = get_unknown_port( default:3632 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

req = string( "DIST00000001",
              "ARGC00000008",
              "ARGV00000002","cc",
              "ARGV00000002","-g",
              "ARGV00000003","-O2",
              "ARGV00000005","-Wall",
              "ARGV00000002","-c",
              "ARGV00000006","main.c",
              "ARGV00000002","-o",
              "ARGV00000006","main.o" );

send( socket:soc, data:req );

req = string( "DOTI0000001B",
              "int main()\n{\n return(0);\n}\n" );

send( socket:soc, data:req );

res = recv( socket:soc, length:255 );
close( soc );

if( "DONE00000" >< res ) {
  set_kb_item( name:"distcc/detected", value:TRUE );
  register_service( port:port, proto:"distcc" );
  log_message( port:port, data:"A DistCC service is running at this port." );
}

exit( 0 );