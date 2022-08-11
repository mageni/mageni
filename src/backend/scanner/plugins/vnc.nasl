###############################################################################
# OpenVAS Vulnerability Test
# $Id: vnc.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# VNC Server and Protocol Version Detection
#
# Authors:
# Patrick Naubert
# Modified by Georges Dagousset <georges.dagousset@alert4web.com> :
#	- warning with the version
#	- detection of other version
#	- default port for single test
#
# Copyright:
# Copyright (C) 2000 Patrick Naubert
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
  script_oid("1.3.6.1.4.1.25623.1.0.10342");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("VNC Server and Protocol Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 Patrick Naubert");
  script_family("Service detection");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/vnc", 5900, 5901, 5902);

  script_tag(name:"solution", value:"Make sure the use of this software is done in accordance with your
  corporate security policy, filter incoming traffic to this port.");
  script_tag(name:"summary", value:"The remote host is running a remote display software (VNC)
  which permits a console to be displayed remotely.

  This allows authenticated users of the remote host to take its
  control remotely.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

report = "A VNC server seems to be running on this port.";

ports = get_kb_list( "Services/vnc" );
if( ! ports ) ports = make_list( 5900, 5901, 5902 );

foreach port ( ports ) {

  if( get_port_state( port ) ) {

    soc = open_sock_tcp( port );
    if( soc ) {

      send( socket:soc, data:"TEST\r\n" );

      buf = recv( socket:soc, length:4096 );
      close( soc );

      if( ereg( pattern:"^RFB [0-9]", string:buf ) ) {
        set_kb_item( name:"vnc/detected", value:TRUE );
        replace_kb_item( name:"vnc/banner/" + port , value:buf );
        version = egrep( pattern:"^RFB 00[0-9]\.00[0-9]", string:buf );
        if( version ) {
          ver_report = '\n\nThe version of the VNC protocol is : ' + version;
        }
        log_message( port:port, data:report + ver_report );
        register_service( port:port, proto:"vnc", message:report + ver_report );
      }
    }
  }
}

exit( 0 );