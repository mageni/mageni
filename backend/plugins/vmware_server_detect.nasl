###############################################################################
# OpenVAS Vulnerability Test
# $Id: vmware_server_detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# VMware ESX/GSX Server detection
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
  script_oid("1.3.6.1.4.1.25623.1.0.20301");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("VMware ESX/GSX Server detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/vmware_auth", 902);

  script_xref(name:"URL", value:"http://www.vmware.com/");

  script_tag(name:"summary", value:"The remote host appears to be running VMware ESX or GSX Server.

  Description :

  According to its banner, the remote host appears to be running a VMWare server authentication daemon, which likely indicates the remote host is running VMware ESX or GSX Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

port = get_kb_item( "Services/vmware_auth" );
if ( ! port ) port = 902;

if( get_port_state( port ) ) {

  soc = open_sock_tcp( port );
  if( soc ) {

    send( socket: soc, data: "TEST\r\n\r\n" );

    buf = recv( socket:soc, length:64 );
    close( soc );

    #220 VMware Authentication Daemon Version 1.00
    #220 VMware Authentication Daemon Version 1.10: SSL Required
    if( "VMware Authentication Daemon Version" >< buf ) {

      version = "unknown";
      vers = eregmatch( string:buf, pattern:"VMware Authentication Daemon Version ([0-9.]+)" );

      if( vers[1] ) {
        version = vers[1];
        report = "A VMware Authentication Daemon in Version: " + version + " is running on this port";
      }

      set_kb_item( name:"vmware_auth/" + port + "/version", value:version );
      set_kb_item( name:"vmware_auth/installed", value:TRUE );
      register_service( port:port, proto:"vmware_auth", message:report );
      log_message( port:port, data:report );
    }
  }
}

exit( 0 );