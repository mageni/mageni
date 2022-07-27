###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ingreslock_backdoor.nasl 11327 2018-09-11 11:35:07Z asteins $
#
# Possible Backdoor: Ingreslock
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103549");
  script_version("$Revision: 11327 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-11 13:35:07 +0200 (Tue, 11 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-08-22 16:21:38 +0200 (Wed, 22 Aug 2012)");
  script_name("Possible Backdoor: Ingreslock");
  script_category(ACT_ATTACK);
  script_family("Gain a shell remotely");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service1.nasl", "find_service2.nasl", "secpod_open_tcp_ports.nasl");
  script_mandatory_keys("TCP/PORTS");

  script_tag(name:"summary", value:"A backdoor is installed on the remote host");
  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary commands in the
  context of the application. Successful attacks will compromise the affected isystem.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("misc_func.inc");

port = get_all_tcp_ports();

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

recv = recv( socket:soc, length:1024 );
send( socket:soc, data:'id;\r\n\r\n' );
recv = recv( socket:soc, length:1024 );
close( soc );

if( recv =~ "uid=[0-9]+.*gid=[0-9]+" ) {
  uid = eregmatch( pattern:"(uid=[0-9]+.*gid=[0-9]+[^ ]+)", string:recv );
  if( uid )
    report = "The service is answering to an 'id;' command with the following response: " + uid[1];
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
