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
  script_oid("1.3.6.1.4.1.25623.1.0.113765");
  script_version("2020-09-30T10:43:19+0000");
  script_tag(name:"last_modification", value:"2020-10-09 10:01:41 +0000 (Fri, 09 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-09-29 12:55:00 +0200 (Tue, 29 Sep 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_name("rlogin detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service6.nasl");
  script_require_ports("Services/rlogin", 513);

  script_tag(name:"summary", value:"Checks whether the rlogin service is running on the target host.");

  script_xref(name:"URL", value:"https://www.ssh.com/ssh/rlogin");
  script_xref(name:"URL", value:"http://www.ietf.org/rfc/rfc1282.txt");

  exit(0);
}

include( "host_details.inc" );
include( "misc_func.inc" );

nullStr = raw_string( 0x00 );

## Client user name : Server user name : Terminal Type / Terminal Speed
req1 = "root" + nullStr + "root" + nullStr + "vt100/9600" + nullStr;

port = get_port_for_service( proto:"rlogin", default:513 );
if( ! get_port_state( port ) ) exit( 0 );

soc = open_priv_sock_tcp( dport:port );
if( ! soc ) exit( 0 );

## Send Client Start-up flag
send( socket:soc, data:nullStr );

## Rlogin user info
send( socket:soc, data:req1 );

## Receive startup info flag
res1 = recv( socket:soc, length:1 );

## Receive data
res2 = recv( socket:soc, length:1024 );

close( soc );
if( isnull( res2 ) ) exit( 0 );

if( res1 == nullStr && "Password:" >< res2 ) {
  detected = TRUE;
} else if( res1 == nullStr && ( ( "root@" >< res2 && ":~#" >< res2 ) || "Last login: " >< res2 || ( "Linux" >< res2 && " SMP" >< res2 ) ) ) {
  set_kb_item( name:"rlogin/nopass", value:TRUE );
  detected = TRUE;
}

if( detected ) {
  set_kb_item( name:"rlogin/detected", value:TRUE );
  set_kb_item( name:"rlogin/port", value:port );
  register_service( port:port, proto:"rlogin", message:"A rlogin service seems to be running on this port." );
}

exit( 0 );
