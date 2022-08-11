###############################################################################
# OpenVAS Vulnerability Test
# $Id: find_service6.nasl 14246 2019-03-18 07:20:13Z cfischer $
#
# Service Detection with 'BINARY' Request
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108204");
  script_version("$Revision: 14246 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 08:20:13 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-08-04 09:08:04 +0200 (Fri, 04 Aug 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Service Detection with 'BINARY' Request");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service5.nasl");
  script_require_ports("Services/unknown");

  script_tag(name:"summary", value:"This plugin performs service detection.

  This plugin is a complement of find_service.nasl. It sends a 'BINARY'
  request to the remaining unknown services and tries to identify them.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("global_settings.inc");

port = get_kb_item( "Services/unknown" );
if( ! port ) exit( 0 );
if( ! get_port_state( port ) ) exit( 0 );
if( ! service_is_unknown( port:port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

req = raw_string( 0x00, 0x01, 0x02, 0x03, 0x04 );
send( socket:soc, data:req );
r = recv( socket:soc, length:4096 );
close( soc );

if( ! r ) {
  debug_print( 'service on port ', port, ' does not answer to a "0x00, 0x01, 0x02, 0x03, 0x04" raw string request', "\n" );
  exit( 0 );
}

rhexstr = hexstr( r );

k = "FindService/tcp/" + port + "/bin";
set_kb_item( name:k, value:r );
if( '\0' >< r )
  set_kb_item( name:k + "Hex", value:rhexstr );

if( "rlogind: Permission denied." >< r ) {
  register_service( port:port, proto:"rlogin", message:"A rlogin service seems to be running on this port." );
  log_message( port:port, data:"A rlogin service seems to be running on this port." );
  exit( 0 );
}

if( "Where are you?" >< r ) {
  register_service( port:port, proto:"rexec", message:"A rexec service seems to be running on this port." );
  log_message( port:port, data:"A rexec service seems to be running on this port." );
  exit( 0 );
}

# 0x00:  53 53 48 2D 32 2E 30 2D 6C 69 62 73 73 68 5F 30    SSH-2.0-libssh_0
# 0x10:  2E 37 2E 39 30 0D 0A                               .7.90..
# on e.g. TeamSpeak3 running on port 10022/tcp
#
# 0x00:  53 53 48 2D 32 2E 30 2D 6C 69 62 73 73 68 2D 30    SSH-2.0-libssh-0
# 0x10:  2E 35 2E 32 0A                                     .5.2.
#
# 0x00:  53 53 48 2D 32 2E 30 2D 6C 69 62 73 73 68 0A       SSH-2.0-libssh.
#
# nb:  Sometimes this isn't detected via find_service.nasl as SSH
# nb2: Keep in single quotes so that the "\r" and "\n" are matching...
if( r =~ '^SSH-2.0-libssh[_-][0-9.]+[^\\r\\n]+$' ||
    r == 'SSH-2.0-libssh\n' ) {
  register_service( port:port, proto:"ssh", message:"A SSH service seems to be running on this port." );
  log_message( port:port, data:"A SSH service seems to be running on this port." );
  # nb3: Neither ssh_detect.nasl nor get_ssh_banner() is sometimes able to get the text
  # banner above so set the SSH banner manually here...
  replace_kb_item( name:"SSH/server_banner/" + port, value:chomp( r ) );
  exit( 0 );
}

# 0x00:  00 11 49 6E 76 61 6C 69 64 20 63 6F 6D 6D 61 6E    ..Invalid comman
# 0x10:  64 0A 00 00 00                                     d....
if( rhexstr == "0011496e76616c696420636f6d6d616e640a000000" ) {
  register_service( port:port, proto:"apcupsd", message:"A apcupsd service seems to be running on this port." );
  log_message( port:port, data:"A apcupsd service seems to be running on this port." );
  exit( 0 );
}

########################################################################
#             Unidentified service                                     #
########################################################################

if( ! r0 ) set_unknown_banner( port:port, banner:r );
