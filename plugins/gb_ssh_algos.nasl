###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ssh_algos.nasl 13581 2019-02-11 14:32:32Z cfischer $
#
# SSH Protocol Algorithms Supported
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.105565");
  script_version("$Revision: 13581 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 15:32:32 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-03-09 08:39:30 +0100 (Wed, 09 Mar 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSH Protocol Algorithms Supported");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");

  script_tag(name:"summary", value:"This script detects which algorithms and languages are supported by the remote SSH Service");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssh_func.inc");
include("byte_func.inc");

port = get_ssh_port( default:22 );

types = make_list(
  "kex_algorithms",
  "server_host_key_algorithms",
  "encryption_algorithms_client_to_server",
  "encryption_algorithms_server_to_client",
  "mac_algorithms_client_to_server",
  "mac_algorithms_server_to_client",
  "compression_algorithms_client_to_server",
  "compression_algorithms_server_to_client");

sock = open_sock_tcp( port );
if( ! sock )
  exit( 0 );

server_version = ssh_exchange_identification( socket:sock );
if( ! server_version ) {
  close( sock );
  exit( 0 );
}

buf = ssh_recv( socket:sock, length:2000 );
close( sock );

if( isnull( buf ) )
  exit( 0 );

blen = strlen( buf );
if( blen < 40 )
  exit( 0 );

if( ord( buf[5] ) != 20 )
  exit( 0 );

pos = 22;

foreach typ( types ) {

  if( pos + 4 > blen )
    break;

  len = getdword( blob:buf, pos:pos );
  pos += 4;

  if( pos + len > blen )
    exit( 0 );

  options = substr( buf, pos, pos + len - 1 );
  pos += len;

  if( ! options )
    continue;

  str = split( options, sep:",", keep:FALSE );

  foreach algo( str )
    set_kb_item( name:"ssh/" + port + "/" + typ, value:algo );

  report += typ + ':\n' + options + '\n\n';
}

# Used in ssh_login_failed to evaluate if the SSH server is using unsupported algorithms
set_kb_item( name:"ssh/" + port + "/algos_available", value:TRUE );

set_kb_item( name:"ssh/algos_available", value:TRUE );

report = 'The following options are supported by the remote ssh service:\n\n' + report;

log_message( port:port, data:report );
exit( 0 );