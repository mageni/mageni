###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_amqp_detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# AMQP Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105030");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-05-21 12:39:47 +0100 (Wed, 21 May 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("AMQP Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 5672);

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts
  to determine if AMQP is supported.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

port = get_unknown_port( default:5672 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

req = raw_string( 'AMQP', 0, 0, 0, 0 );

send( socket:soc, data:req );
buf = recv( socket:soc, min:8, length:128 );
close( soc );

if( ! buf || isnull( buf ) || strlen( buf ) != 8 || substr( buf, 0, 3 ) != 'AMQP'  ) exit( 0 );

register_service( port:port, proto:"amqp" );

pv = ord( buf[4] );
version = ord( buf[5] ) + '.' + ord( buf[6] ) + '.' + ord( buf[7] );

protocol = 'unknown';

if      ( pv == 0 ) protocol = 'Basic';
else if ( pv == 2 ) protocol = 'STARTTLS';
else if ( pv == 3 ) protocol = 'SASL';

set_kb_item( name:"amqp/" + port + "/protocol", value:pv );
set_kb_item( name:"amqp/" + port + "/version", value:version );
set_kb_item( name:"amqp/" + port + "/version/raw", value:buf[5] + buf[6] + buf[7] );
set_kb_item( name:"amqp/installed", value:TRUE );

report = 'An AMQP server is running on this host.\n\nVersion:  ' + version + '\nProtocol: ' + protocol + '\n';
log_message( port:port, data:report );

exit( 0 );
