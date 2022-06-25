###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_jserv_detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# Apache JServ Protocol v1.3 Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108082");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-02-10 13:00:00 +0100 (Fri, 10 Feb 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Apache JServ Protocol v1.3 Detection");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 8008, 8009);

  script_tag(name:"summary", value:"The script detects a service running the
  Apache JServ Protocol version 1.3.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

port = get_unknown_port( default:8008 );
soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

# CPing Request
# https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html
req = raw_string( 0x12, 0x34, 0x00, 0x01, 0x0a );
send( socket:soc, data:req );
buf = recv( socket:soc, length:5 );
close( soc );
if( strlen( buf < 5 ) ) exit( 0 );

# The CPong Reply
if( hexstr( buf ) =~ "^4142000109$" ) {
  register_service( port:port, proto:"ajp13" );
  log_message( port:port, data:"A service supporting the Apache JServ Protocol v1.3 seems to be running on this port." );
}

exit( 0 );