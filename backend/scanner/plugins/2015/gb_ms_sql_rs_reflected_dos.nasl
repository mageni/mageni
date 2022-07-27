###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_sql_rs_reflected_dos.nasl 10411 2018-07-05 10:15:10Z cfischer $
#
# MS SQL Server Resolution Service Amplification Reflected DRDoS
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105187");
  script_version("$Revision: 10411 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("MS SQL Server Resolution Service Amplification Reflected DRDoS");
  script_tag(name:"last_modification", value:"$Date: 2018-07-05 12:15:10 +0200 (Thu, 05 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-01-26 13:45:36 +0100 (Mon, 26 Jan 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("mssql_ping.nasl", "global_settings.nasl");
  script_mandatory_keys("MSSQL/UDP/Ping");
  script_exclude_keys("keys/islocalhost", "keys/islocalnet", "keys/is_private_addr");

  script_xref(name:"URL", value:"http://kurtaubuchon.blogspot.de/2015/01/mc-sqlr-amplification-ms-sql-server.html");

  script_tag(name:"impact", value:"Successfully exploiting this vulnerability allows attackers to
  cause denial-of-service conditions against remote hosts");

  script_tag(name:"vuldetect", value:"Send a request with a single byte and check the length of the response");

  script_tag(name:"solution", value:"Restrict access to this port.");

  script_tag(name:"summary", value:"The remote MS SQL Server allows distributed reflection and amplification (DRDoS) attacks");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("network_func.inc");

port = 1434;

if( islocalnet() || islocalhost() || is_private_addr() ) exit( 0 );

soc = open_sock_udp( port );
if( ! soc ) exit(0);

byte = raw_string( 0x02 );

send( socket:soc, data:byte );
recv = recv( socket:soc, length:4096 );

close( soc );

if( strlen( recv ) > 50 ){
  report = 'By sending a request with a single byte, we received a response of ' +  strlen( recv ) + ' bytes\n';
  security_message( port:port, proto:"udp", data:report );
  exit( 0 );
}

exit( 99 );
