###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_netstat_service_detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# netstat Service Information Disclosure
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111047");
  script_version("$Revision: 13541 $");
  script_cve_id("CVE-1999-0650");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-11-06 18:00:00 +0100 (Fri, 06 Nov 2015)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"cvss_base", value:"5.0");
  script_name("netstat Service Information Disclosure");
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Useless services");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/netstat", 15);

  script_tag(name:"summary", value:"The script checks the presence of a netstat service.");

  script_tag(name:"impact", value:"The netstat service provides sensitive information to remote attackers.");

  script_tag(name:"solution", value:"It is recommended to disable this service if not used.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

port = get_kb_item( "Services/netstat" );
if( ! port ) port = 15;
if( ! get_port_state( port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

send( socket: soc, data: "TEST\r\n\r\n" );

buf = recv( socket:soc, length:64 );
close( soc );

if( "Active Internet connections" >< buf || "Active connections" >< buf ||
     ( "ESTABLISHED" >< buf && "TCP" >< buf ) ) {
  register_service( port:port, proto:"netstat" );
  set_kb_item( name:"netstat/" + port + "/installed", value:TRUE );
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
